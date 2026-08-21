//! La mecánica de una transferencia con un plugin, en un solo sitio.
//!
//! Las tres operaciones —backup, restore y verify— hacen exactamente lo mismo
//! cuatro veces: crear un socket, pedir por gRPC que el plugin se conecte a él,
//! esperar esa conexión con un plazo, drenar el flujo de `Progress` y traducir
//! las cinco formas distintas en que eso puede romperse. Lo único que cambia
//! entre ellas es **qué RPC** se llama y **en qué orden**.
//!
//! Ese reparto es la razón de que este módulo exista y de que no sea
//! `ops/mod.rs`: `ops/mod.rs` es el mapa de qué operaciones hay: si además
//! guardase los plazos, el seguimiento de progreso y la traducción de errores,
//! el mapa quedaría enterrado bajo la maquinaria. Aquí está la maquinaria, con
//! su propio nombre, y `backup.rs`, `restore.rs` y `verify.rs` quedan siendo lo
//! que de verdad son: tres órdenes de llamada distintos sobre las mismas
//! piezas.
//!
//! [`BackupError`] vive aquí por la misma razón: sus variantes describen los
//! fallos de esta mecánica —el plugin no contestó, no se conectó, se rompió a
//! mitad— y dos de ellas citan los plazos de este módulo en su mensaje. Conserva
//! el nombre porque las tres operaciones lo comparten y renombrarlo a
//! `OperacionError` no diría nada más de lo que ya dice.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sb_crypto::PipelineError;
use sb_proto::engine_client::EngineClient;
use sb_proto::storage_client::StorageClient;
use sb_proto::{DumpRequest, GetRequest, Progress, PutRequest, RestoreRequest};
use sb_transport::DataChannel;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::task::JoinHandle;
use tonic::Streaming;

use crate::model::ManifestError;
use crate::plugin::client::mensaje_de;
use crate::plugin::{PluginClient, PluginError};

/// Plazo para que el RPC que abre una transferencia devuelva sus cabeceras.
///
/// `Dump`, `Put`, `Get` y `Restore` pueden tardar horas en **terminar**, pero
/// en contestar no: lo único que hacen antes de responder es validar la
/// petición y lanzar su tarea. Un plugin que ni siquiera llega a eso no va a
/// mover un byte.
pub(crate) const PLAZO_APERTURA: Duration = Duration::from_secs(60);

/// Plazo para que el plugin se conecte al canal de datos que se le ofreció.
///
/// Sin este plazo, un plugin que acepta el RPC y luego no abre el socket
/// dejaría el `accept` esperando para siempre: la operación no fallaría, se
/// quedaría colgada, que es peor porque nadie se entera hasta que hace falta
/// restaurar.
pub(crate) const PLAZO_CONEXION: Duration = Duration::from_secs(30);

/// Tope de lo que se acepta como blob «pequeño».
///
/// [`descargar_blob`] carga en memoria lo que lee, así que necesita un techo:
/// un destino roto —o hostil— que sirviera cien gigabytes bajo la clave del
/// manifiesto tumbaría el proceso. Un manifiesto real ronda el kilobyte; un
/// mebibyte deja sitio de sobra sin dejar de ser un techo.
const LIMITE_BLOB: u64 = 1024 * 1024;

pub(crate) const OP_DUMP: &str = "dump";
pub(crate) const OP_PUT: &str = "put";
pub(crate) const OP_GET: &str = "get";
pub(crate) const OP_RESTORE: &str = "restore";

/// Todo lo que puede salir mal en una operación con plugins.
///
/// Cada variante nombra al plugin: una operación tiene dos vivos a la vez y
/// «falló la transferencia» obliga a adivinar cuál de los dos fue.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// El plugin elegido no sabe hacer el papel que se le pide, o el canal de
    /// control falló.
    #[error(transparent)]
    Plugin(#[from] PluginError),
    /// No se pudo crear el socket por el que iban a fluir los bytes.
    #[error("no se pudo crear el canal de datos para el plugin «{plugin}»: {fuente}")]
    Canal {
        plugin: String,
        fuente: std::io::Error,
    },
    /// El plugin contestó al RPC con un error, antes de mover nada.
    #[error("el plugin «{plugin}» rechazó {operacion}: {mensaje}")]
    Rpc {
        plugin: String,
        operacion: String,
        mensaje: String,
    },
    /// El RPC ni siquiera devolvió cabeceras.
    #[error("el plugin «{plugin}» no respondió a {operacion} en {} s", PLAZO_APERTURA.as_secs())]
    SinRespuesta { plugin: String, operacion: String },
    /// El plugin aceptó el RPC pero nunca abrió el socket. Se distingue de
    /// `SinRespuesta` porque aquí el plugin sí está vivo y contestando: lo que
    /// falla es su lado del canal de datos.
    #[error(
        "el plugin «{plugin}» aceptó {operacion} pero no se conectó al canal de datos en {} s",
        PLAZO_CONEXION.as_secs()
    )]
    SinConexion { plugin: String, operacion: String },
    /// La transferencia empezó y se rompió a mitad. El error llega por el flujo
    /// de `Progress`, que es el único camino que le queda una vez enviadas las
    /// cabeceras.
    #[error("el plugin «{plugin}» falló durante {operacion}: {mensaje}")]
    Transferencia {
        plugin: String,
        operacion: String,
        mensaje: String,
    },
    /// La tarea que seguía el progreso se cayó. No es culpa del plugin, pero la
    /// operación tampoco se puede dar por buena.
    #[error("se perdió el seguimiento de {operacion} del plugin «{plugin}»: {fuente}")]
    Seguimiento {
        plugin: String,
        operacion: String,
        fuente: tokio::task::JoinError,
    },
    /// Falló comprimir, cifrar, descifrar o hashear.
    #[error("el pipeline de cifrado falló: {0}")]
    Pipeline(#[from] PipelineError),
    /// Falló escribir o leer en el canal de datos desde el núcleo.
    #[error("error de E/S en el canal de datos con «{plugin}»: {fuente}")]
    Io {
        plugin: String,
        fuente: std::io::Error,
    },
    /// El manifiesto no se pudo serializar o no se pudo interpretar.
    #[error("no se pudo leer el manifiesto: {0}")]
    Manifiesto(#[from] ManifestError),
    /// El manifiesto que describe un artefacto no está o no se pudo traer.
    ///
    /// Se separa de `Rpc` porque el remedio es distinto y el mensaje tiene que
    /// decir **qué clave se buscó**: sin manifiesto no hay contra qué comparar,
    /// y quien lea el error necesita saber si el manifiesto se perdió o si el
    /// artefacto nunca se llamó así.
    #[error(
        "no se pudo leer el manifiesto «{clave}» del destino «{plugin}»: {motivo}. \
         Sin él no hay con qué comprobar el artefacto"
    )]
    SinManifiesto {
        plugin: String,
        clave: String,
        motivo: String,
    },
    /// El blob que se pedía pequeño no lo era.
    #[error(
        "«{clave}» ocupa más de {} bytes: no parece un manifiesto",
        LIMITE_BLOB
    )]
    BlobDemasiadoGrande { clave: String },
}

/// Crea el canal de datos dentro del directorio de ejecución de `plugin`.
///
/// El nombre lleva un contador porque una misma pareja de plugins hace varias
/// operaciones seguidas y dos canales vivos a la vez con el mismo nombre se
/// pisarían el socket.
pub(crate) fn crear_canal(plugin: &PluginClient) -> Result<DataChannel, BackupError> {
    static SIGUIENTE: AtomicU64 = AtomicU64::new(0);
    let nombre = format!("datos-{}", SIGUIENTE.fetch_add(1, Ordering::Relaxed));
    DataChannel::create(plugin.proceso().runtime_dir(), &nombre).map_err(|fuente| {
        BackupError::Canal {
            plugin: plugin.nombre().to_string(),
            fuente,
        }
    })
}

/// Le pide al destino que se ponga a **leer** del canal.
pub(crate) async fn iniciar_put(
    storage: &PluginClient,
    clave: &str,
    canal: &DataChannel,
) -> Result<JoinHandle<Result<u64, BackupError>>, BackupError> {
    let mut grpc = StorageClient::new(storage.canal());
    let peticion = PutRequest {
        key: clave.to_string(),
        data_socket: ruta_de(canal),
    };
    let flujo = abrir(storage.nombre(), OP_PUT, grpc.put(peticion)).await?;
    Ok(seguir_progreso(storage.nombre().to_string(), OP_PUT, flujo))
}

/// Le pide al destino que se ponga a **escribir** en el canal.
pub(crate) async fn iniciar_get(
    storage: &PluginClient,
    clave: &str,
    canal: &DataChannel,
) -> Result<JoinHandle<Result<u64, BackupError>>, BackupError> {
    let mut grpc = StorageClient::new(storage.canal());
    let peticion = GetRequest {
        key: clave.to_string(),
        data_socket: ruta_de(canal),
    };
    let flujo = abrir(storage.nombre(), OP_GET, grpc.get(peticion)).await?;
    Ok(seguir_progreso(storage.nombre().to_string(), OP_GET, flujo))
}

/// Le pide al motor que se ponga a **escribir** en el canal.
pub(crate) async fn iniciar_dump(
    engine: &PluginClient,
    canal: &DataChannel,
) -> Result<JoinHandle<Result<u64, BackupError>>, BackupError> {
    let mut grpc = EngineClient::new(engine.canal());
    let peticion = DumpRequest {
        data_socket: ruta_de(canal),
    };
    let flujo = abrir(engine.nombre(), OP_DUMP, grpc.dump(peticion)).await?;
    Ok(seguir_progreso(engine.nombre().to_string(), OP_DUMP, flujo))
}

/// Le pide al motor que se ponga a **leer** del canal y a tragarse lo que salga.
pub(crate) async fn iniciar_restore(
    engine: &PluginClient,
    canal: &DataChannel,
) -> Result<JoinHandle<Result<u64, BackupError>>, BackupError> {
    let mut grpc = EngineClient::new(engine.canal());
    let peticion = RestoreRequest {
        data_socket: ruta_de(canal),
    };
    let flujo = abrir(engine.nombre(), OP_RESTORE, grpc.restore(peticion)).await?;
    Ok(seguir_progreso(
        engine.nombre().to_string(),
        OP_RESTORE,
        flujo,
    ))
}

fn ruta_de(canal: &DataChannel) -> String {
    canal.path().to_string_lossy().into_owned()
}

/// El plazo y la traducción de errores de un RPC de transferencia, en un solo
/// sitio: basta con olvidar el `timeout` una vez para que un plugin mudo deje
/// la operación esperando.
async fn abrir<F>(
    plugin: &str,
    operacion: &str,
    llamada: F,
) -> Result<Streaming<Progress>, BackupError>
where
    F: Future<Output = Result<tonic::Response<Streaming<Progress>>, tonic::Status>>,
{
    match tokio::time::timeout(PLAZO_APERTURA, llamada).await {
        Ok(Ok(respuesta)) => Ok(respuesta.into_inner()),
        Ok(Err(status)) => Err(BackupError::Rpc {
            plugin: plugin.to_string(),
            operacion: operacion.to_string(),
            mensaje: mensaje_de(&status),
        }),
        Err(_) => Err(BackupError::SinRespuesta {
            plugin: plugin.to_string(),
            operacion: operacion.to_string(),
        }),
    }
}

/// Espera a que el plugin abra su lado del canal, con plazo.
///
/// `DataChannel::accept` no impone ninguno a propósito —lo dice su
/// documentación— y este es el sitio donde se impone.
pub(crate) async fn aceptar(
    canal: &DataChannel,
    plugin: &str,
    operacion: &str,
) -> Result<UnixStream, BackupError> {
    match tokio::time::timeout(PLAZO_CONEXION, canal.accept()).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(fuente)) => Err(BackupError::Io {
            plugin: plugin.to_string(),
            fuente,
        }),
        Err(_) => Err(BackupError::SinConexion {
            plugin: plugin.to_string(),
            operacion: operacion.to_string(),
        }),
    }
}

/// Drena el flujo de `Progress` en una tarea de fondo y lo reemite como trazas.
///
/// Hay que drenarlo sí o sí: el SDK de los plugins aplica backpressure sobre
/// ese flujo, así que un núcleo que no lo lee acaba frenando al plugin que
/// mueve los bytes. Y es además el único camino por el que puede llegar un
/// error una vez enviadas las cabeceras del RPC.
///
/// Devuelve los bytes que el plugin dijo haber movido, que sirven para
/// contrastar con lo que contó el pipeline.
fn seguir_progreso(
    plugin: String,
    operacion: &'static str,
    mut flujo: Streaming<Progress>,
) -> JoinHandle<Result<u64, BackupError>> {
    tokio::spawn(async move {
        let mut ultimo = 0;
        loop {
            match flujo.message().await {
                Ok(Some(progreso)) => {
                    ultimo = progreso.bytes;
                    tracing::debug!(
                        plugin = %plugin,
                        operacion,
                        bytes = progreso.bytes,
                        mensaje = %progreso.message,
                        "progreso"
                    );
                }
                Ok(None) => return Ok(ultimo),
                Err(status) => {
                    return Err(BackupError::Transferencia {
                        plugin,
                        operacion: operacion.to_string(),
                        mensaje: mensaje_de(&status),
                    });
                }
            }
        }
    })
}

/// Espera a que la tarea de progreso termine y traduce sus dos formas de
/// fallar: la del plugin y la de la propia tarea.
pub(crate) async fn esperar_progreso(
    tarea: JoinHandle<Result<u64, BackupError>>,
    plugin: &str,
    operacion: &str,
) -> Result<u64, BackupError> {
    match tarea.await {
        Ok(resultado) => resultado,
        Err(fuente) => Err(BackupError::Seguimiento {
            plugin: plugin.to_string(),
            operacion: operacion.to_string(),
            fuente,
        }),
    }
}

/// Sube un contenido pequeño que ya está en memoria.
///
/// Lo usa el manifiesto. Recorre exactamente los mismos pasos que el artefacto
/// —canal, `Put`, `accept` con plazo, progreso— porque un segundo camino de
/// subida es un segundo comportamiento que mantener.
pub(crate) async fn subir_blob(
    storage: &PluginClient,
    clave: &str,
    contenido: &[u8],
) -> Result<(), BackupError> {
    let canal = crear_canal(storage)?;
    let subida = iniciar_put(storage, clave, &canal).await?;
    let mut sumidero = aceptar(&canal, storage.nombre(), OP_PUT).await?;

    let error_io = |fuente| BackupError::Io {
        plugin: storage.nombre().to_string(),
        fuente,
    };
    sumidero.write_all(contenido).await.map_err(error_io)?;
    // El cierre del lado de escritura es lo que el destino ve como fin de
    // flujo. Sin él esperaría bytes que ya no van a llegar.
    sumidero.shutdown().await.map_err(error_io)?;

    esperar_progreso(subida, storage.nombre(), OP_PUT).await?;
    Ok(())
}

/// Baja a memoria un blob que se sabe pequeño.
///
/// El reverso de [`subir_blob`], y **solo** para lo que de verdad es pequeño:
/// el artefacto nunca pasa por aquí, se lee en flujo. De ahí el
/// [`LIMITE_BLOB`], que convierte «me fío de que esta clave sea un manifiesto»
/// en un error con nombre.
pub(crate) async fn descargar_blob(
    storage: &PluginClient,
    clave: &str,
) -> Result<Vec<u8>, BackupError> {
    let canal = crear_canal(storage)?;
    let descarga = iniciar_get(storage, clave, &canal).await?;
    let fuente = aceptar(&canal, storage.nombre(), OP_GET).await?;

    // `take` de un byte más que el tope: si se llenan, es que había más.
    let mut contenido = Vec::new();
    let leidos = fuente
        .take(LIMITE_BLOB + 1)
        .read_to_end(&mut contenido)
        .await
        .map_err(|fuente| BackupError::Io {
            plugin: storage.nombre().to_string(),
            fuente,
        })?;
    if u64::try_from(leidos).unwrap_or(u64::MAX) > LIMITE_BLOB {
        return Err(BackupError::BlobDemasiadoGrande {
            clave: clave.to_string(),
        });
    }

    esperar_progreso(descarga, storage.nombre(), OP_GET).await?;
    Ok(contenido)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El camino feliz vive en `tests/backup_mock.rs` y en
    /// `tests/ciclo_completo.rs`, que necesitan dos procesos de verdad. Aquí
    /// solo se comprueba lo que un test de integración no puede provocar a
    /// voluntad: que los errores digan lo que hay que decir.
    #[test]
    fn el_error_de_conexion_nombra_al_plugin_la_operacion_y_el_plazo() {
        // Sin el plazo en el mensaje, quien lo lea no sabe si esperó un segundo
        // o media hora, y por tanto no sabe si el problema es lentitud o un
        // plugin que nunca iba a conectarse.
        let texto = BackupError::SinConexion {
            plugin: "r2".into(),
            operacion: OP_PUT.into(),
        }
        .to_string();
        assert!(texto.contains("r2"));
        assert!(texto.contains("put"));
        assert!(texto.contains(&PLAZO_CONEXION.as_secs().to_string()));
    }

    #[test]
    fn el_error_de_transferencia_distingue_al_plugin_culpable() {
        // Una operación tiene dos plugins vivos: «falló la transferencia»
        // obliga a adivinar cuál.
        let texto = BackupError::Transferencia {
            plugin: "postgres".into(),
            operacion: OP_DUMP.into(),
            mensaje: "conexión rechazada".into(),
        }
        .to_string();
        assert!(texto.contains("postgres"));
        assert!(texto.contains("dump"));
        assert!(texto.contains("conexión rechazada"));
    }

    #[test]
    fn una_capacidad_ausente_se_propaga_tal_cual() {
        // El mensaje de `PluginError` ya es el bueno; envolverlo otra vez solo
        // añadiría ruido delante.
        let error = BackupError::from(PluginError::SinCapacidad {
            plugin: "solo-destino".into(),
            capacidad: "engine".into(),
        });
        assert_eq!(
            error.to_string(),
            "el plugin «solo-destino» no sabe hacer de «engine»"
        );
    }

    #[test]
    fn el_error_de_apertura_dice_su_propio_plazo() {
        let texto = BackupError::SinRespuesta {
            plugin: "s3".into(),
            operacion: OP_PUT.into(),
        }
        .to_string();
        assert!(texto.contains("s3"));
        assert!(texto.contains(&PLAZO_APERTURA.as_secs().to_string()));
    }

    #[test]
    fn el_error_de_manifiesto_ausente_dice_la_clave_que_buscaba() {
        // Es la diferencia entre «no encuentro el manifiesto» —que no ayuda— y
        // saber si se perdió o si el artefacto nunca se llamó así.
        let texto = BackupError::SinManifiesto {
            plugin: "r2".into(),
            clave: "prod/2026/x.age.manifest.json".into(),
            motivo: "NotFound: no existe".into(),
        }
        .to_string();
        assert!(texto.contains("prod/2026/x.age.manifest.json"));
        assert!(texto.contains("manifiesto"));
        assert!(texto.contains("r2"));
    }
}
