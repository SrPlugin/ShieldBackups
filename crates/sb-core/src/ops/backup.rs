//! La operación de backup: motor → núcleo → destino, en un solo paso y sin
//! tocar el disco local.
//!
//! ```text
//! plugin-motor ──[socket datos]──▶ núcleo ──[socket datos]──▶ plugin-destino
//!                               zstd → age → SHA-256
//! ```
//!
//! Los bytes cruzan **dos veces** el límite de proceso y en ningún momento se
//! materializan enteros: la memoria que usa un backup de un terabyte es la
//! misma que la de uno de un megabyte.
//!
//! # El orden de las llamadas
//!
//! Se llama primero a `Storage.Put` y **después** a `Engine.Dump`, que es justo
//! al revés de como se lee el diagrama. La razón está en [`ejecutar_backup`] y
//! no es una preferencia estilística: es la diferencia entre un backup que
//! termina y uno que se cuelga.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sb_crypto::{BackupOptions, BackupSummary, CompressionLevel, PipelineError, Recipient};
use sb_proto::engine_client::EngineClient;
use sb_proto::storage_client::StorageClient;
use sb_proto::{DumpRequest, Progress, PutRequest};
use sb_transport::DataChannel;
use tokio::io::AsyncWriteExt as _;
use tokio::net::UnixStream;
use tokio::task::JoinHandle;
use tonic::Streaming;

use crate::model::{
    CompressionInfo, EncryptionInfo, EngineInfo, MANIFEST_VERSION, Manifest, ManifestError,
};
use crate::plugin::client::mensaje_de;
use crate::plugin::{Capacidad, PluginClient, PluginError};

/// Plazo para que el RPC que abre una transferencia devuelva sus cabeceras.
///
/// `Dump` y `Put` pueden tardar horas en **terminar**, pero en contestar no:
/// lo único que hacen antes de responder es validar la petición y lanzar su
/// tarea. Un plugin que ni siquiera llega a eso no va a mover un byte.
const PLAZO_APERTURA: Duration = Duration::from_secs(60);

/// Plazo para que el plugin se conecte al canal de datos que se le ofreció.
///
/// Sin este plazo, un plugin que acepta el RPC y luego no abre el socket
/// dejaría el `accept` esperando para siempre: el backup no fallaría, se
/// quedaría colgado, que es peor porque nadie se entera hasta que hace falta
/// restaurar.
const PLAZO_CONEXION: Duration = Duration::from_secs(30);

/// Algoritmo de compresión que registra el manifiesto. Lo fija el pipeline de
/// `sb-crypto`, no la configuración.
const ALGORITMO_COMPRESION: &str = "zstd";
/// Algoritmo de cifrado, por el mismo motivo.
const ALGORITMO_CIFRADO: &str = "age";

const OP_DUMP: &str = "dump";
const OP_PUT: &str = "put";

/// Todo lo que puede salir mal en un backup.
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
    /// La tarea que seguía el progreso se cayó. No es culpa del plugin, pero el
    /// backup tampoco se puede dar por bueno.
    #[error("se perdió el seguimiento de {operacion} del plugin «{plugin}»: {fuente}")]
    Seguimiento {
        plugin: String,
        operacion: String,
        fuente: tokio::task::JoinError,
    },
    /// Falló comprimir, cifrar o hashear.
    #[error("el pipeline de cifrado falló: {0}")]
    Pipeline(#[from] PipelineError),
    /// Falló escribir en el canal de datos desde el núcleo.
    #[error("error de E/S en el canal de datos con «{plugin}»: {fuente}")]
    Io {
        plugin: String,
        fuente: std::io::Error,
    },
    /// El manifiesto no se pudo serializar.
    #[error("no se pudo escribir el manifiesto: {0}")]
    Manifiesto(#[from] ManifestError),
}

/// Todo lo que hace falta para un backup, ya resuelto.
///
/// Los plugins llegan **arrancados y configurados**: esta operación no decide
/// qué plugin usar ni cómo configurarlo, solo los pone a hablar.
pub struct BackupRequest<'a> {
    pub target: String,
    pub engine: &'a PluginClient,
    pub storage: &'a PluginClient,
    pub artifact_key: String,
    pub recipient: Recipient,
    pub level: CompressionLevel,
    pub engine_version: String,
    pub server_version: String,
    /// Marca ISO-8601 en UTC. La calcula quien llama, para que la operación
    /// sea determinista y testeable.
    pub created_at: String,
}

/// Lo que queda de un backup que salió bien.
#[derive(Debug, Clone)]
pub struct BackupOutcome {
    pub summary: BackupSummary,
    pub artifact_key: String,
}

/// Ejecuta un backup completo y deja el artefacto y su manifiesto en el destino.
///
/// # El orden de `Put` y `Dump`, que es contraintuitivo a propósito
///
/// `Storage.Put` se llama **antes** que `Engine.Dump`. Leyendo el diagrama de
/// arriba se diría que el productor va primero, y es exactamente el cambio que
/// alguien intentará hacer algún día.
///
/// No lo hagas, y esta es la razón con lo que se sabe medido detrás.
///
/// El socket del volcado tiene un búfer del kernel de unos 208 KiB
/// (`net.core.wmem_default`). Si el motor arranca antes de que el destino esté
/// colocado, escribe en un socket que todavía nadie va a drenar y se bloquea en
/// su `write` en cuanto ese búfer se llena. **Lo que ocurre después depende de
/// algo que este código no controla: de cómo esté escrito el plugin.**
///
/// Se probó a invertir el orden y los tests de `tests/backup_mock.rs` siguen
/// pasando, incluso metiendo tres segundos de retardo entre las dos llamadas:
/// con plugins como el mock —cuyo `Dump` devuelve las cabeceras del RPC de
/// inmediato y hace el trabajo en una tarea aparte— el motor no se cuelga, solo
/// se queda parado en su `write` hasta que el núcleo llega al `accept` y el
/// pipeline empieza a drenar. Que aquí no se vea no significa que dé igual:
///
/// * Un plugin cuyo `Dump` escriba **antes** de devolver la respuesta del RPC
///   —el protocolo no lo prohíbe— nunca contestaría, y `Dump` primero
///   significaría que `Put` no llega a llamarse jamás. Eso sí es el bloqueo, y
///   solo lo corta el plazo de [`PLAZO_APERTURA`].
/// * Con `Dump` primero, un `Put` que falle —clave inválida, destino caído—
///   deja detrás un motor ya lanzado, escribiendo contra un socket que se va a
///   cerrar debajo. Poner `Put` delante hace que ese fallo ocurra antes de
///   haber movido un solo byte.
///
/// La regla que hay debajo es la que vale la pena recordar: **el consumidor se
/// coloca antes que el productor**, siempre. Es gratis y quita de en medio una
/// clase entera de cuelgues que, por definición, no se manifiestan en las
/// pruebas donde todo va bien.
///
/// # Errors
/// Devuelve [`BackupError`] si algún plugin no tiene la capacidad que se le
/// pide, si no se conecta a su canal de datos dentro del plazo, si la
/// transferencia se rompe o si falla el pipeline.
pub async fn ejecutar_backup(req: BackupRequest<'_>) -> Result<BackupOutcome, BackupError> {
    // 1. Antes de nada: que cada plugin sepa hacer el papel que se le asigna.
    //    Descubrirlo aquí cuesta una comparación de cadenas; descubrirlo a
    //    mitad del volcado cuesta el volcado.
    req.engine.exigir_capacidad(Capacidad::Engine)?;
    req.storage.exigir_capacidad(Capacidad::Storage)?;

    // 2. Un canal por plugin, cada uno dentro del directorio de ejecución de su
    //    dueño: es el único sitio al que ese proceso tiene acceso garantizado.
    let canal_volcado = crear_canal(req.engine)?;
    let canal_subida = crear_canal(req.storage)?;

    // 3 y 4. EL CONSUMIDOR PRIMERO. Ver la nota de arriba antes de tocar esto.
    let subida = iniciar_put(req.storage, &req.artifact_key, &canal_subida).await?;
    let volcado = iniciar_dump(req.engine, &canal_volcado).await?;

    // 6. Ambos plugins tienen ya su orden; ahora deben aparecer por el socket.
    let fuente = aceptar(&canal_volcado, req.engine.nombre(), OP_DUMP).await?;
    let sumidero = aceptar(&canal_subida, req.storage.nombre(), OP_PUT).await?;

    // 7. El núcleo no es más que el tramo de tubería entre los dos sockets.
    let recipiente = req.recipient.to_string();
    let summary = sb_crypto::backup(
        fuente,
        sumidero,
        &BackupOptions {
            recipient: req.recipient,
            level: req.level,
        },
    )
    .await?;

    // 8. El pipeline ha terminado, pero los plugins no tienen por qué: el
    //    destino aún puede estar cerrando su fichero. Sin esperar aquí, el
    //    manifiesto podría describir un artefacto que todavía no está entero.
    esperar_progreso(volcado, req.engine.nombre(), OP_DUMP).await?;
    esperar_progreso(subida, req.storage.nombre(), OP_PUT).await?;

    // 9. El manifiesto sube por el mismo camino que el artefacto —otro canal,
    //    otro `Put`—. Un segundo camino (un RPC aparte que escribiera el JSON)
    //    sería más corto, pero permitiría que artefacto y manifiesto acabaran
    //    en sitios distintos o con permisos distintos sin que nadie lo notase.
    let manifiesto = Manifest {
        version: MANIFEST_VERSION,
        target: req.target,
        engine: EngineInfo {
            plugin: req.engine.nombre().to_string(),
            plugin_version: req.engine_version,
            server_version: req.server_version,
        },
        created_at: req.created_at,
        artifact_key: req.artifact_key.clone(),
        plaintext_bytes: summary.plaintext_bytes,
        ciphertext_bytes: summary.ciphertext_bytes,
        plaintext_sha256: summary.plaintext_sha256.to_hex(),
        ciphertext_sha256: summary.ciphertext_sha256.to_hex(),
        compression: CompressionInfo {
            algorithm: ALGORITMO_COMPRESION.to_string(),
            level: req.level.get(),
        },
        encryption: EncryptionInfo {
            algorithm: ALGORITMO_CIFRADO.to_string(),
            recipient: recipiente,
        },
    };
    subir_blob(
        req.storage,
        &manifiesto.manifest_key(),
        manifiesto.to_json()?.as_bytes(),
    )
    .await?;

    tracing::info!(
        clave = %req.artifact_key,
        plaintext = summary.plaintext_bytes,
        ciphertext = summary.ciphertext_bytes,
        "backup completado"
    );

    Ok(BackupOutcome {
        summary,
        artifact_key: req.artifact_key,
    })
}

/// Sube un contenido pequeño que ya está en memoria.
///
/// Lo usa el manifiesto, y lo usarán las marcas que `verify` y `restore`
/// necesiten dejar en el destino. Recorre exactamente los mismos pasos que el
/// artefacto —canal, `Put`, `accept` con plazo, progreso— porque un segundo
/// camino de subida es un segundo comportamiento que mantener.
///
/// # Errors
/// Las mismas que [`ejecutar_backup`], menos las del pipeline.
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

/// Crea el canal de datos dentro del directorio de ejecución de `plugin`.
///
/// El nombre lleva un contador porque una misma pareja de plugins hace varios
/// backups seguidos y dos canales vivos a la vez con el mismo nombre se
/// pisarían el socket.
fn crear_canal(plugin: &PluginClient) -> Result<DataChannel, BackupError> {
    static SIGUIENTE: AtomicU64 = AtomicU64::new(0);
    let nombre = format!("datos-{}", SIGUIENTE.fetch_add(1, Ordering::Relaxed));
    DataChannel::create(plugin.proceso().runtime_dir(), &nombre).map_err(|fuente| {
        BackupError::Canal {
            plugin: plugin.nombre().to_string(),
            fuente,
        }
    })
}

/// Le pide al destino que se ponga a leer del canal.
async fn iniciar_put(
    storage: &PluginClient,
    clave: &str,
    canal: &DataChannel,
) -> Result<JoinHandle<Result<u64, BackupError>>, BackupError> {
    let mut grpc = StorageClient::new(storage.canal());
    let peticion = PutRequest {
        key: clave.to_string(),
        data_socket: canal.path().to_string_lossy().into_owned(),
    };
    let flujo = abrir(storage.nombre(), OP_PUT, grpc.put(peticion)).await?;
    Ok(seguir_progreso(storage.nombre().to_string(), OP_PUT, flujo))
}

/// Le pide al motor que se ponga a escribir en el canal.
async fn iniciar_dump(
    engine: &PluginClient,
    canal: &DataChannel,
) -> Result<JoinHandle<Result<u64, BackupError>>, BackupError> {
    let mut grpc = EngineClient::new(engine.canal());
    let peticion = DumpRequest {
        data_socket: canal.path().to_string_lossy().into_owned(),
    };
    let flujo = abrir(engine.nombre(), OP_DUMP, grpc.dump(peticion)).await?;
    Ok(seguir_progreso(engine.nombre().to_string(), OP_DUMP, flujo))
}

/// El plazo y la traducción de errores de un RPC de transferencia, en un solo
/// sitio: basta con olvidar el `timeout` una vez para que un plugin mudo deje
/// el backup esperando.
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
async fn aceptar(
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
async fn esperar_progreso(
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

#[cfg(test)]
mod tests {
    use super::*;

    /// El camino feliz vive en `tests/backup_mock.rs`, que necesita dos
    /// procesos de verdad. Aquí solo se comprueba lo que un test de integración
    /// no puede provocar a voluntad: que los errores digan lo que hay que decir.
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
        // Un backup tiene dos plugins vivos: «falló la transferencia» obliga a
        // adivinar cuál.
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
}
