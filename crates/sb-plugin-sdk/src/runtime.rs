//! Arranque de un plugin: del sobre de stdin al servidor gRPC escuchando.
//!
//! Todo lo que hace un plugin al nacer —leer el sobre, negociar la versión,
//! montar el TLS, levantar el servidor y anunciarse— cabe en una llamada a
//! [`PluginRuntime::serve`].

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sb_proto::PROTOCOL_VERSION;
use sb_proto::engine_server::{Engine, EngineServer};
use sb_proto::plugin_server::{Plugin, PluginServer};
use sb_proto::storage_server::{Storage, StorageServer};
use sb_transport::{Bootstrap, MAGIC, Ready, serve_control_routes, server_config_from_bundle};
use tokio::io::{AsyncBufReadExt, BufReader};
use tonic::service::Routes;

/// Cuánto se espera a que el socket de control aparezca antes de rendirse.
/// Anunciarse antes de estar escuchando hace que el núcleo falle al conectar,
/// así que se espera; pero se espera **acotado**, para que un fallo al enlazar
/// no deje al núcleo colgado hasta su propio timeout.
const ESPERA_SOCKET: Duration = Duration::from_secs(2);
/// Granularidad del sondeo del socket.
const SONDEO_SOCKET: Duration = Duration::from_millis(10);

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error(
        "no se recibió el sobre de arranque por stdin; ¿se ejecutó este binario a mano en vez de desde shieldbk?"
    )]
    SinBootstrap,
    #[error(transparent)]
    Handshake(#[from] sb_transport::HandshakeError),
    #[error(transparent)]
    Pki(#[from] sb_transport::PkiError),
    #[error(transparent)]
    Control(#[from] sb_transport::ControlError),
    /// El servidor arrancó pero el socket nunca llegó a existir. Se prefiere
    /// fallar aquí, con la ruta en el mensaje, antes que anunciarse igualmente
    /// y que el núcleo vea un "conexión rechazada" sin explicación.
    #[error("el canal de control no llegó a escuchar en {ruta} tras {espera_ms} ms")]
    SocketNoAparecio { ruta: String, espera_ms: u64 },
    /// La tarea que sirve el canal murió de forma anómala (panic o cancelación).
    #[error("la tarea del canal de control terminó de forma anómala: {0}")]
    TareaDelServidor(String),
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
}

/// Capacidades que se anuncian, derivadas de los servicios registrados.
fn capacidades(motor: bool, destino: bool) -> Vec<String> {
    let mut v = Vec::new();
    if motor {
        v.push("engine".to_string());
    }
    if destino {
        v.push("storage".to_string());
    }
    v
}

fn construir_ready(protocol_version: u32, motor: bool, destino: bool, pid: u32) -> Ready {
    Ready {
        magic: MAGIC.into(),
        protocol_version,
        capabilities: capacidades(motor, destino),
        pid,
    }
}

/// Un servicio ya envuelto en su `*Server`, guardado como la operación de
/// añadirlo a las rutas.
///
/// Cada `*Server<T>` tiene un tipo distinto y `Routes` no se puede fusionar con
/// otro `Routes`, así que lo que se guarda no es el servicio sino la función
/// que lo registra. Eso mantiene `PluginRuntime` con un único parámetro de tipo
/// —el del plugin— en vez de arrastrar uno por cada capacidad opcional.
type Registro = Box<dyn FnOnce(Routes) -> Routes + Send>;

/// Arranque de un plugin.
///
/// Registra los servicios que el plugin implementa y llama a
/// [`PluginRuntime::serve`]. Las capacidades que se anuncian al núcleo **se
/// derivan de lo registrado**: un plugin no puede declarar un motor que no
/// implementa, porque no hay forma de declararlo por separado.
///
/// ```ignore
/// PluginRuntime::new(MiPlugin::default())
///     .con_motor(MiMotor::default())
///     .serve()
///     .await?;
/// ```
pub struct PluginRuntime<P> {
    plugin: P,
    motor: Option<Registro>,
    destino: Option<Registro>,
}

impl<P: Plugin> PluginRuntime<P> {
    /// Un plugin que solo implementa el servicio `Plugin`, obligatorio para todos.
    #[must_use]
    pub fn new(plugin: P) -> Self {
        Self {
            plugin,
            motor: None,
            destino: None,
        }
    }

    /// Registra el motor de volcado/restauración. Anuncia la capacidad `engine`.
    ///
    /// Registrarlo dos veces se queda con el último: dos motores en el mismo
    /// canal se pisarían las rutas, y un `Option` lo hace imposible.
    #[must_use]
    pub fn con_motor<E: Engine>(mut self, motor: E) -> Self {
        self.motor = Some(Box::new(move |r: Routes| {
            r.add_service(EngineServer::new(motor))
        }));
        self
    }

    /// Registra el destino de almacenamiento. Anuncia la capacidad `storage`.
    #[must_use]
    pub fn con_destino<S: Storage>(mut self, destino: S) -> Self {
        self.destino = Some(Box::new(move |r: Routes| {
            r.add_service(StorageServer::new(destino))
        }));
        self
    }

    /// Ejecuta el plugin hasta que el núcleo cierre el canal.
    ///
    /// El logging va a **stderr**: stdout está reservado para la línea del
    /// handshake, y cualquier otra cosa ahí rompe el arranque.
    ///
    /// # Errors
    ///
    /// Devuelve [`SdkError::SinBootstrap`] si stdin se cierra sin sobre,
    /// [`SdkError::Handshake`] si el sobre no es válido o no hay versión de
    /// protocolo en común, [`SdkError::Pki`] si el material TLS no se puede
    /// cargar, [`SdkError::SocketNoAparecio`] si el canal no llega a escuchar,
    /// y [`SdkError::Control`] o [`SdkError::Io`] si el servidor falla.
    pub async fn serve(self) -> Result<(), SdkError> {
        iniciar_logging();

        let bootstrap = leer_bootstrap().await?;
        let version = bootstrap.negotiate(&[PROTOCOL_VERSION])?;
        let tls = server_config_from_bundle(&bootstrap.tls)?;

        let motor = self.motor.is_some();
        let destino = self.destino.is_some();

        let mut rutas = Routes::new(PluginServer::new(self.plugin));
        if let Some(registrar) = self.motor {
            rutas = registrar(rutas);
        }
        if let Some(registrar) = self.destino {
            rutas = registrar(rutas);
        }

        let socket = PathBuf::from(&bootstrap.control_socket);
        let socket_del_servidor = socket.clone();
        let mut servidor =
            tokio::spawn(
                async move { serve_control_routes(&socket_del_servidor, tls, rutas).await },
            );

        // Anunciarse antes de estar escuchando es una carrera perdida: el
        // núcleo conectaría contra un socket que aún no existe.
        esperar_socket(&socket, &mut servidor).await?;

        tracing::debug!(
            protocolo = version,
            socket = %socket.display(),
            motor,
            destino,
            "canal de control escuchando; anunciando ready"
        );
        anunciar(&construir_ready(
            version,
            motor,
            destino,
            std::process::id(),
        ))?;

        match servidor.await {
            Ok(resultado) => Ok(resultado?),
            Err(e) => Err(SdkError::TareaDelServidor(e.to_string())),
        }
    }
}

/// Inicializa el logging **a stderr**.
///
/// `try_init` en vez de `init` a propósito: `init` panica si ya hay un
/// suscriptor global, lo que impediría usar un plugin desde un test que ya
/// inicializó el suyo.
fn iniciar_logging() {
    let filtro = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    // El writer se fija explícitamente: el de fábrica es stdout, y ahí solo
    // puede ir la línea del handshake.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filtro)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Lee el sobre de arranque: una única línea JSON por stdin.
async fn leer_bootstrap() -> Result<Bootstrap, SdkError> {
    let mut entrada = BufReader::new(tokio::io::stdin());
    let mut linea = String::new();
    if entrada.read_line(&mut linea).await? == 0 || linea.trim().is_empty() {
        return Err(SdkError::SinBootstrap);
    }
    // `from_line` ya valida el marcador y la versión del sobre.
    Ok(Bootstrap::from_line(&linea)?)
}

/// Espera, acotadamente, a que el socket de control exista.
///
/// Vigila de paso la tarea del servidor: si murió al enlazar, se propaga *su*
/// error —que dice qué pasó— en vez de un timeout que solo dice que no pasó nada.
async fn esperar_socket(
    socket: &Path,
    servidor: &mut tokio::task::JoinHandle<Result<(), sb_transport::ControlError>>,
) -> Result<(), SdkError> {
    let limite = tokio::time::Instant::now() + ESPERA_SOCKET;
    loop {
        if socket.exists() {
            return Ok(());
        }
        if servidor.is_finished() {
            return match servidor.await {
                Ok(resultado) => {
                    resultado?;
                    // Terminó sin error y sin socket: no hay nada que servir.
                    Err(SdkError::SocketNoAparecio {
                        ruta: socket.display().to_string(),
                        espera_ms: u64::try_from(ESPERA_SOCKET.as_millis()).unwrap_or(u64::MAX),
                    })
                }
                Err(e) => Err(SdkError::TareaDelServidor(e.to_string())),
            };
        }
        if tokio::time::Instant::now() >= limite {
            return Err(SdkError::SocketNoAparecio {
                ruta: socket.display().to_string(),
                espera_ms: u64::try_from(ESPERA_SOCKET.as_millis()).unwrap_or(u64::MAX),
            });
        }
        tokio::time::sleep(SONDEO_SOCKET).await;
    }
}

/// Escribe la línea `Ready` en stdout y la vacía.
///
/// Síncrono a propósito: es una sola línea, una sola vez, y el `flush` explícito
/// importa más que la asincronía. Sin él, el núcleo esperaría un anuncio que
/// duerme en el búfer.
fn anunciar(ready: &Ready) -> Result<(), SdkError> {
    let linea = ready.to_line()?;
    let mut salida = std::io::stdout().lock();
    writeln!(salida, "{linea}")?;
    salida.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn un_plugin_sin_servicios_extra_solo_anuncia_lo_basico() {
        assert!(capacidades(false, false).is_empty());
    }

    #[test]
    fn un_motor_anuncia_engine() {
        assert_eq!(capacidades(true, false), vec!["engine"]);
    }

    #[test]
    fn un_destino_anuncia_storage() {
        assert_eq!(capacidades(false, true), vec!["storage"]);
    }

    #[test]
    fn un_plugin_que_hace_ambas_cosas_anuncia_ambas() {
        assert_eq!(capacidades(true, true), vec!["engine", "storage"]);
    }

    #[test]
    fn la_linea_de_ready_lleva_el_marcador_y_la_version_negociada() {
        let r = construir_ready(1, true, false, 4242);
        assert_eq!(r.magic, sb_transport::MAGIC);
        assert_eq!(r.protocol_version, 1);
        assert_eq!(r.capabilities, vec!["engine"]);
        assert_eq!(r.pid, 4242);
    }

    #[test]
    fn el_ready_se_serializa_en_una_sola_linea() {
        // El núcleo lo lee con un read_line: si llevara saltos, se cortaría.
        let linea = construir_ready(1, true, true, 1).to_line().unwrap();
        assert!(!linea.contains('\n'));
        assert!(sb_transport::Ready::from_line(&linea).is_ok());
    }

    #[test]
    fn las_capacidades_declaradas_coinciden_con_los_servicios_registrados() {
        // La razón de derivarlas en vez de pasarlas a mano: un plugin no puede
        // anunciar un motor que no implementa.
        for (motor, destino) in [(false, false), (true, false), (false, true), (true, true)] {
            let r = construir_ready(1, motor, destino, 1);
            assert_eq!(r.capabilities.contains(&"engine".to_string()), motor);
            assert_eq!(r.capabilities.contains(&"storage".to_string()), destino);
        }
    }
}
