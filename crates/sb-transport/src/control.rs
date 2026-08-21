//! Canal de control gRPC entre el núcleo y un plugin.
//!
//! El canal viaja sobre un socket Unix con TLS mutuo. `tonic` trae soporte TLS
//! de fábrica, pero atado a su transporte TCP: en la versión 0.14 pedirle una
//! configuración TLS a un `Endpoint` de tipo UDS falla con
//! `InvalidTlsConfigForUds`. Por eso aquí el TLS se monta a mano con
//! `tokio-rustls` y se le entrega a tonic ya envuelto, que es la única forma de
//! combinar socket Unix con TLS mutuo.

use std::convert::Infallible;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tonic::body::Body;
use tonic::server::NamedService;
use tonic::service::Routes;
use tonic::transport::server::Connected;
use tonic::transport::{Channel, Endpoint, Server};
use tower::Service;
use tower::service_fn;

#[cfg(test)]
use crate::pki::EphemeralPki;
use crate::pki::SERVER_NAME;

/// Fallos al levantar o usar el canal de control.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// El núcleo no pudo abrir el canal hacia el plugin.
    #[error("no se pudo conectar al canal de control del plugin: {0}")]
    Conexion(String),
    /// El plugin no pudo servir el canal de control.
    #[error("no se pudo levantar el canal de control: {0}")]
    Servidor(String),
    /// Fallo del sistema de ficheros al preparar el socket.
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
}

/// Envoltorio sobre una conexión TLS en socket Unix.
///
/// Existe solo para satisfacer el trait `Connected` de tonic, que la regla de
/// coherencia nos impide implementar sobre `TlsStream` directamente.
/// No hay metadatos de conexión que exponer: la identidad del par ya la
/// garantiza el TLS mutuo, que es más fuerte que cualquier cosa que se pudiera
/// sacar del socket.
#[derive(Debug)]
struct TlsUnixStream(tokio_rustls::server::TlsStream<UnixStream>);

impl Connected for TlsUnixStream {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl AsyncRead for TlsUnixStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsUnixStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Prepara el socket Unix y devuelve el flujo de conexiones ya cifradas.
///
/// Lo comparten [`serve_control`] y [`serve_control_routes`]: el trabajo sucio
/// —limpiar el socket huérfano, enlazar, aceptar y envolver en TLS— es idéntico
/// en ambos casos y no debe divergir.
fn conexiones_entrantes(
    socket: &Path,
    tls: Arc<ServerConfig>,
) -> Result<impl tokio_stream::Stream<Item = Result<TlsUnixStream, std::io::Error>>, ControlError> {
    // Un plugin que murió sin limpiar deja el socket huérfano: `bind` fallaría
    // con "address already in use" sobre un fichero que ya no sirve a nadie.
    if socket.exists() {
        std::fs::remove_file(socket)?;
    }
    let listener = UnixListener::bind(socket)?;
    let acceptor = TlsAcceptor::from(tls);

    Ok(async_stream::stream! {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let acceptor = acceptor.clone();
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => yield Ok::<_, std::io::Error>(TlsUnixStream(tls_stream)),
                        // Un handshake fallido no debe tumbar el servidor: se
                        // registra y se sigue aceptando. Si el error se
                        // propagara al stream, tonic cerraría el servidor
                        // entero y cualquiera podría dejar el plugin
                        // inservible con una conexión basura.
                        Err(e) => tracing::warn!(error = %e, "handshake TLS rechazado"),
                    }
                }
                Err(e) => tracing::warn!(error = %e, "accept falló"),
            }
        }
    })
}

/// Levanta el servidor gRPC del plugin sobre un socket Unix con TLS mutuo.
///
/// Sirve **un solo** servicio. Es la vía cómoda para tests y para código que
/// solo necesita exponer `Plugin`; un plugin real expone además `Engine` y/o
/// `Storage`, y para eso está [`serve_control_routes`]. Esta función delega en
/// ella con unas rutas de un único servicio, así que el comportamiento del
/// socket, del TLS y de los handshakes rechazados es exactamente el mismo.
///
/// El futuro solo termina si el servidor muere; lo normal es abortarlo o
/// dejarlo corriendo durante toda la vida del plugin.
///
/// # Errors
///
/// Devuelve [`ControlError::Io`] si el socket no se puede preparar o enlazar, y
/// [`ControlError::Servidor`] si tonic no puede servir sobre él.
pub async fn serve_control<S>(
    socket: &Path,
    tls: Arc<ServerConfig>,
    servicio: S,
) -> Result<(), ControlError>
where
    S: Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>
        + NamedService
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    serve_control_routes(socket, tls, Routes::new(servicio)).await
}

/// Levanta el servidor gRPC del plugin sirviendo **varios** servicios por el
/// mismo canal.
///
/// Es la función que usan los plugins reales: el protocolo obliga a todos a
/// implementar `Plugin`, y encima cada uno expone `Engine`, `Storage` o ambos
/// según sus capacidades. Con un solo servicio por canal —lo que ofrece
/// [`serve_control`]— ningún plugin de verdad podría funcionar.
///
/// Las rutas se montan fuera y se pasan ya construidas porque cada servicio
/// tiene su propio tipo: agruparlos en un [`Routes`] es lo que permite pasar un
/// número variable de ellos por un único parámetro.
///
/// Un método pedido a un servicio que no se registró se responde con
/// `Unimplemented`, que es lo que hace el fallback de [`Routes`]. Es la
/// respuesta correcta: el núcleo se entera de que el plugin no tiene esa
/// capacidad en lugar de quedarse colgado o ver un error de transporte opaco.
///
/// El futuro solo termina si el servidor muere; lo normal es abortarlo o
/// dejarlo corriendo durante toda la vida del plugin.
///
/// # Errors
///
/// Devuelve [`ControlError::Io`] si el socket no se puede preparar o enlazar, y
/// [`ControlError::Servidor`] si tonic no puede servir sobre él.
pub async fn serve_control_routes(
    socket: &Path,
    tls: Arc<ServerConfig>,
    rutas: Routes,
) -> Result<(), ControlError> {
    let incoming = conexiones_entrantes(socket, tls)?;

    Server::builder()
        .add_routes(rutas)
        .serve_with_incoming(incoming)
        .await
        .map_err(|e| ControlError::Servidor(e.to_string()))
}

/// Presupuesto que el núcleo le concede al plugin para tener el socket listo.
const ESPERA_SOCKET: std::time::Duration = std::time::Duration::from_millis(500);
/// Pausa entre intentos mientras se agota [`ESPERA_SOCKET`].
const PAUSA_ENTRE_INTENTOS: std::time::Duration = std::time::Duration::from_millis(10);

/// Abre el socket del plugin, tolerando que todavía no esté escuchando.
///
/// El núcleo conecta justo después de arrancar el proceso del plugin, así que
/// es normal encontrarse el socket sin crear —o encontrarse el fichero huérfano
/// que dejó una ejecución anterior, que el plugin borrará en cuanto arranque—.
/// Reintentar durante un presupuesto corto evita convertir una carrera de
/// milisegundos en un fallo de arranque; pasado el presupuesto se devuelve el
/// último error real, no uno inventado.
async fn conectar_socket(ruta: &Path) -> Result<UnixStream, std::io::Error> {
    let limite = std::time::Instant::now() + ESPERA_SOCKET;
    loop {
        match UnixStream::connect(ruta).await {
            Ok(stream) => return Ok(stream),
            Err(e) if std::time::Instant::now() < limite => {
                tracing::trace!(error = %e, "socket de control aún no disponible, reintentando");
                tokio::time::sleep(PAUSA_ENTRE_INTENTOS).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Conecta el núcleo al canal de control del plugin.
///
/// El canal devuelto es reutilizable: multiplexa todas las llamadas sobre una
/// sola conexión, de modo que el handshake TLS se paga una única vez.
///
/// # Errors
///
/// Devuelve [`ControlError::Conexion`] si el socket no existe, si el handshake
/// TLS no se completa o si el par no presenta un certificado de la CA esperada.
pub async fn connect_control(
    socket: &Path,
    tls: Arc<ClientConfig>,
) -> Result<Channel, ControlError> {
    let ruta = socket.to_path_buf();
    let connector = TlsConnector::from(tls);

    // La URI es un marcador: la conexión real la hace el conector de abajo.
    // El nombre debe coincidir con el SAN del certificado del servidor.
    Endpoint::try_from(format!("https://{SERVER_NAME}"))
        .map_err(|e| ControlError::Conexion(e.to_string()))?
        .connect_with_connector(service_fn(move |_: http::Uri| {
            let ruta = ruta.clone();
            let connector = connector.clone();
            async move {
                let stream = conectar_socket(&ruta).await?;
                let nombre = ServerName::try_from(SERVER_NAME).map_err(std::io::Error::other)?;
                let tls_stream = connector.connect(nombre, stream).await?;
                Ok::<_, std::io::Error>(TokioIo::new(tls_stream))
            }
        }))
        .await
        .map_err(|e| ControlError::Conexion(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_proto::plugin_server::{Plugin, PluginServer};
    use sb_proto::{
        Capability, ConfigureRequest, ConfigureResponse, InfoRequest, InfoResponse,
        PROTOCOL_VERSION, PreflightRequest, PreflightResponse, SchemaRequest, SchemaResponse,
        ShutdownRequest, ShutdownResponse,
    };
    use tonic::{Request, Response, Status};

    /// Plugin trivial: solo sirve para comprobar que el transporte funciona.
    struct PluginDePrueba;

    #[tonic::async_trait]
    impl Plugin for PluginDePrueba {
        async fn info(&self, _: Request<InfoRequest>) -> Result<Response<InfoResponse>, Status> {
            Ok(Response::new(InfoResponse {
                name: "prueba".into(),
                version: "0.0.1".into(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: vec![Capability::Engine as i32],
            }))
        }
        async fn schema(
            &self,
            _: Request<SchemaRequest>,
        ) -> Result<Response<SchemaResponse>, Status> {
            Ok(Response::new(SchemaResponse { fields: vec![] }))
        }
        async fn configure(
            &self,
            _: Request<ConfigureRequest>,
        ) -> Result<Response<ConfigureResponse>, Status> {
            Ok(Response::new(ConfigureResponse {}))
        }
        async fn preflight(
            &self,
            _: Request<PreflightRequest>,
        ) -> Result<Response<PreflightResponse>, Status> {
            Ok(Response::new(PreflightResponse {
                ok: true,
                checks: vec![],
                server_version: String::new(),
            }))
        }
        async fn shutdown(
            &self,
            _: Request<ShutdownRequest>,
        ) -> Result<Response<ShutdownResponse>, Status> {
            Ok(Response::new(ShutdownResponse {}))
        }
    }

    /// Levanta el servidor y espera a que el socket exista.
    async fn levantar(
        socket: &std::path::Path,
        tls: std::sync::Arc<rustls::ServerConfig>,
    ) -> tokio::task::JoinHandle<()> {
        let ruta = socket.to_path_buf();
        let h = tokio::spawn(async move {
            let _ = serve_control(&ruta, tls, PluginServer::new(PluginDePrueba)).await;
        });
        for _ in 0..200 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        h
    }

    #[tokio::test]
    async fn el_nucleo_habla_con_el_plugin_por_uds_con_mtls() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();

        let servidor = levantar(&socket, pki.server_config().unwrap()).await;

        let canal = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();
        let mut cliente = sb_proto::plugin_client::PluginClient::new(canal);
        let info = cliente.info(InfoRequest {}).await.unwrap().into_inner();

        assert_eq!(info.name, "prueba");
        assert_eq!(info.protocol_version, PROTOCOL_VERSION);
        servidor.abort();
    }

    #[tokio::test]
    async fn varias_llamadas_reutilizan_el_mismo_canal() {
        // El núcleo hace Info, Schema, Configure y Preflight sobre una sola
        // conexión: si el canal no fuera reutilizable, cada RPC pagaría un
        // handshake TLS.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();
        let servidor = levantar(&socket, pki.server_config().unwrap()).await;

        let canal = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();
        let mut cliente = sb_proto::plugin_client::PluginClient::new(canal);

        assert_eq!(
            cliente
                .info(InfoRequest {})
                .await
                .unwrap()
                .into_inner()
                .name,
            "prueba"
        );
        assert!(cliente.schema(SchemaRequest {}).await.is_ok());
        assert!(cliente.configure(ConfigureRequest::default()).await.is_ok());
        assert!(
            cliente
                .preflight(PreflightRequest {})
                .await
                .unwrap()
                .into_inner()
                .ok
        );

        servidor.abort();
    }

    #[tokio::test]
    async fn un_cliente_de_otra_ca_es_rechazado() {
        // La defensa que justifica el mTLS: otro proceso de la máquina que
        // encuentre el socket no puede hacerse pasar por el núcleo.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();
        let servidor = levantar(&socket, pki.server_config().unwrap()).await;

        let intruso = EphemeralPki::generate().unwrap();
        let resultado = async {
            let canal = connect_control(&socket, intruso.client_config().unwrap()).await?;
            let mut c = sb_proto::plugin_client::PluginClient::new(canal);
            c.info(InfoRequest {}).await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        }
        .await;

        assert!(
            resultado.is_err(),
            "un cliente de otra CA nunca debe ser aceptado"
        );
        servidor.abort();
    }

    #[tokio::test]
    async fn un_handshake_rechazado_no_tumba_el_servidor() {
        // Un intruso que falla el handshake no puede dejar al plugin inservible
        // para el núcleo legítimo: sería una denegación de servicio trivial.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();
        let servidor = levantar(&socket, pki.server_config().unwrap()).await;

        let intruso = EphemeralPki::generate().unwrap();
        let _ = async {
            let canal = connect_control(&socket, intruso.client_config().unwrap()).await?;
            let mut c = sb_proto::plugin_client::PluginClient::new(canal);
            c.info(InfoRequest {}).await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        }
        .await;

        // Y ahora el cliente legítimo debe seguir funcionando.
        let canal = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();
        let mut cliente = sb_proto::plugin_client::PluginClient::new(canal);
        assert_eq!(
            cliente
                .info(InfoRequest {})
                .await
                .unwrap()
                .into_inner()
                .name,
            "prueba",
            "el servidor debe seguir aceptando conexiones legítimas tras un intento fallido"
        );

        servidor.abort();
    }

    #[tokio::test]
    async fn conectar_a_un_socket_inexistente_da_un_error_claro() {
        let pki = EphemeralPki::generate().unwrap();
        let err = connect_control(
            std::path::Path::new("/tmp/no-existe-este-socket-shieldbk.sock"),
            pki.client_config().unwrap(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ControlError::Conexion(_)));
    }

    #[tokio::test]
    async fn el_socket_se_crea_aunque_ya_existiera_un_fichero() {
        // Un plugin que murió sin limpiar deja el socket huérfano. Arrancar
        // debe funcionar igual, no fallar con "address already in use".
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        std::fs::write(&socket, b"restos de una ejecucion anterior").unwrap();

        let pki = EphemeralPki::generate().unwrap();
        let servidor = levantar(&socket, pki.server_config().unwrap()).await;

        let canal = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();
        let mut cliente = sb_proto::plugin_client::PluginClient::new(canal);
        assert!(cliente.info(InfoRequest {}).await.is_ok());
        servidor.abort();
    }

    /// Implementación trivial del servicio Engine, para comprobar que se puede
    /// servir junto al de Plugin por el mismo canal.
    struct EngineDePrueba;

    #[tonic::async_trait]
    impl sb_proto::engine_server::Engine for EngineDePrueba {
        type DumpStream = std::pin::Pin<
            Box<dyn tokio_stream::Stream<Item = Result<sb_proto::Progress, Status>> + Send>,
        >;
        type RestoreStream = Self::DumpStream;

        async fn dump(
            &self,
            _: Request<sb_proto::DumpRequest>,
        ) -> Result<Response<Self::DumpStream>, Status> {
            let s = tokio_stream::iter(vec![Ok(sb_proto::Progress {
                bytes: 42,
                message: "ok".into(),
            })]);
            Ok(Response::new(Box::pin(s) as Self::DumpStream))
        }

        async fn restore(
            &self,
            _: Request<sb_proto::RestoreRequest>,
        ) -> Result<Response<Self::RestoreStream>, Status> {
            let s = tokio_stream::iter(vec![Ok(sb_proto::Progress {
                bytes: 7,
                message: "ok".into(),
            })]);
            Ok(Response::new(Box::pin(s) as Self::RestoreStream))
        }
    }

    #[tokio::test]
    async fn un_plugin_puede_servir_varios_servicios_por_el_mismo_canal() {
        // Un plugin real expone Plugin + Engine, o Plugin + Storage, o los tres.
        // Si solo pudiera exponer uno, la arquitectura no funcionaría.
        use tokio_stream::StreamExt as _;

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();

        let rutas = rutas_de(
            PluginServer::new(PluginDePrueba),
            Some(sb_proto::engine_server::EngineServer::new(EngineDePrueba)),
        );

        let ruta = socket.clone();
        let tls = pki.server_config().unwrap();
        let servidor = tokio::spawn(async move {
            let _ = serve_control_routes(&ruta, tls, rutas).await;
        });
        for _ in 0..200 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let canal = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();

        // El servicio Plugin responde.
        let mut c1 = sb_proto::plugin_client::PluginClient::new(canal.clone());
        assert_eq!(
            c1.info(InfoRequest {}).await.unwrap().into_inner().name,
            "prueba"
        );

        // Y el servicio Engine también, por el MISMO canal.
        let mut c2 = sb_proto::engine_client::EngineClient::new(canal);
        let mut stream = c2
            .dump(sb_proto::DumpRequest {
                data_socket: "/tmp/x.sock".into(),
            })
            .await
            .unwrap()
            .into_inner();
        let primero = stream.next().await.unwrap().unwrap();
        assert_eq!(primero.bytes, 42);

        servidor.abort();
    }

    #[tokio::test]
    async fn un_servicio_no_registrado_devuelve_no_implementado() {
        // Un plugin que solo es motor no expone Storage. Pedirle un Put debe
        // dar un error claro del protocolo, no un cuelgue ni un error de
        // transporte que nadie sepa interpretar.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();

        let rutas = rutas_de(PluginServer::new(PluginDePrueba), None);
        let ruta = socket.clone();
        let tls = pki.server_config().unwrap();
        let servidor = tokio::spawn(async move {
            let _ = serve_control_routes(&ruta, tls, rutas).await;
        });
        for _ in 0..200 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let canal = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();
        let mut c = sb_proto::storage_client::StorageClient::new(canal);
        let err = c
            .list(sb_proto::ListRequest {
                prefix: String::new(),
            })
            .await
            .unwrap_err();

        assert_eq!(
            err.code(),
            tonic::Code::Unimplemented,
            "un servicio ausente debe reportarse como Unimplemented"
        );
        servidor.abort();
    }

    /// Ayudante del test: monta las rutas con Plugin y, opcionalmente, Engine.
    fn rutas_de(
        plugin: PluginServer<PluginDePrueba>,
        engine: Option<sb_proto::engine_server::EngineServer<EngineDePrueba>>,
    ) -> tonic::service::Routes {
        let mut r = tonic::service::Routes::new(plugin);
        if let Some(e) = engine {
            r = r.add_service(e);
        }
        r
    }
}
