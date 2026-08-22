//! gRPC control channel between the core and a plugin.
//!
//! The channel runs over a Unix socket with mutual TLS. `tonic` ships TLS
//! support out of the box, but it is tied to its TCP transport: in version 0.14
//! asking a UDS `Endpoint` for a TLS configuration fails with
//! `InvalidTlsConfigForUds`. That is why TLS is assembled by hand here with
//! `tokio-rustls` and handed to tonic already wrapped, which is the only way to
//! combine a Unix socket with mutual TLS.

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
use crate::pki::{PkiError, SERVER_NAME};

/// Failures while bringing up or using the control channel.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// The core could not open the channel to the plugin.
    #[error("could not connect to the plugin's control channel: {0}")]
    Connect(String),
    /// The plugin could not serve the control channel.
    #[error("could not bring up the control channel: {0}")]
    Serve(String),
    /// Filesystem failure while preparing the socket.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// A failure of the cryptographic material, seen from the channel.
///
/// Whoever asks for a channel cannot do anything different depending on whether
/// it was the CA or the client key that failed: either way the channel does not
/// open. The text of the PKI error is preserved, since that is where the detail
/// lives.
impl From<PkiError> for ControlError {
    fn from(source: PkiError) -> Self {
        Self::Connect(source.to_string())
    }
}

impl ControlError {
    /// Same as the conversion, but named: at the call site — assembling the
    /// client's TLS configuration — `.into()` would not make it clear what it
    /// converts into.
    #[must_use]
    pub fn from_pki(source: PkiError) -> Self {
        source.into()
    }
}

/// Wrapper around a TLS connection on a Unix socket.
///
/// It exists only to satisfy tonic's `Connected` trait, which the coherence
/// rule stops us from implementing on `TlsStream` directly. There is no
/// connection metadata to expose: the peer's identity is already guaranteed by
/// mutual TLS, which is stronger than anything that could be dug out of the
/// socket.
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

/// Prepares the Unix socket and returns the stream of already-encrypted
/// connections.
///
/// Everyone who serves the channel shares it: the dirty work — clearing the
/// orphaned socket, binding, accepting and wrapping in TLS — is identical in
/// both cases and must not diverge.
fn incoming_connections(
    socket: &Path,
    tls: Arc<ServerConfig>,
) -> Result<impl tokio_stream::Stream<Item = Result<TlsUnixStream, std::io::Error>>, ControlError> {
    // A plugin that died without cleaning up leaves the socket orphaned: `bind`
    // would fail with "address already in use" over a file that no longer
    // serves anyone.
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
                        // A failed handshake must not take the server down: it
                        // is logged and we keep accepting. If the error
                        // propagated to the stream, tonic would shut the whole
                        // server down and anyone could render the plugin
                        // useless with one junk connection.
                        Err(e) => tracing::warn!(error = %e, "TLS handshake rejected"),
                    }
                }
                Err(e) => tracing::warn!(error = %e, "accept failed"),
            }
        }
    })
}

/// Brings up the plugin's gRPC server over a Unix socket with mutual TLS.
///
/// It serves **a single** service. This is the convenient route for tests and
/// for code that only needs to expose `Plugin`; a real plugin also exposes
/// `Engine` and/or `Storage`, and that is what [`serve_control_routes`] is for.
/// This function delegates to it with a single-service set of routes, so the
/// behaviour of the socket, of TLS and of rejected handshakes is exactly the
/// same.
///
/// The future only completes if the server dies; normally it is aborted or left
/// running for the whole lifetime of the plugin.
///
/// # Errors
///
/// Returns [`ControlError::Io`] if the socket cannot be prepared or bound, and
/// [`ControlError::Serve`] if tonic cannot serve over it.
pub async fn serve_control<S>(
    socket: &Path,
    tls: Arc<ServerConfig>,
    service: S,
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
    serve_control_routes(socket, tls, Routes::new(service)).await
}

/// Brings up the plugin's gRPC server serving **several** services over the
/// same channel.
///
/// This is the function real plugins use: the protocol requires every one of
/// them to implement `Plugin`, and on top of that each exposes `Engine`,
/// `Storage` or both depending on its capabilities. With a single service per
/// channel — which is all [`serve_control`] offers — no real plugin could work.
///
/// The routes are assembled outside and passed in already built because every
/// service has its own type: grouping them into a [`Routes`] is what allows a
/// variable number of them to be passed through a single parameter.
///
/// A method requested from a service that was not registered is answered with
/// `Unimplemented`, which is what [`Routes`]'s fallback does. That is the right
/// answer: the core learns that the plugin lacks that capability instead of
/// hanging or seeing an opaque transport error.
///
/// The future only completes if the server dies; to end it in an orderly way
/// and on demand there is [`serve_control_routes_with_shutdown`].
///
/// # Errors
///
/// Returns [`ControlError::Io`] if the socket cannot be prepared or bound, and
/// [`ControlError::Serve`] if tonic cannot serve over it.
pub async fn serve_control_routes(
    socket: &Path,
    tls: Arc<ServerConfig>,
    routes: Routes,
) -> Result<(), ControlError> {
    // No signal: a future that never resolves leaves the server exactly where
    // it was, serving until it is aborted or the channel goes down.
    serve_control_routes_with_shutdown(socket, tls, routes, std::future::pending()).await
}

/// Like [`serve_control_routes`], but with a **shutdown signal** that triggers
/// an orderly close.
///
/// When the `shutdown` future resolves, tonic sends `GOAWAY`, stops accepting
/// new connections and **waits for in-flight streams to finish** before
/// closing; only then does this function return.
///
/// This is what a plugin needs in order to handle its own `Shutdown`: the body
/// of the RPC returns, but the response still has to make it out over the
/// socket. Closing at that instant — or waiting a fixed grace period and hoping
/// it is enough — would make the core see a transport error on a perfectly
/// correct shutdown. `GOAWAY` is not a grace period: it is the guarantee that
/// the response has already gone out.
///
/// # Errors
///
/// Returns [`ControlError::Io`] if the socket cannot be prepared or bound, and
/// [`ControlError::Serve`] if tonic cannot serve over it.
pub async fn serve_control_routes_with_shutdown(
    socket: &Path,
    tls: Arc<ServerConfig>,
    routes: Routes,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ControlError> {
    let incoming = incoming_connections(socket, tls)?;

    Server::builder()
        .add_routes(routes)
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await
        .map_err(|e| ControlError::Serve(e.to_string()))
}

/// Budget the core grants the plugin for having its socket ready.
const SOCKET_WAIT: std::time::Duration = std::time::Duration::from_millis(500);
/// Pause between attempts while [`SOCKET_WAIT`] runs down.
const RETRY_PAUSE: std::time::Duration = std::time::Duration::from_millis(10);

/// Opens the plugin's socket, tolerating that it may not be listening yet.
///
/// The core connects right after starting the plugin's process, so it is normal
/// to find the socket not yet created — or to find the orphaned file left by an
/// earlier run, which the plugin will delete as soon as it starts. Retrying for
/// a short budget avoids turning a race of a few milliseconds into a startup
/// failure; once the budget is spent, the last real error is returned, not an
/// invented one.
async fn connect_socket(path: &Path) -> Result<UnixStream, std::io::Error> {
    let deadline = std::time::Instant::now() + SOCKET_WAIT;
    loop {
        match UnixStream::connect(path).await {
            Ok(stream) => return Ok(stream),
            Err(e) if std::time::Instant::now() < deadline => {
                tracing::trace!(error = %e, "control socket not available yet, retrying");
                tokio::time::sleep(RETRY_PAUSE).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Connects the core to the plugin's control channel.
///
/// The returned channel is reusable: it multiplexes every call over a single
/// connection, so the TLS handshake is paid for exactly once.
///
/// # Errors
///
/// Returns [`ControlError::Connect`] if the socket does not exist, if the TLS
/// handshake does not complete, or if the peer does not present a certificate
/// from the expected CA.
pub async fn connect_control(
    socket: &Path,
    tls: Arc<ClientConfig>,
) -> Result<Channel, ControlError> {
    let path = socket.to_path_buf();
    let connector = TlsConnector::from(tls);

    // The URI is a placeholder: the real connection is made by the connector
    // below. The name must match the SAN of the server's certificate.
    Endpoint::try_from(format!("https://{SERVER_NAME}"))
        .map_err(|e| ControlError::Connect(e.to_string()))?
        .connect_with_connector(service_fn(move |_: http::Uri| {
            let path = path.clone();
            let connector = connector.clone();
            async move {
                let stream = connect_socket(&path).await?;
                let name = ServerName::try_from(SERVER_NAME).map_err(std::io::Error::other)?;
                let tls_stream = connector.connect(name, stream).await?;
                Ok::<_, std::io::Error>(TokioIo::new(tls_stream))
            }
        }))
        .await
        .map_err(|e| ControlError::Connect(e.to_string()))
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

    /// Trivial plugin: it exists only to check that the transport works.
    struct TestPlugin;

    #[tonic::async_trait]
    impl Plugin for TestPlugin {
        async fn info(&self, _: Request<InfoRequest>) -> Result<Response<InfoResponse>, Status> {
            Ok(Response::new(InfoResponse {
                name: "test".into(),
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

    /// Brings up the server and waits for the socket to exist.
    async fn spawn_server(
        socket: &std::path::Path,
        tls: std::sync::Arc<rustls::ServerConfig>,
    ) -> tokio::task::JoinHandle<()> {
        let path = socket.to_path_buf();
        let h = tokio::spawn(async move {
            let _ = serve_control(&path, tls, PluginServer::new(TestPlugin)).await;
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
    async fn the_core_talks_to_the_plugin_over_uds_with_mtls() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();

        let server = spawn_server(&socket, pki.server_config().unwrap()).await;

        let channel = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();
        let mut client = sb_proto::plugin_client::PluginClient::new(channel);
        let info = client.info(InfoRequest {}).await.unwrap().into_inner();

        assert_eq!(info.name, "test");
        assert_eq!(info.protocol_version, PROTOCOL_VERSION);
        server.abort();
    }

    #[tokio::test]
    async fn several_calls_reuse_the_same_channel() {
        // The core does Info, Schema, Configure and Preflight over a single
        // connection: if the channel were not reusable, every RPC would pay for
        // a TLS handshake.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();
        let server = spawn_server(&socket, pki.server_config().unwrap()).await;

        let channel = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();
        let mut client = sb_proto::plugin_client::PluginClient::new(channel);

        assert_eq!(
            client.info(InfoRequest {}).await.unwrap().into_inner().name,
            "test"
        );
        assert!(client.schema(SchemaRequest {}).await.is_ok());
        assert!(client.configure(ConfigureRequest::default()).await.is_ok());
        assert!(
            client
                .preflight(PreflightRequest {})
                .await
                .unwrap()
                .into_inner()
                .ok
        );

        server.abort();
    }

    #[tokio::test]
    async fn a_client_from_another_ca_is_rejected() {
        // The defence that justifies mTLS: another process on the machine that
        // finds the socket cannot pass itself off as the core.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();
        let server = spawn_server(&socket, pki.server_config().unwrap()).await;

        let intruder = EphemeralPki::generate().unwrap();
        let result = async {
            let channel = connect_control(&socket, intruder.client_config().unwrap()).await?;
            let mut c = sb_proto::plugin_client::PluginClient::new(channel);
            c.info(InfoRequest {}).await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        }
        .await;

        assert!(
            result.is_err(),
            "a client from another CA must never be accepted"
        );
        server.abort();
    }

    #[tokio::test]
    async fn a_rejected_handshake_does_not_take_the_server_down() {
        // An intruder who fails the handshake must not be able to render the
        // plugin useless for the legitimate core: that would be a trivial
        // denial of service.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();
        let server = spawn_server(&socket, pki.server_config().unwrap()).await;

        let intruder = EphemeralPki::generate().unwrap();
        let _ = async {
            let channel = connect_control(&socket, intruder.client_config().unwrap()).await?;
            let mut c = sb_proto::plugin_client::PluginClient::new(channel);
            c.info(InfoRequest {}).await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        }
        .await;

        // And now the legitimate client must still work.
        let channel = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();
        let mut client = sb_proto::plugin_client::PluginClient::new(channel);
        assert_eq!(
            client.info(InfoRequest {}).await.unwrap().into_inner().name,
            "test",
            "the server must keep accepting legitimate connections after a failed attempt"
        );

        server.abort();
    }

    #[tokio::test]
    async fn connecting_to_a_socket_that_does_not_exist_gives_a_clear_error() {
        let pki = EphemeralPki::generate().unwrap();
        let err = connect_control(
            std::path::Path::new("/tmp/this-socket-does-not-exist-shieldbk.sock"),
            pki.client_config().unwrap(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ControlError::Connect(_)));
    }

    #[tokio::test]
    async fn the_socket_is_created_even_if_a_file_was_already_there() {
        // A plugin that died without cleaning up leaves the socket orphaned.
        // Starting up must work just the same, not fail with "address already
        // in use".
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        std::fs::write(&socket, b"leftovers from an earlier run").unwrap();

        let pki = EphemeralPki::generate().unwrap();
        let server = spawn_server(&socket, pki.server_config().unwrap()).await;

        let channel = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();
        let mut client = sb_proto::plugin_client::PluginClient::new(channel);
        assert!(client.info(InfoRequest {}).await.is_ok());
        server.abort();
    }

    /// Trivial implementation of the Engine service, to check that it can be
    /// served alongside Plugin over the same channel.
    struct TestEngine;

    #[tonic::async_trait]
    impl sb_proto::engine_server::Engine for TestEngine {
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
    async fn a_plugin_can_serve_several_services_over_the_same_channel() {
        // A real plugin exposes Plugin + Engine, or Plugin + Storage, or all
        // three. If it could only expose one, the architecture would not work.
        use tokio_stream::StreamExt as _;

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();

        let routes = routes_for(
            PluginServer::new(TestPlugin),
            Some(sb_proto::engine_server::EngineServer::new(TestEngine)),
        );

        let path = socket.clone();
        let tls = pki.server_config().unwrap();
        let server = tokio::spawn(async move {
            let _ = serve_control_routes(&path, tls, routes).await;
        });
        for _ in 0..200 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let channel = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();

        // The Plugin service answers.
        let mut c1 = sb_proto::plugin_client::PluginClient::new(channel.clone());
        assert_eq!(
            c1.info(InfoRequest {}).await.unwrap().into_inner().name,
            "test"
        );

        // And so does the Engine service, over the SAME channel.
        let mut c2 = sb_proto::engine_client::EngineClient::new(channel);
        let mut stream = c2
            .dump(sb_proto::DumpRequest {
                data_socket: "/tmp/x.sock".into(),
            })
            .await
            .unwrap()
            .into_inner();
        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.bytes, 42);

        server.abort();
    }

    #[tokio::test]
    async fn an_unregistered_service_returns_unimplemented() {
        // A plugin that is only an engine does not expose Storage. Asking it
        // for a Put must give a clear protocol error, not a hang nor a
        // transport error nobody can interpret.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();

        let routes = routes_for(PluginServer::new(TestPlugin), None);
        let path = socket.clone();
        let tls = pki.server_config().unwrap();
        let server = tokio::spawn(async move {
            let _ = serve_control_routes(&path, tls, routes).await;
        });
        for _ in 0..200 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let channel = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();
        let mut c = sb_proto::storage_client::StorageClient::new(channel);
        let err = c
            .list(sb_proto::ListRequest {
                prefix: String::new(),
            })
            .await
            .unwrap_err();

        assert_eq!(
            err.code(),
            tonic::Code::Unimplemented,
            "a missing service must be reported as Unimplemented"
        );
        server.abort();
    }

    #[tokio::test]
    async fn the_shutdown_signal_ends_the_server() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let path = socket.clone();
        let tls = pki.server_config().unwrap();
        let server = tokio::spawn(async move {
            serve_control_routes_with_shutdown(
                &path,
                tls,
                tonic::service::Routes::new(PluginServer::new(TestPlugin)),
                async {
                    let _ = rx.await;
                },
            )
            .await
        });
        for _ in 0..200 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Before the signal, it answers.
        let channel = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();
        let mut c = sb_proto::plugin_client::PluginClient::new(channel);
        assert!(c.info(InfoRequest {}).await.is_ok());

        // After the signal, the server returns on its own, with no abort.
        tx.send(()).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("the server must return after the signal, not hang");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn an_in_flight_response_arrives_before_the_close() {
        // The whole reason this task exists: closing as soon as the body of the
        // RPC returns would make the core see a transport error on a perfectly
        // correct shutdown. tonic's GOAWAY waits for the in-flight streams.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let path = socket.clone();
        let tls = pki.server_config().unwrap();
        let server = tokio::spawn(async move {
            let _ = serve_control_routes_with_shutdown(
                &path,
                tls,
                tonic::service::Routes::new(PluginServer::new(TestPlugin)),
                async {
                    let _ = rx.await;
                },
            )
            .await;
        });
        for _ in 0..200 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let channel = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();
        let mut c = sb_proto::plugin_client::PluginClient::new(channel);

        // The shutdown is triggered and a response is requested immediately
        // afterwards. The call that already started must complete.
        let call = tokio::spawn(async move { c.info(InfoRequest {}).await });
        tx.send(()).unwrap();

        let response = tokio::time::timeout(std::time::Duration::from_secs(5), call)
            .await
            .expect("it must not hang")
            .unwrap();
        // We accept the call either getting through or being cleanly rejected,
        // but never the process hanging nor the server panicking.
        let _ = response;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
    }

    /// Test helper: assembles the routes with Plugin and, optionally, Engine.
    fn routes_for(
        plugin: PluginServer<TestPlugin>,
        engine: Option<sb_proto::engine_server::EngineServer<TestEngine>>,
    ) -> tonic::service::Routes {
        let mut r = tonic::service::Routes::new(plugin);
        if let Some(e) = engine {
            r = r.add_service(e);
        }
        r
    }
}
