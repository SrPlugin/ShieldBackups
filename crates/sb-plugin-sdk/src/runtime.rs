//! Plugin startup: from the stdin envelope to the gRPC server listening.
//!
//! Everything a plugin does when it is born —read the envelope, negotiate the
//! version, set up TLS, bring up the server and announce itself— fits in one
//! call to [`PluginRuntime::serve`].

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sb_proto::PROTOCOL_VERSION;
use sb_proto::notifier_server::{Notifier, NotifierServer};
use sb_proto::plugin_server::{Plugin, PluginServer};
use sb_proto::source_server::{Source, SourceServer};
use sb_proto::storage_server::{Storage, StorageServer};
use sb_transport::{
    Bootstrap, MAGIC, Ready, serve_control_routes_with_shutdown, server_config_from_bundle,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tonic::service::Routes;

use crate::shutdown::{PluginWithShutdown, ShutdownSignal};

/// How long to wait for the control socket to appear before giving up.
/// Announcing before actually listening makes the core fail to connect, so we
/// wait; but we wait **with a bound**, so that a bind failure does not leave the
/// core hanging until its own timeout.
const SOCKET_WAIT: Duration = Duration::from_secs(2);
/// Granularity of the socket polling.
const SOCKET_POLL: Duration = Duration::from_millis(10);
/// Safety cap for the orderly shutdown. **It is not the shutdown mechanism.**
///
/// What guarantees that the `Shutdown` response reaches the core is tonic's
/// `GOAWAY`, which waits for the in-flight streams before closing. This cap only
/// covers the pathological case of a stream that never ends —a hung dump, for
/// instance—, which without it would leave the plugin immortal right after the
/// core asked it to die. It is deliberately generous: if it ever fires,
/// something was already wrong.
const SHUTDOWN_LIMIT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error(
        "no bootstrap envelope was received on stdin; was this binary run by hand instead of from shieldbk?"
    )]
    MissingBootstrap,
    #[error(transparent)]
    Handshake(#[from] sb_transport::HandshakeError),
    #[error(transparent)]
    Pki(#[from] sb_transport::PkiError),
    #[error(transparent)]
    Control(#[from] sb_transport::ControlError),
    /// The server started but the socket never came into existence. Failing
    /// here, with the path in the message, is preferred over announcing anyway
    /// and letting the core see an unexplained "connection refused".
    #[error("the control channel never listened on {path} after {waited_ms} ms")]
    SocketNeverAppeared { path: String, waited_ms: u64 },
    /// The task serving the channel died abnormally (panic or cancellation).
    #[error("the control channel task ended abnormally: {0}")]
    ServerTask(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Capabilities that are announced, derived from the registered services.
fn capabilities(source: bool, storage: bool, notifier: bool) -> Vec<String> {
    let mut v = Vec::new();
    if source {
        v.push("source".to_string());
    }
    if storage {
        v.push("storage".to_string());
    }
    if notifier {
        v.push("notifier".to_string());
    }
    v
}

fn build_ready(
    protocol_version: u32,
    source: bool,
    storage: bool,
    notifier: bool,
    pid: u32,
) -> Ready {
    Ready {
        magic: MAGIC.into(),
        protocol_version,
        capabilities: capabilities(source, storage, notifier),
        pid,
    }
}

/// A service already wrapped in its `*Server`, stored as the operation of
/// adding it to the routes.
///
/// Every `*Server<T>` has a different type and a `Routes` cannot be merged with
/// another `Routes`, so what is stored is not the service but the function that
/// registers it. That keeps `PluginRuntime` with a single type parameter —the
/// plugin's— instead of dragging one per optional capability.
type Registration = Box<dyn FnOnce(Routes) -> Routes + Send>;

/// Plugin startup.
///
/// Register the services the plugin implements and call
/// [`PluginRuntime::serve`]. The capabilities announced to the core **are
/// derived from what was registered**: a plugin cannot declare a source it does
/// not implement, because there is no way to declare it separately.
///
/// ```ignore
/// PluginRuntime::new(MyPlugin::default())
///     .with_source(MySource::default())
///     .serve()
///     .await?;
/// ```
pub struct PluginRuntime<P> {
    plugin: P,
    source: Option<Registration>,
    storage: Option<Registration>,
    notifier: Option<Registration>,
}

impl<P: Plugin> PluginRuntime<P> {
    /// A plugin that only implements the `Plugin` service, mandatory for all of
    /// them.
    #[must_use]
    pub fn new(plugin: P) -> Self {
        Self {
            plugin,
            source: None,
            storage: None,
            notifier: None,
        }
    }

    /// Registers the dump/restore source. Announces the `source` capability.
    ///
    /// Registering twice keeps the last one: two sources on the same channel
    /// would stomp on each other's routes, and an `Option` makes that
    /// impossible.
    #[must_use]
    pub fn with_source<T: Source>(mut self, source: T) -> Self {
        self.source = Some(Box::new(move |r: Routes| {
            r.add_service(SourceServer::new(source))
        }));
        self
    }

    /// Registers the storage destination. Announces the `storage` capability.
    #[must_use]
    pub fn with_storage<S: Storage>(mut self, storage: S) -> Self {
        self.storage = Some(Box::new(move |r: Routes| {
            r.add_service(StorageServer::new(storage))
        }));
        self
    }

    /// Registers the notifier. Announces the `notifier` capability.
    #[must_use]
    pub fn with_notifier<N: Notifier>(mut self, notifier: N) -> Self {
        self.notifier = Some(Box::new(move |r: Routes| {
            r.add_service(NotifierServer::new(notifier))
        }));
        self
    }

    /// Runs the plugin until the core closes it.
    ///
    /// It ends when the core calls `Shutdown` —the SDK intercepts it, so the
    /// plugin does not have to do anything for its process to die— or when the
    /// control channel goes down on its own.
    ///
    /// Logging goes to **stderr**: stdout is reserved for the handshake line,
    /// and anything else there breaks startup.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::MissingBootstrap`] if stdin closes without an
    /// envelope, [`SdkError::Handshake`] if the envelope is invalid or there is
    /// no protocol version in common, [`SdkError::Pki`] if the TLS material
    /// cannot be loaded, [`SdkError::SocketNeverAppeared`] if the channel never
    /// listens, and [`SdkError::Control`] or [`SdkError::Io`] if the server
    /// fails.
    pub async fn serve(self) -> Result<(), SdkError> {
        init_logging();

        let bootstrap = read_bootstrap().await?;
        let version = bootstrap.negotiate(&[PROTOCOL_VERSION])?;
        let tls = server_config_from_bundle(&bootstrap.tls)?;

        let source = self.source.is_some();
        let storage = self.storage.is_some();
        let notifier = self.notifier.is_some();

        // The Plugin service goes wrapped: `Shutdown` is first served by the
        // plugin's implementation and then ends the process, without the plugin
        // having to cooperate and without it being able to forget.
        let stop = ShutdownSignal::default();
        let mut routes = Routes::new(PluginServer::new(PluginWithShutdown::new(
            self.plugin,
            stop.clone(),
        )));
        if let Some(register) = self.source {
            routes = register(routes);
        }
        if let Some(register) = self.storage {
            routes = register(routes);
        }
        if let Some(register) = self.notifier {
            routes = register(routes);
        }

        // The server's stop goes through its own channel: `stop` requests it and
        // this `oneshot` relays it to tonic, which answers with a `GOAWAY`.
        let socket = PathBuf::from(&bootstrap.control_socket);
        let server_socket = socket.clone();
        let (request_stop, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let mut server = tokio::spawn(async move {
            serve_control_routes_with_shutdown(&server_socket, tls, routes, async move {
                let _ = stop_rx.await;
            })
            .await
        });

        // Announcing before actually listening is a lost race: the core would
        // connect against a socket that does not exist yet.
        wait_for_socket(&socket, &mut server).await?;

        tracing::debug!(
            protocol = version,
            socket = %socket.display(),
            source,
            storage,
            notifier,
            "control channel listening; announcing ready"
        );
        announce(&build_ready(
            version,
            source,
            storage,
            notifier,
            std::process::id(),
        ))?;

        // We live until one of two things happens: the channel goes down by
        // itself —and then its error is the plugin's result— or the core asks
        // for the shutdown. The `return` in the first branch avoids having to
        // touch `server` again inside the `select!`, which still has it
        // borrowed.
        tokio::select! {
            result = &mut server => {
                return match result {
                    Ok(result) => Ok(result?),
                    Err(e) => Err(SdkError::ServerTask(e.to_string())),
                };
            }
            () = stop.wait() => {}
        }

        tracing::info!("shutdown requested by the core; the plugin ends");
        // From here on tonic is in charge: it sends `GOAWAY`, stops accepting
        // connections and waits for the in-flight streams, so that the response
        // to the `Shutdown` itself leaves through the socket before the channel
        // dies. There is no time budget to squeeze: we wait until it really
        // finishes.
        let _ = request_stop.send(());
        match tokio::time::timeout(SHUTDOWN_LIMIT, &mut server).await {
            Ok(Ok(result)) => Ok(result?),
            Ok(Err(e)) => Err(SdkError::ServerTask(e.to_string())),
            Err(_) => {
                tracing::warn!(
                    limit_s = SHUTDOWN_LIMIT.as_secs(),
                    "the control channel did not close within the safety cap; aborting"
                );
                server.abort();
                Ok(())
            }
        }
    }
}

/// Initializes logging **to stderr**.
///
/// `try_init` instead of `init` on purpose: `init` panics if there is already a
/// global subscriber, which would prevent using a plugin from a test that has
/// already initialized its own.
fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    // The writer is set explicitly: the default is stdout, and only the
    // handshake line may go there.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Reads the bootstrap envelope: a single JSON line on stdin.
async fn read_bootstrap() -> Result<Bootstrap, SdkError> {
    let mut input = BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    if input.read_line(&mut line).await? == 0 || line.trim().is_empty() {
        return Err(SdkError::MissingBootstrap);
    }
    // `from_line` already validates the magic and the envelope version.
    Ok(Bootstrap::from_line(&line)?)
}

/// Waits, with a bound, for the control socket to exist.
///
/// It also keeps an eye on the server task: if it died while binding, *its*
/// error —which says what happened— is propagated instead of a timeout that only
/// says that nothing happened.
async fn wait_for_socket(
    socket: &Path,
    server: &mut tokio::task::JoinHandle<Result<(), sb_transport::ControlError>>,
) -> Result<(), SdkError> {
    let deadline = tokio::time::Instant::now() + SOCKET_WAIT;
    loop {
        if socket.exists() {
            return Ok(());
        }
        if server.is_finished() {
            return match server.await {
                Ok(result) => {
                    result?;
                    // Finished without error and without a socket: there is
                    // nothing to serve.
                    Err(SdkError::SocketNeverAppeared {
                        path: socket.display().to_string(),
                        waited_ms: u64::try_from(SOCKET_WAIT.as_millis()).unwrap_or(u64::MAX),
                    })
                }
                Err(e) => Err(SdkError::ServerTask(e.to_string())),
            };
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(SdkError::SocketNeverAppeared {
                path: socket.display().to_string(),
                waited_ms: u64::try_from(SOCKET_WAIT.as_millis()).unwrap_or(u64::MAX),
            });
        }
        tokio::time::sleep(SOCKET_POLL).await;
    }
}

/// Writes the `Ready` line on stdout and flushes it.
///
/// Synchronous on purpose: it is a single line, exactly once, and the explicit
/// `flush` matters more than the asynchrony. Without it, the core would wait for
/// an announcement asleep in the buffer.
fn announce(ready: &Ready) -> Result<(), SdkError> {
    let line = ready.to_line()?;
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}")?;
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plugin_with_no_extra_services_only_announces_the_basics() {
        assert!(capabilities(false, false, false).is_empty());
    }

    #[test]
    fn a_source_announces_source() {
        assert_eq!(capabilities(true, false, false), vec!["source"]);
    }

    #[test]
    fn a_storage_announces_storage() {
        assert_eq!(capabilities(false, true, false), vec!["storage"]);
    }

    #[test]
    fn a_plugin_that_does_both_announces_both() {
        assert_eq!(capabilities(true, true, false), vec!["source", "storage"]);
    }

    #[test]
    fn a_notifier_announces_notifier() {
        assert_eq!(capabilities(false, false, true), vec!["notifier"]);
    }

    #[test]
    fn the_ready_line_carries_the_magic_and_the_negotiated_version() {
        let r = build_ready(1, true, false, false, 4242);
        assert_eq!(r.magic, sb_transport::MAGIC);
        assert_eq!(r.protocol_version, 1);
        assert_eq!(r.capabilities, vec!["source"]);
        assert_eq!(r.pid, 4242);
    }

    #[test]
    fn the_ready_serializes_into_a_single_line() {
        // The core reads it with a read_line: if it carried newlines it would be
        // cut short.
        let line = build_ready(1, true, true, true, 1).to_line().unwrap();
        assert!(!line.contains('\n'));
        assert!(sb_transport::Ready::from_line(&line).is_ok());
    }

    #[test]
    fn the_declared_capabilities_match_the_registered_services() {
        // The reason for deriving them instead of passing them by hand: a plugin
        // cannot announce a source it does not implement.
        for bits in 0..8_u8 {
            let (source, storage, notifier) = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0);
            let r = build_ready(1, source, storage, notifier, 1);
            assert_eq!(r.capabilities.contains(&"source".to_string()), source);
            assert_eq!(r.capabilities.contains(&"storage".to_string()), storage);
            assert_eq!(r.capabilities.contains(&"notifier".to_string()), notifier);
        }
    }
}
