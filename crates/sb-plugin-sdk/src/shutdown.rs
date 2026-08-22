//! Making `Shutdown` end the process, without the plugin having to remember.
//!
//! The core calls `Shutdown` expecting an orderly close. A plugin has no way to
//! terminate itself from the body of an RPC —the one that decides when the
//! process ends is [`crate::PluginRuntime::serve`]—, so the SDK **intercepts**
//! the call: it wraps the plugin's `Plugin` service, delegates to its
//! implementation and, no matter what happens, fires the stop signal.
//!
//! Intercepting was chosen over handing the plugin a handle to keep and use: a
//! handle can be forgotten, and forgetting it brings back the original failure
//! —a process that outlives its own `Shutdown` until someone kills it—. Here
//! there is nothing to forget, and no way to switch it off.

use std::sync::Arc;

use sb_proto::plugin_server::Plugin;
use sb_proto::{
    ConfigureRequest, ConfigureResponse, InfoRequest, InfoResponse, PreflightRequest,
    PreflightResponse, SchemaRequest, SchemaResponse, ShutdownRequest, ShutdownResponse,
};
use tokio::sync::Notify;
use tonic::{Request, Response, Status};

/// The "time to stop" notice, from the `Shutdown` interception to `serve`.
#[derive(Clone, Default)]
pub(crate) struct ShutdownSignal(Arc<Notify>);

impl ShutdownSignal {
    /// Requests the stop. Idempotent and non-blocking.
    fn fire(&self) {
        // `notify_one` keeps the permit if nobody is waiting yet, so the signal
        // is not lost even if `serve` has not reached its `select` yet.
        self.0.notify_one();
    }

    /// Resolves once somebody has requested the stop.
    pub(crate) async fn wait(&self) {
        self.0.notified().await;
    }
}

/// The plugin's `Plugin` service, with `Shutdown` intercepted.
///
/// The other four RPCs pass straight through: the wrapper adds nothing to
/// `Info`, `Schema`, `Configure` or `Preflight`, and simply delegates.
pub(crate) struct PluginWithShutdown<P> {
    inner: P,
    signal: ShutdownSignal,
}

impl<P> PluginWithShutdown<P> {
    pub(crate) fn new(inner: P, signal: ShutdownSignal) -> Self {
        Self { inner, signal }
    }
}

#[tonic::async_trait]
impl<P: Plugin> Plugin for PluginWithShutdown<P> {
    async fn info(&self, p: Request<InfoRequest>) -> Result<Response<InfoResponse>, Status> {
        self.inner.info(p).await
    }

    async fn schema(&self, p: Request<SchemaRequest>) -> Result<Response<SchemaResponse>, Status> {
        self.inner.schema(p).await
    }

    async fn configure(
        &self,
        p: Request<ConfigureRequest>,
    ) -> Result<Response<ConfigureResponse>, Status> {
        self.inner.configure(p).await
    }

    async fn preflight(
        &self,
        p: Request<PreflightRequest>,
    ) -> Result<Response<PreflightResponse>, Status> {
        self.inner.preflight(p).await
    }

    /// Delegates and **then** requests the stop.
    ///
    /// The order matters: first the plugin's own `Shutdown` runs —closing
    /// connections, flushing buffers—, and only then is termination requested.
    /// It is also requested **even if the implementation returns an error**: the
    /// contract the core sees is "calling Shutdown ends the process", and a
    /// plugin that complained while closing cannot become a plugin that does not
    /// close. The error is still returned to the core, which thus learns that
    /// the shutdown was not clean.
    async fn shutdown(
        &self,
        p: Request<ShutdownRequest>,
    ) -> Result<Response<ShutdownResponse>, Status> {
        let result = self.inner.shutdown(p).await;
        if let Err(e) = &result {
            tracing::warn!(error = %e, "the plugin failed to close; terminating anyway");
        }
        self.signal.fire();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// A plugin that records whether it was called and can fake a close failure.
    #[derive(Default)]
    struct Spy {
        closed: AtomicBool,
        fails_on_close: bool,
    }

    #[tonic::async_trait]
    impl Plugin for Spy {
        async fn info(&self, _: Request<InfoRequest>) -> Result<Response<InfoResponse>, Status> {
            Ok(Response::new(InfoResponse {
                name: "spy".into(),
                ..InfoResponse::default()
            }))
        }
        async fn schema(
            &self,
            _: Request<SchemaRequest>,
        ) -> Result<Response<SchemaResponse>, Status> {
            Ok(Response::new(SchemaResponse::default()))
        }
        async fn configure(
            &self,
            _: Request<ConfigureRequest>,
        ) -> Result<Response<ConfigureResponse>, Status> {
            Ok(Response::new(ConfigureResponse::default()))
        }
        async fn preflight(
            &self,
            _: Request<PreflightRequest>,
        ) -> Result<Response<PreflightResponse>, Status> {
            Ok(Response::new(PreflightResponse::default()))
        }
        async fn shutdown(
            &self,
            _: Request<ShutdownRequest>,
        ) -> Result<Response<ShutdownResponse>, Status> {
            self.closed.store(true, Ordering::SeqCst);
            if self.fails_on_close {
                return Err(Status::internal("could not close"));
            }
            Ok(Response::new(ShutdownResponse::default()))
        }
    }

    /// `true` if the signal is already fired, without hanging if it is not.
    async fn fired(signal: &ShutdownSignal) -> bool {
        tokio::time::timeout(Duration::from_millis(100), signal.wait())
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn shutdown_fires_the_signal_even_if_the_plugin_does_nothing() {
        // The smoke plugin does nothing in its `shutdown` and the process must
        // still terminate: that is the whole reason for intercepting.
        let signal = ShutdownSignal::default();
        let wrapped = PluginWithShutdown::new(Spy::default(), signal.clone());

        assert!(!fired(&signal).await, "it must not be fired to begin with");
        wrapped
            .shutdown(Request::new(ShutdownRequest {}))
            .await
            .unwrap();
        assert!(fired(&signal).await);
    }

    #[tokio::test]
    async fn the_plugin_shutdown_runs_before_stopping() {
        let signal = ShutdownSignal::default();
        let wrapped = PluginWithShutdown::new(Spy::default(), signal.clone());
        wrapped
            .shutdown(Request::new(ShutdownRequest {}))
            .await
            .unwrap();
        assert!(
            wrapped.inner.closed.load(Ordering::SeqCst),
            "the plugin's own close must run before termination is requested"
        );
    }

    #[tokio::test]
    async fn a_plugin_that_fails_to_close_terminates_anyway() {
        let signal = ShutdownSignal::default();
        let wrapped = PluginWithShutdown::new(
            Spy {
                fails_on_close: true,
                ..Spy::default()
            },
            signal.clone(),
        );
        let e = wrapped
            .shutdown(Request::new(ShutdownRequest {}))
            .await
            .unwrap_err();
        // The core learns that the shutdown was not clean...
        assert_eq!(e.code(), tonic::Code::Internal);
        // ...and the process closes all the same.
        assert!(fired(&signal).await);
    }

    #[tokio::test]
    async fn the_other_rpcs_do_not_stop_the_plugin() {
        let signal = ShutdownSignal::default();
        let wrapped = PluginWithShutdown::new(Spy::default(), signal.clone());

        assert_eq!(
            wrapped
                .info(Request::new(InfoRequest {}))
                .await
                .unwrap()
                .into_inner()
                .name,
            "spy"
        );
        wrapped
            .schema(Request::new(SchemaRequest {}))
            .await
            .unwrap();
        wrapped
            .configure(Request::new(ConfigureRequest::default()))
            .await
            .unwrap();
        wrapped
            .preflight(Request::new(PreflightRequest {}))
            .await
            .unwrap();

        assert!(!fired(&signal).await, "only Shutdown may stop it");
    }
}
