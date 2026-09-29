//! The five RPCs every plugin implements, plus the `Notifier` service.

use sb_plugin_sdk::sb_proto::notifier_server::Notifier;
use sb_plugin_sdk::sb_proto::plugin_server::Plugin;
use sb_plugin_sdk::sb_proto::{
    Capability, Check, ConfigureRequest, ConfigureResponse, InfoRequest, InfoResponse,
    NotifyRequest, NotifyResponse, PROTOCOL_VERSION, PreflightRequest, PreflightResponse,
    SchemaRequest, SchemaResponse, ShutdownRequest, ShutdownResponse,
};
use sb_plugin_sdk::tonic::{Request, Response, Status};

use crate::config::{self, State, WebhookConfig};
use crate::send;

/// Name the plugin identifies itself with to the core.
pub const NAME: &str = "webhook";

pub struct WebhookPlugin {
    state: State,
}

impl WebhookPlugin {
    #[must_use]
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[sb_plugin_sdk::tonic::async_trait]
impl Plugin for WebhookPlugin {
    async fn info(&self, _: Request<InfoRequest>) -> Result<Response<InfoResponse>, Status> {
        Ok(Response::new(InfoResponse {
            name: NAME.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            protocol_version: PROTOCOL_VERSION,
            capabilities: vec![Capability::Notifier as i32],
        }))
    }

    async fn schema(&self, _: Request<SchemaRequest>) -> Result<Response<SchemaResponse>, Status> {
        Ok(Response::new(SchemaResponse {
            fields: config::schema(),
        }))
    }

    async fn configure(
        &self,
        request: Request<ConfigureRequest>,
    ) -> Result<Response<ConfigureResponse>, Status> {
        let config = WebhookConfig::from_values(&request.into_inner().config)?;
        // The SDK's subscriber bridges the `log` facade into `tracing`, and at
        // trace level the HTTP client logs the request path -- where the token
        // lives. This plugin's own logging goes through `tracing` and is not
        // affected. It is set here, not in `main`, because the subscriber is
        // installed by `serve` and would overwrite an earlier setting.
        log::set_max_level(log::LevelFilter::Off);
        // Never the URL: only what is safe to read in a log.
        tracing::info!(
            format = ?config.format,
            timeout_secs = config.timeout.as_secs(),
            "webhook plugin configured"
        );
        self.state.store(config);
        Ok(Response::new(ConfigureResponse {}))
    }

    async fn preflight(
        &self,
        _: Request<PreflightRequest>,
    ) -> Result<Response<PreflightResponse>, Status> {
        // Preflight sends **nothing**: a `doctor` run must not page anyone or
        // trip a dead-man's-switch check. Reaching the endpoint is only proven
        // by a real notification; what can be said here is that the plugin is
        // configured, and the URL was validated when it was accepted.
        let check = if self.state.is_configured() {
            Check {
                name: "url".into(),
                ok: true,
                detail: "the URL scheme is acceptable (nothing was sent)".into(),
                remediation: String::new(),
            }
        } else {
            Check {
                name: "configuration".into(),
                ok: false,
                detail: "the plugin has not received its configuration yet".into(),
                remediation: format!(
                    "call Configure with the `{}` field before Preflight",
                    config::FIELD_URL
                ),
            }
        };
        Ok(Response::new(PreflightResponse {
            ok: check.ok,
            checks: vec![check],
            source_version: NAME.into(),
        }))
    }

    async fn shutdown(
        &self,
        _: Request<ShutdownRequest>,
    ) -> Result<Response<ShutdownResponse>, Status> {
        tracing::info!("shutdown requested");
        Ok(Response::new(ShutdownResponse {}))
    }
}

pub struct WebhookNotifier {
    state: State,
}

impl WebhookNotifier {
    #[must_use]
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[sb_plugin_sdk::tonic::async_trait]
impl Notifier for WebhookNotifier {
    async fn notify(
        &self,
        request: Request<NotifyRequest>,
    ) -> Result<Response<NotifyResponse>, Status> {
        let config = self.state.resolved()?;
        let NotifyRequest {
            command,
            ok,
            report_json,
        } = request.into_inner();
        let body = send::body(config.format, &command, ok, &report_json);
        // The client is blocking, so it must not run on the async executor.
        tokio::task::spawn_blocking(move || send::post(&config, body))
            .await
            // A `JoinError` can carry a panic payload; a fixed phrase keeps
            // whatever it held -- possibly the URL -- out of the status.
            .map_err(|_| Status::internal("the delivery task failed"))?
            .map_err(Status::unavailable)?;
        Ok(Response::new(NotifyResponse {}))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use sb_plugin_sdk::sb_proto::{Value, value::Kind};
    use sb_plugin_sdk::tonic::Code;

    use super::*;

    const TOKEN: &str = "s3cr3t-t0ken";

    fn configure_request(url: &str) -> Request<ConfigureRequest> {
        Request::new(ConfigureRequest {
            config: HashMap::from([(
                "url".to_string(),
                Value {
                    kind: Some(Kind::StringValue(url.into())),
                },
            )]),
        })
    }

    fn notify_request() -> Request<NotifyRequest> {
        Request::new(NotifyRequest {
            command: "backup".into(),
            ok: true,
            report_json: r#"{"ok":true}"#.into(),
        })
    }

    fn pair() -> (WebhookPlugin, WebhookNotifier) {
        let state = State::new(NAME);
        (
            WebhookPlugin::new(state.clone()),
            WebhookNotifier::new(state),
        )
    }

    /// Answers one request with `status_line` and returns what it received.
    fn fake_webhook(status_line: &'static str) -> (u16, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Headers and body may arrive in separate segments; answering
            // before the body is read would reset the connection.
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            while !(seen.windows(4).any(|w| w == b"\r\n\r\n") && seen.ends_with(b"}")) {
                let n = stream.read(&mut buf).unwrap();
                seen.extend_from_slice(&buf[..n]);
            }
            write!(
                stream,
                "HTTP/1.1 {status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            String::from_utf8_lossy(&seen).into_owned()
        });
        (port, handle)
    }

    #[tokio::test]
    async fn info_announces_only_the_notifier_capability() {
        let (plugin, _) = pair();
        let info = plugin.info(Request::new(InfoRequest {})).await.unwrap();
        assert_eq!(
            info.into_inner().capabilities,
            vec![Capability::Notifier as i32]
        );
    }

    #[tokio::test]
    async fn a_configured_notifier_posts_the_report() {
        let (plugin, notifier) = pair();
        let (port, server) = fake_webhook("200 OK");
        plugin
            .configure(configure_request(&format!(
                "http://127.0.0.1:{port}/hook/{TOKEN}"
            )))
            .await
            .unwrap();

        notifier.notify(notify_request()).await.unwrap();

        let seen = server.join().unwrap();
        assert!(seen.starts_with(&format!("POST /hook/{TOKEN} ")), "{seen}");
        assert!(seen.ends_with(r#"{"ok":true}"#), "{seen}");
    }

    #[tokio::test]
    async fn a_failing_webhook_becomes_a_status_without_the_url() {
        let (plugin, notifier) = pair();
        let (port, server) = fake_webhook("500 Internal Server Error");
        plugin
            .configure(configure_request(&format!(
                "http://127.0.0.1:{port}/hook/{TOKEN}"
            )))
            .await
            .unwrap();

        let status = notifier.notify(notify_request()).await.unwrap_err();

        server.join().unwrap();
        assert_eq!(status.code(), Code::Unavailable);
        assert_eq!(status.message(), "the webhook answered HTTP 500");
    }

    #[tokio::test]
    async fn notify_before_configure_is_a_failed_precondition() {
        let (_, notifier) = pair();
        let status = notifier.notify(notify_request()).await.unwrap_err();
        assert_eq!(status.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn configure_rejects_a_remote_http_url_without_echoing_it() {
        let (plugin, _) = pair();
        let status = plugin
            .configure(configure_request(&format!("http://example.com/{TOKEN}")))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(!status.message().contains(TOKEN), "{}", status.message());
    }

    #[tokio::test]
    async fn preflight_reports_missing_configuration() {
        let (plugin, _) = pair();
        let r = plugin
            .preflight(Request::new(PreflightRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(!r.ok);
    }

    #[tokio::test]
    async fn preflight_sends_nothing_and_does_not_show_the_url() {
        let (plugin, _) = pair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        plugin
            .configure(configure_request(&format!(
                "http://127.0.0.1:{port}/hook/{TOKEN}"
            )))
            .await
            .unwrap();

        let r = plugin
            .preflight(Request::new(PreflightRequest {}))
            .await
            .unwrap()
            .into_inner();

        assert!(r.ok);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "preflight must not contact the webhook"
        );
        let shown = format!("{r:?}");
        assert!(
            !shown.contains(TOKEN) && !shown.contains("127.0.0.1"),
            "{shown}"
        );
    }

    #[tokio::test]
    async fn configure_silences_the_http_clients_log_output() {
        let (plugin, _) = pair();
        plugin
            .configure(configure_request("https://example.com/hook"))
            .await
            .unwrap();
        assert_eq!(log::max_level(), log::LevelFilter::Off);
    }
}
