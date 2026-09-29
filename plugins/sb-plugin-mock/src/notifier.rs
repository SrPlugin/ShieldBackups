//! The notifier: appends what it is told to a file, so a test can read it back.
//!
//! A real notifier talks to Slack or a mailbox, where a test cannot look. This
//! one leaves the event on disk, one JSON object per line, and that is enough to
//! check that the core told the right plugin the right thing at the right time.

use sb_plugin_sdk::sb_proto::notifier_server::Notifier;
use sb_plugin_sdk::sb_proto::{NotifyRequest, NotifyResponse};
use sb_plugin_sdk::tonic::{Request, Response, Status};
use tokio::io::AsyncWriteExt as _;

use crate::config::State;

/// File, inside the configured `dir`, the events are appended to.
pub const NOTIFICATIONS_FILE: &str = "notifications.jsonl";

pub struct MockNotifier {
    state: State,
}

impl MockNotifier {
    #[must_use]
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[sb_plugin_sdk::tonic::async_trait]
impl Notifier for MockNotifier {
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

        // `report_json` is already a JSON document and `command` is one of the
        // core's fixed command names, so composing the line by hand is exact
        // here and keeps the mock free of a JSON dependency.
        let line = format!("{{\"command\":{command:?},\"ok\":{ok},\"report\":{report_json}}}\n");

        tokio::fs::create_dir_all(&config.dir)
            .await
            .map_err(|source| Status::internal(format!("could not create `dir`: {source}")))?;
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(config.dir.join(NOTIFICATIONS_FILE))
            .await
            .map_err(|source| Status::internal(format!("could not open the file: {source}")))?;
        file.write_all(line.as_bytes())
            .await
            .map_err(|source| Status::internal(format!("could not write the event: {source}")))?;

        tracing::info!(command = %command, ok, "notification recorded");
        Ok(Response::new(NotifyResponse {}))
    }
}
