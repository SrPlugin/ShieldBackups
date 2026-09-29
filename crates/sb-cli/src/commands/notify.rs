//! Telling the configured notifiers how a command went.
//!
//! The core does not know what a Slack channel, a mailbox or a Telegram chat is.
//! It knows that a command ended, that a `[[notify]]` block asked to hear about
//! it, and that a plugin with the `notifier` capability turns an event into
//! whatever its channel needs. The event is the very document `--format json`
//! prints, so a notifier and a script piping into `jq` read the same contract.
//!
//! Two rules keep this from making things worse than not having it:
//!
//! - **A notification never changes the outcome.** The backup worked or it did
//!   not; a Slack outage does not turn a good backup into a failed one. But a
//!   silent alerting failure is exactly what an alert exists to prevent, so the
//!   failure is said out loud on stderr.
//! - **A notifier cannot hang the run.** It is a process this one waits for,
//!   started from a cron job: each one gets a deadline, and is killed when it
//!   is over.

use std::time::Duration;

use sb_config::Notify;
use sb_proto::NotifyRequest;
use sb_proto::notifier_client::NotifierClient;

use super::concurrency::in_batches;
use crate::context::Context;
use crate::error::CliError;
use crate::output::{self, Report};
use crate::plugins;

/// How many notifiers are being told at the same time. They are independent
/// and mostly waiting on the network; the limit only keeps a long list from
/// starting that many processes at once.
const AT_ONCE: usize = 4;

/// How long one notifier has, from being started to having answered.
const DEADLINE: Duration = Duration::from_secs(30);

/// Tells every notifier that asked to hear about a command that ended with
/// `result`.
///
/// Nothing comes back: whatever goes wrong is written to stderr and that is all.
pub async fn tell(ctx: &Context, command: &str, result: &Result<Report, CliError>) {
    let ok = matches!(result, Ok(report) if report.failure.is_none());
    let due = due(&ctx.config.notify, ok);
    if due.is_empty() {
        return;
    }

    let request = NotifyRequest {
        command: command.to_owned(),
        ok,
        report_json: document_of(result).to_string(),
    };
    let outcomes = in_batches(due, AT_ONCE, |notify| {
        let request = request.clone();
        async move { (notify, deliver(ctx, notify, request).await) }
    })
    .await;

    for (notify, outcome) in outcomes {
        if let Err(error) = outcome {
            eprintln!(
                "warning: could not notify through `{}`: {error}",
                notify.plugin
            );
        }
    }
}

/// The blocks that want to hear about a command that ended `ok`.
fn due(notify: &[Notify], ok: bool) -> Vec<&Notify> {
    notify.iter().filter(|n| n.on.matches(ok)).collect()
}

/// What `--format json` would have printed for this result, failure included.
fn document_of(result: &Result<Report, CliError>) -> serde_json::Value {
    match result {
        Ok(report) => output::document(report),
        Err(error) => output::document(
            &Report::new("", serde_json::json!({})).with_failure(error.duplicate()),
        ),
    }
}

async fn deliver(ctx: &Context, notify: &Notify, request: NotifyRequest) -> Result<(), CliError> {
    match tokio::time::timeout(DEADLINE, send(ctx, notify, request)).await {
        Ok(outcome) => outcome,
        // The future is dropped here, and with it the plugin process: the
        // client kills its child when it goes.
        Err(_) => Err(CliError::operation(format!(
            "it did not answer within {}s",
            DEADLINE.as_secs()
        ))),
    }
}

async fn send(ctx: &Context, notify: &Notify, request: NotifyRequest) -> Result<(), CliError> {
    let client = plugins::start_notifier(ctx, notify).await?;
    let outcome = NotifierClient::new(client.channel())
        .notify(request)
        .await
        .map(|_| ())
        .map_err(|status| CliError::operation(status.message().to_owned()));
    plugins::close(client).await;
    outcome
}

#[cfg(test)]
mod tests {
    use sb_config::NotifyOn;

    use super::*;

    fn block(plugin: &str, on: NotifyOn) -> Notify {
        Notify {
            plugin: plugin.into(),
            on,
            config: sb_config::ConfigTable::new(),
        }
    }

    #[test]
    fn only_the_blocks_that_asked_for_this_outcome_are_told() {
        let all = [
            block("alerts", NotifyOn::Failure),
            block("pings", NotifyOn::Success),
            block("log", NotifyOn::Always),
        ];
        let names = |ok| {
            due(&all, ok)
                .iter()
                .map(|n| n.plugin.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(true), ["pings", "log"]);
        assert_eq!(names(false), ["alerts", "log"]);
    }

    #[test]
    fn a_command_that_died_before_it_had_a_report_still_has_a_document() {
        let document = document_of(&Err(CliError::config("no such target")));
        assert_eq!(document["ok"], serde_json::Value::Bool(false));
        assert_eq!(document["class"], "config");
        assert!(
            document["error"]
                .as_str()
                .unwrap()
                .contains("no such target")
        );
    }

    #[test]
    fn a_report_that_carries_a_failure_is_not_ok() {
        // `doctor` finding problems is the case: the command ran, and what it
        // found is bad.
        let report = Report::new("", serde_json::json!({ "targets": [] }))
            .with_failure(CliError::operation("1 of 1 targets have problems"));
        let document = document_of(&Ok(report));
        assert_eq!(document["ok"], serde_json::Value::Bool(false));
        assert!(document["targets"].is_array());
    }
}
