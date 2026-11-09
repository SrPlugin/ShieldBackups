//! The restore drill: prove an artifact restores, in a place that can be thrown
//! away.
//!
//! ```text
//!  Provision ──▶ restore (storage → core → source) ──▶ Check ──▶ Teardown
//!                                                                  ▲
//!                  runs whatever happened above ───────────────────┘
//! ```
//!
//! The restore in the middle is [`crate::ops::restore::run_restore`], untouched:
//! a drill that restored by some other path would prove that *that* path works.
//! What is new is around it, and all of it is the source plugin's to do, because
//! the core does not know what a database is: it asks the plugin for a disposable
//! place ([`Provision`](sb_proto::drill_client::DrillClient::provision)), lets
//! the ordinary restore fill it, asks the plugin whether what landed is right
//! ([`Check`](sb_proto::drill_client::DrillClient::check)) and has it thrown
//! away ([`Teardown`](sb_proto::drill_client::DrillClient::teardown)).
//!
//! # What this returns, and what it does not
//!
//! A drill that **fails** is not an error of this function: it is its answer, and
//! the whole point of running one. [`run_drill`] only returns `Err` for what stops
//! it before touching anything -- a plugin that cannot take part -- and otherwise
//! hands back a [`DrillOutcome`] saying how far it got, so the report can say "the
//! restore worked but the check found no rows" and not just "it failed".
//!
//! # Teardown always runs
//!
//! A restore that dies halfway leaves partial plaintext in the scratch place, and a
//! check that fails leaves a whole restored database: both have to be thrown away,
//! and the plugin's `Teardown` is idempotent precisely so the core can call it
//! without asking whether anything was provisioned. A teardown that itself fails
//! does **not** change the verdict -- the backup restored or it did not -- but it
//! is reported, because a scratch database nobody drops is a leak.

use std::future::Future;
use std::time::{Duration, Instant};

use sb_crypto::{Digest, Identity};
use sb_proto::drill_client::DrillClient;
use sb_proto::{CheckRequest, ProvisionRequest, TeardownRequest};

use crate::ops::channel::BackupError;
use crate::ops::restore::{RestoreRequest, run_restore};
use crate::plugin::{Capability, PluginClient};

/// How long one drill RPC has to answer.
///
/// Generous, and deliberately not the control channel's one minute: a check is a
/// query against a freshly restored database, and on a large one it may scan.
/// What this guards against is a plugin that hangs, not one that is slow.
const STEP_DEADLINE: Duration = Duration::from_secs(300);

/// Everything a drill needs, already resolved.
///
/// As in [`RestoreRequest`], the plugins arrive started and configured: this
/// operation neither chooses a plugin nor resolves configuration.
pub struct DrillRequest<'a> {
    /// The source plugin, which must also implement `Drill`.
    pub source: &'a PluginClient,
    pub storage: &'a PluginClient,
    pub artifact_key: String,
    pub identity: &'a Identity,
    /// The digest the manifest says the artifact must have. As in a restore,
    /// optional because the manifest may be missing, and for the same reason
    /// worth having: see [`RestoreRequest::expected_ciphertext_sha256`].
    pub expected_ciphertext_sha256: Option<Digest>,
    /// What to ask the plugin once the artifact is restored. The core does not
    /// interpret it.
    pub check: String,
}

/// The step a drill failed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Making the disposable place.
    Provision,
    /// Moving the artifact into it.
    Restore,
    /// Asking whether what landed there is right.
    Check,
}

impl Stage {
    /// The name it travels under in the report.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provision => "provision",
            Self::Restore => "restore",
            Self::Check => "check",
        }
    }
}

/// Why a drill did not pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrillFailure {
    pub stage: Stage,
    pub message: String,
}

/// What the plugin answered to the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckVerdict {
    pub ok: bool,
    pub detail: String,
}

/// How far a drill got and how it ended.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrillOutcome {
    /// Where the restore landed, as the plugin described it. `None` if nothing
    /// was provisioned.
    pub scratch: Option<String>,
    /// Plaintext bytes handed to the source. `None` if the restore did not finish.
    pub plaintext_bytes: Option<u64>,
    /// The plugin's answer to the check. `None` if it was never asked, or never
    /// answered.
    pub check: Option<CheckVerdict>,
    /// `None` is the only way a drill passes.
    pub failure: Option<DrillFailure>,
    /// Why the scratch place could not be thrown away, if it could not.
    pub teardown_error: Option<String>,
    /// Time spent restoring. `None` if the restore never started.
    pub restore_elapsed: Option<Duration>,
    /// Time from the first RPC to the end of the teardown.
    pub elapsed: Duration,
}

impl DrillOutcome {
    /// Whether the artifact restored and the check held.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.failure.is_none()
    }
}

/// Restores `req.artifact_key` into a disposable place, checks it and throws it
/// away.
///
/// # Errors
/// Returns [`BackupError`] only when the drill could not even begin: the source
/// lacks the `source` or `drill` capability, or the storage lacks `storage`.
/// Everything after that -- including a restore that fails and a check that does
/// not hold -- is in the returned [`DrillOutcome`].
pub async fn run_drill(req: DrillRequest<'_>) -> Result<DrillOutcome, BackupError> {
    // Before provisioning anything: finding out that the plugin cannot take part
    // costs a string comparison, and finding out after `Provision` costs a
    // scratch database to clean up.
    req.source.require_capability(Capability::Source)?;
    req.source.require_capability(Capability::Drill)?;
    req.storage.require_capability(Capability::Storage)?;

    let started = Instant::now();
    let mut drill = DrillClient::new(req.source.channel());
    let mut outcome = DrillOutcome::default();

    if let Err(failure) = attempt(&req, &mut drill, &mut outcome).await {
        tracing::warn!(
            key = %req.artifact_key,
            stage = failure.stage.as_str(),
            message = %failure.message,
            "restore drill failed"
        );
        outcome.failure = Some(failure);
    }

    outcome.teardown_error = step(
        STEP_DEADLINE,
        req.source.name(),
        "Teardown",
        drill.teardown(TeardownRequest {}),
    )
    .await
    .err();
    if let Some(error) = &outcome.teardown_error {
        tracing::error!(
            plugin = %req.source.name(),
            %error,
            "the drill's scratch place may not have been thrown away"
        );
    }

    outcome.elapsed = started.elapsed();
    Ok(outcome)
}

/// Provision, restore, check: everything that can fail before the teardown,
/// which runs regardless and so lives outside.
async fn attempt(
    req: &DrillRequest<'_>,
    drill: &mut DrillClient<tonic::transport::Channel>,
    outcome: &mut DrillOutcome,
) -> Result<(), DrillFailure> {
    let provisioned = step(
        STEP_DEADLINE,
        req.source.name(),
        "Provision",
        drill.provision(ProvisionRequest {}),
    )
    .await
    .map_err(|message| failure(Stage::Provision, message))?;
    outcome.scratch = Some(provisioned.description);

    let restore_started = Instant::now();
    let written = run_restore(RestoreRequest {
        source: req.source,
        storage: req.storage,
        artifact_key: req.artifact_key.clone(),
        identity: req.identity,
        expected_ciphertext_sha256: req.expected_ciphertext_sha256,
    })
    .await
    .map_err(|error| failure(Stage::Restore, error.to_string()))?;
    outcome.plaintext_bytes = Some(written);
    outcome.restore_elapsed = Some(restore_started.elapsed());

    let answer = step(
        STEP_DEADLINE,
        req.source.name(),
        "Check",
        drill.check(CheckRequest {
            query: req.check.clone(),
        }),
    )
    .await
    .map_err(|message| failure(Stage::Check, message))?;
    outcome.check = Some(CheckVerdict {
        ok: answer.ok,
        detail: answer.detail.clone(),
    });

    if answer.ok {
        Ok(())
    } else {
        Err(failure(Stage::Check, answer.detail))
    }
}

fn failure(stage: Stage, message: String) -> DrillFailure {
    DrillFailure { stage, message }
}

/// One drill RPC with its deadline, its error already turned into a sentence
/// that names the plugin and the call.
async fn step<T, F>(deadline: Duration, plugin: &str, operation: &str, call: F) -> Result<T, String>
where
    F: Future<Output = Result<tonic::Response<T>, tonic::Status>>,
{
    match tokio::time::timeout(deadline, call).await {
        Ok(Ok(response)) => Ok(response.into_inner()),
        Ok(Err(status)) => Err(format!(
            "the plugin \"{plugin}\" failed on {operation}: {}",
            crate::plugin::client::message_from(&status)
        )),
        Err(_) => Err(format!(
            "the plugin \"{plugin}\" did not answer {operation} in {} s",
            deadline.as_secs()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_drill_with_no_failure_passed_and_one_with_a_failure_did_not() {
        let mut outcome = DrillOutcome::default();
        assert!(outcome.passed());
        outcome.failure = Some(failure(Stage::Check, "no rows".into()));
        assert!(!outcome.passed());
    }

    #[test]
    fn a_stage_travels_under_a_stable_name() {
        // The report's JSON is a contract: a script switches on these.
        assert_eq!(Stage::Provision.as_str(), "provision");
        assert_eq!(Stage::Restore.as_str(), "restore");
        assert_eq!(Stage::Check.as_str(), "check");
    }

    #[tokio::test]
    async fn a_step_that_fails_names_the_plugin_and_the_call() {
        let error = step::<(), _>(STEP_DEADLINE, "postgres", "Provision", async {
            Err(tonic::Status::permission_denied("no CREATEDB"))
        })
        .await
        .unwrap_err();
        assert!(error.contains("postgres"), "{error}");
        assert!(error.contains("Provision"), "{error}");
        assert!(error.contains("no CREATEDB"), "{error}");
    }

    #[tokio::test]
    async fn a_step_that_never_answers_gives_up_instead_of_hanging() {
        let error = step::<(), _>(
            Duration::from_millis(20),
            "postgres",
            "Check",
            std::future::pending(),
        )
        .await
        .unwrap_err();
        assert!(error.contains("did not answer Check"), "{error}");
    }
}
