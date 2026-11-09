//! `shieldbk drill <target> --identity <path> [--artifact <key>]`.
//!
//! A backup that has never been restored is a hope, not a backup. This command is
//! how a target proves otherwise on a schedule: it restores the newest artifact
//! into a disposable place, asks the question the target's `[target.drill]` block
//! says is the proof the data is there, and reports the answer with an exit code a
//! `cron` job can page on.
//!
//! The command itself is short because everything that needs to know what a
//! database is lives in the source plugin (`Drill` service) and everything that
//! orders the steps lives in [`sb_core::ops::drill`]. What is left here is the part
//! only the CLI knows: which artifact is "the latest", and how the outcome is told.
//!
//! # The private key
//!
//! It takes `--identity` exactly as `restore` does, and for the same reason: it is
//! the one thing that must not live in a file that gets versioned. That makes a
//! scheduled drill the one job that needs the key on the machine that runs it --
//! worth knowing before scheduling it somewhere shared.

use std::path::Path;
use std::time::Duration;

use sb_core::ops::drill::{DrillOutcome, DrillRequest, run_drill};
use sb_crypto::Identity;

use super::restore::{expected_digest, read_identity};
use crate::artifacts;
use crate::context::Context;
use crate::error::CliError;
use crate::output::Report;
use crate::plugins::{self, Role};

/// # Errors
/// Returns [`CliError::Config`] if the target does not exist, has no
/// `[target.drill]` block, or the identity cannot be read; [`CliError::Plugin`] if
/// a plugin does not start; and [`CliError::Operation`] if the target has no
/// artifact to drill. A drill that **runs and fails** -- the restore breaks, the
/// check does not hold -- is not an `Err`: its failure travels inside the report so
/// the output says how far it got.
pub async fn run(
    ctx: &Context,
    target: &str,
    artifact: Option<&str>,
    identity: &Path,
) -> Result<Report, CliError> {
    let target = ctx.target(target)?;
    let Some(drill) = &target.drill else {
        return Err(CliError::config(format!(
            "the target `{0}` has no `[target.drill]` block: add one with the `check` whose \
             answer shows the restored data is really there",
            target.name
        )));
    };
    let identity = read_identity(identity)?;

    let source = plugins::start_drill_source(ctx, target, drill).await?;
    let storage = match plugins::start_for(ctx, target, Role::Storage).await {
        Ok(storage) => storage,
        Err(error) => {
            plugins::close(source).await;
            return Err(error);
        }
    };

    let outcome = drill_latest(
        ctx,
        target,
        &source,
        &storage,
        artifact,
        &identity,
        &drill.check,
    )
    .await;

    // Both are closed whatever happened, including when no artifact could be
    // chosen: a live plugin nobody is going to ask anything of any more is a
    // process with session key material in memory.
    plugins::close(source).await;
    plugins::close(storage).await;

    let (key, outcome) = outcome?;
    Ok(compose(&target.name, &key, &outcome))
}

async fn drill_latest(
    ctx: &Context,
    target: &sb_config::Target,
    source: &sb_core::plugin::PluginClient,
    storage: &sb_core::plugin::PluginClient,
    artifact: Option<&str>,
    identity: &Identity,
    check: &str,
) -> Result<(String, DrillOutcome), CliError> {
    let key = choose_artifact(ctx, target, storage, artifact).await?;

    let outcome = run_drill(DrillRequest {
        source,
        storage,
        expected_ciphertext_sha256: expected_digest(storage, &key).await,
        artifact_key: key.clone(),
        identity,
        check: check.to_owned(),
    })
    .await?;
    Ok((key, outcome))
}

/// The artifact to drill: the one that was named, or the newest of the target.
async fn choose_artifact(
    ctx: &Context,
    target: &sb_config::Target,
    storage: &sb_core::plugin::PluginClient,
    named: Option<&str>,
) -> Result<String, CliError> {
    if let Some(key) = named {
        return Ok(key.to_owned());
    }
    let prefix = artifacts::prefix_for(target, &ctx.config.defaults);
    let found = artifacts::list(storage, &prefix).await?;
    // No artifact is a failure, not a pass: a target whose backups are missing is
    // exactly what a drill is there to flag.
    artifacts::latest(found)
        .map(|newest| newest.key)
        .ok_or_else(|| {
            CliError::operation(format!(
                "target `{}` has no artifacts under `{prefix}` to drill: nothing has been backed \
                 up there yet, or the backups are not where its template says",
                target.name
            ))
        })
}

/// Tells how the drill went, in both languages.
///
/// The failure -- and with it the exit code -- goes **inside** the report rather
/// than replacing it: whoever is paged needs to know the restore worked and the
/// check did not, not only that something failed.
fn compose(target: &str, key: &str, outcome: &DrillOutcome) -> Report {
    let json = serde_json::json!({
        "command": "drill",
        "target": target,
        "artifact_key": key,
        "passed": outcome.passed(),
        "scratch": outcome.scratch,
        "plaintext_bytes": outcome.plaintext_bytes,
        "check": outcome.check.as_ref().map(|c| serde_json::json!({
            "ok": c.ok,
            "detail": c.detail,
        })),
        "failed_stage": outcome.failure.as_ref().map(|f| f.stage.as_str()),
        "failure": outcome.failure.as_ref().map(|f| f.message.as_str()),
        "restore_ms": outcome.restore_elapsed.map(millis),
        "elapsed_ms": millis(outcome.elapsed),
        "teardown_ok": outcome.teardown_error.is_none(),
        "teardown_error": outcome.teardown_error,
    });

    let seconds = outcome.elapsed.as_secs_f64();
    let mut lines = Vec::new();
    match &outcome.failure {
        None => {
            let bytes = outcome.plaintext_bytes.unwrap_or(0);
            let detail = outcome.check.as_ref().map_or("", |c| c.detail.as_str());
            lines.push(format!(
                "{target}: drill passed: restored {bytes} bytes from {key}; check: {detail} \
                 ({seconds:.1}s)"
            ));
        }
        Some(failure) => {
            lines.push(format!(
                "{target}: drill FAILED at {}: {} ({seconds:.1}s)",
                failure.stage.as_str(),
                failure.message
            ));
        }
    }
    if let Some(error) = &outcome.teardown_error {
        // Said even when the drill passed: a scratch place nobody dropped is a
        // leak, and it would otherwise only show up on the bill.
        lines.push(format!(
            "warning: the scratch place may not have been thrown away: {error}"
        ));
    }

    let report = Report::new(lines.join("\n"), json);
    match &outcome.failure {
        None => report,
        Some(failure) => report.with_failure(CliError::operation(format!(
            "the drill of target `{target}` failed at {}: {}",
            failure.stage.as_str(),
            failure.message
        ))),
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use sb_core::ops::drill::{CheckVerdict, DrillFailure, Stage};

    use super::*;

    fn passed() -> DrillOutcome {
        DrillOutcome {
            scratch: Some("drill_1".into()),
            plaintext_bytes: Some(2048),
            check: Some(CheckVerdict {
                ok: true,
                detail: "true".into(),
            }),
            restore_elapsed: Some(Duration::from_millis(1500)),
            elapsed: Duration::from_millis(2500),
            ..DrillOutcome::default()
        }
    }

    #[test]
    fn a_drill_that_passed_says_so_and_carries_no_failure() {
        let report = compose("app", "app/a.age", &passed());
        assert!(report.failure.is_none());
        assert_eq!(report.code(), 0);
        assert!(report.human.contains("drill passed"), "{}", report.human);
        assert!(report.human.contains("2048 bytes"), "{}", report.human);
        assert_eq!(report.json["command"], "drill");
        assert_eq!(report.json["passed"], true);
        assert_eq!(report.json["restore_ms"], 1500);
        assert_eq!(report.json["check"]["ok"], true);
        assert!(report.json["failed_stage"].is_null());
        assert_eq!(report.json["teardown_ok"], true);
    }

    #[test]
    fn a_failed_check_exits_with_the_operation_code_and_keeps_what_the_restore_did() {
        let mut outcome = passed();
        outcome.check = Some(CheckVerdict {
            ok: false,
            detail: "f".into(),
        });
        outcome.failure = Some(DrillFailure {
            stage: Stage::Check,
            message: "no rows in users".into(),
        });

        let report = compose("app", "app/a.age", &outcome);
        assert_eq!(report.code(), 4, "the code a cron job pages on");
        assert!(report.human.contains("FAILED at check"), "{}", report.human);
        assert_eq!(report.json["passed"], false);
        assert_eq!(report.json["failed_stage"], "check");
        assert_eq!(report.json["failure"], "no rows in users");
        // The restore worked, and the report must not lose that.
        assert_eq!(report.json["plaintext_bytes"], 2048);
    }

    #[test]
    fn a_teardown_that_failed_is_a_warning_and_not_a_failure() {
        let mut outcome = passed();
        outcome.teardown_error = Some("could not drop drill_1".into());

        let report = compose("app", "app/a.age", &outcome);
        assert_eq!(report.code(), 0, "the backup restored: that is the verdict");
        assert!(report.human.contains("warning"), "{}", report.human);
        assert_eq!(report.json["teardown_ok"], false);
        assert_eq!(report.json["teardown_error"], "could not drop drill_1");
    }

    #[test]
    fn a_drill_that_never_got_going_reports_nulls_and_not_zeros() {
        // Provision failed: nothing was restored, so "0 bytes" would be a lie.
        let outcome = DrillOutcome {
            failure: Some(DrillFailure {
                stage: Stage::Provision,
                message: "no CREATEDB".into(),
            }),
            ..DrillOutcome::default()
        };
        let report = compose("app", "app/a.age", &outcome);
        assert!(report.json["plaintext_bytes"].is_null());
        assert!(report.json["scratch"].is_null());
        assert!(report.json["restore_ms"].is_null());
        assert!(report.json["check"].is_null());
    }
}
