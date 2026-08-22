//! `shieldbk backup [target]`.
//!
//! The one thing this command decides and nobody else can decide for it is
//! **what the artifact is called**: the core receives the key already computed,
//! because an operation that looked at the clock on its own could not be
//! tested. Here is where it is looked at, once per target, and in UTC: a
//! nightly backup cannot change its name because the server switched to summer
//! time.
//!
//! The second thing is that **a target that fails does not take the others down
//! with it**. Whoever backs up ten databases with a `cron` wants the nine that
//! go well done anyway, and to find out at the end which one did not. The exit
//! code is still an error one if any of them failed.

use sb_config::Target;
use sb_core::naming::{NamingContext, render};
use sb_core::ops::backup::{BackupRequest, run_backup};
use sb_crypto::{CompressionLevel, Recipient};
use time::OffsetDateTime;

use crate::commands::concurrency::in_batches;
use crate::context::Context;
use crate::error::CliError;
use crate::output::Report;
use crate::plugins::{self, Role};

/// What is left of backing up a target, well or badly.
struct Outcome {
    target: String,
    /// The key only exists if the backup got as far as being named.
    key: Option<String>,
    /// The failure is kept whole, not as text: its class is what decides the
    /// exit code, and an unregistered plugin has to exit with the plugin code
    /// even though the failure was discovered while backing up.
    failure: Option<CliError>,
    plaintext: u64,
    ciphertext: u64,
    digest: String,
}

/// # Errors
/// Returns [`CliError::Config`] if the target does not exist. Backups that fail
/// are **not** propagated as an error: they travel inside the report, so that
/// whoever backs up ten databases sees the nine that went well.
pub async fn run(ctx: &Context, target: Option<&str>) -> Result<Report, CliError> {
    let targets = ctx.targets(target)?;
    let total = targets.len();

    let outcomes = in_batches(targets, ctx.jobs, |t| back_up(ctx, t)).await;

    let failures: Vec<CliError> = outcomes
        .iter()
        .filter_map(|r| r.failure.as_ref().map(CliError::duplicate))
        .collect();
    let report = compose(&outcomes, total, failures.len());

    let summary = format!(
        "{} of {total} backups failed:\n{}",
        failures.len(),
        failure_detail(&outcomes)
    );
    Ok(match CliError::group(summary, &failures) {
        Some(failure) => report.with_failure(failure),
        None => report,
    })
}

/// Backs up a target from beginning to end. It never propagates: it returns the
/// failure inside the outcome so that the rest of the targets carry on.
async fn back_up(ctx: &Context, target: &Target) -> Outcome {
    match attempt(ctx, target).await {
        Ok(outcome) => outcome,
        Err(failure) => {
            tracing::error!(target = %target.name, %failure, "the backup failed");
            Outcome {
                target: target.name.clone(),
                key: None,
                failure: Some(failure),
                plaintext: 0,
                ciphertext: 0,
                digest: String::new(),
            }
        }
    }
}

async fn attempt(ctx: &Context, target: &Target) -> Result<Outcome, CliError> {
    // The recipient is checked **before** starting any plugin: a typo in the
    // public key costs a second to discover here and costs an artifact that is
    // unreadable forever to discover later.
    let recipient = Recipient::parse(&target.recipient).map_err(|source| {
        CliError::config(format!(
            "the `recipient` of target `{}` is not a valid age key: {source}",
            target.name
        ))
    })?;

    let level =
        CompressionLevel::new(target.effective_level(&ctx.config.defaults)).map_err(|source| {
            CliError::config(format!(
                "the compression level of target `{}` is not valid: {source}",
                target.name
            ))
        })?;

    let now = OffsetDateTime::now_utc();
    let naming = NamingContext::new(
        &target.name,
        &target.source,
        &target.storage,
        now.unix_timestamp(),
    );
    let key = render(target.effective_template(&ctx.config.defaults), &naming)?;

    let source = plugins::start_for(ctx, target, Role::Source).await?;
    let storage = match plugins::start_for(ctx, target, Role::Storage).await {
        Ok(storage) => storage,
        Err(error) => {
            plugins::close(source).await;
            return Err(error);
        }
    };

    let outcome = run_with(&source, &storage, target, key, recipient, level, now).await;

    plugins::close(source).await;
    plugins::close(storage).await;
    outcome
}

async fn run_with(
    source: &sb_core::plugin::PluginClient,
    storage: &sb_core::plugin::PluginClient,
    target: &Target,
    key: String,
    recipient: Recipient,
    level: CompressionLevel,
    now: OffsetDateTime,
) -> Result<Outcome, CliError> {
    // The plugin's version and the server's go into the manifest. The second is
    // reported by the source in its preflight, which is also the cheap check
    // that rules out an expired credential before moving a byte.
    let plugin_version = source.info().await?.version;
    let source_version = source.preflight().await?.source_version;

    let out = run_backup(BackupRequest {
        target: target.name.clone(),
        source,
        storage,
        artifact_key: key,
        recipient,
        level,
        plugin_version,
        source_version,
        created_at: iso8601_utc(now),
    })
    .await?;

    Ok(Outcome {
        target: target.name.clone(),
        key: Some(out.artifact_key),
        failure: None,
        plaintext: out.summary.plaintext_bytes,
        ciphertext: out.summary.ciphertext_bytes,
        digest: out.summary.ciphertext_sha256.to_hex(),
    })
}

/// The stamp that goes into the manifest, in UTC and without depending on the
/// locale.
///
/// It is composed by hand instead of with `time`'s formatter so as not to drag
/// in its `formatting` features: the format is fixed and the manifest is read
/// by a program.
fn iso8601_utc(instant: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        instant.year(),
        u8::from(instant.month()),
        instant.day(),
        instant.hour(),
        instant.minute(),
        instant.second()
    )
}

fn compose(outcomes: &[Outcome], total: usize, failed: usize) -> Report {
    let mut lines = Vec::with_capacity(outcomes.len() + 1);
    let mut json = Vec::with_capacity(outcomes.len());

    for r in outcomes {
        match (&r.key, &r.failure) {
            (Some(key), _) => {
                lines.push(format!(
                    "{}: {key} ({} plaintext bytes -> {} encrypted)",
                    r.target, r.plaintext, r.ciphertext
                ));
                json.push(serde_json::json!({
                    "target": r.target,
                    "ok": true,
                    "artifact_key": key,
                    "plaintext_bytes": r.plaintext,
                    "ciphertext_bytes": r.ciphertext,
                    "ciphertext_sha256": r.digest,
                }));
            }
            (None, failure) => {
                let reason = failure
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                lines.push(format!("{}: FAILED - {reason}", r.target));
                json.push(serde_json::json!({
                    "target": r.target,
                    "ok": false,
                    "error": reason,
                }));
            }
        }
    }

    lines.push(format!("{}/{total} backups completed", total - failed));

    Report::new(
        lines.join("\n"),
        serde_json::json!({
            "command": "backup",
            "total": total,
            "failed": failed,
            "targets": json,
        }),
    )
}

fn failure_detail(outcomes: &[Outcome]) -> String {
    outcomes
        .iter()
        .filter_map(|r| r.failure.as_ref().map(|f| format!("  {}: {f}", r.target)))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(target: &str, key: &str) -> Outcome {
        Outcome {
            target: target.into(),
            key: Some(key.into()),
            failure: None,
            plaintext: 10,
            ciphertext: 5,
            digest: "abc".into(),
        }
    }

    fn bad(target: &str, reason: &str) -> Outcome {
        Outcome {
            target: target.into(),
            key: None,
            failure: Some(CliError::operation(reason)),
            plaintext: 0,
            ciphertext: 0,
            digest: String::new(),
        }
    }

    #[test]
    fn the_timestamp_is_iso8601_in_utc() {
        // The manifest is read by a program: the format has to be fixed and not
        // depend on the server's locale.
        let instant = OffsetDateTime::from_unix_timestamp(1_755_770_400).unwrap();
        let text = iso8601_utc(instant);
        assert_eq!(text.len(), 20, "{text}");
        assert!(text.ends_with('Z'), "{text}");
        assert_eq!(&text[4..5], "-");
        assert_eq!(&text[10..11], "T");
    }

    #[test]
    fn the_json_carries_each_artifacts_key() {
        // It is what a script looks for: `jq '.targets[].artifact_key'`.
        let report = compose(&[ok("prod", "prod/2026/x.age")], 1, 0);
        assert_eq!(report.json["targets"][0]["artifact_key"], "prod/2026/x.age");
        assert_eq!(report.json["failed"], 0);
    }

    #[test]
    fn a_target_that_fails_does_not_erase_the_ones_that_went_well() {
        // Whoever backs up ten databases wants the nine good ones done and to
        // know which was the tenth.
        let report = compose(&[ok("a", "a.age"), bad("b", "no space left")], 2, 1);
        assert_eq!(report.json["targets"][0]["ok"], true);
        assert_eq!(report.json["targets"][1]["ok"], false);
        assert_eq!(report.json["targets"][1]["error"], "no space left");
        assert!(report.human.contains("1/2 backups completed"));
    }

    #[test]
    fn the_failure_detail_names_its_target() {
        let text = failure_detail(&[ok("a", "a.age"), bad("b", "disk full")]);
        assert!(text.contains('b'), "{text}");
        assert!(text.contains("disk full"), "{text}");
        assert!(
            !text.contains("a.age"),
            "the ones that went well are not failures"
        );
    }
}
