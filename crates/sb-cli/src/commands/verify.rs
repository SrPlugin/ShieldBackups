//! `shieldbk verify <target> [artifact]`.
//!
//! This command starts **only the storage plugin**, and that is not a saving:
//! it is the property that justifies the pipeline hashing the ciphertext and
//! not the plaintext. Verifying decrypts nothing, so a machine can check that
//! its backups are still intact without having anything to read them with and
//! without bothering the database it backs up.
//!
//! With no artifact, every artifact of the target is checked. It is the use
//! that really matters -- a weekly `cron` against the whole repository -- and
//! that is why an artifact that does not add up does not interrupt the next
//! one: the report has to say how many passed, not which was the first to fail.

use sb_core::ops::verify::run_verify;
use sb_core::plugin::PluginClient;

use crate::artifacts;
use crate::context::Context;
use crate::error::CliError;
use crate::output::Report;
use crate::plugins::{self, Role};

/// The verdict on one artifact, ready to be told.
struct Verdict {
    key: String,
    ok: bool,
    detail: String,
}

/// # Errors
/// Returns [`CliError::Config`] if the target does not exist and
/// [`CliError::Plugin`] if the storage target does not start. An artifact that
/// does not add up does **not** interrupt the check: the negative verdict
/// travels inside the report.
pub async fn run(ctx: &Context, target: &str, artifact: Option<&str>) -> Result<Report, CliError> {
    let target = ctx.target(target)?;
    let storage = plugins::start_for(ctx, target, Role::Storage).await?;

    // With no artifact, every artifact of the target is checked, which is the
    // use that really matters: a weekly `cron` against the whole repository.
    let keys = if let Some(key) = artifact {
        Ok(vec![key.to_owned()])
    } else {
        let prefix = artifacts::prefix_for(target, &ctx.config.defaults);
        artifacts::list(&storage, &prefix)
            .await
            .map(|metas| metas.into_iter().map(|m| m.key).collect())
    };

    // The storage target is closed no matter what, including when the listing
    // failed: a live plugin nobody is going to ask anything of any more is a
    // process with session key material in memory.
    let outcome = match keys {
        Ok(keys) => Ok(check_all(&storage, keys).await),
        Err(error) => Err(error),
    };
    plugins::close(storage).await;

    let verdicts = outcome?;
    let failed = verdicts.iter().filter(|v| !v.ok).count();
    let report = compose(&target.name, &verdicts, failed);

    if failed == 0 {
        return Ok(report);
    }
    // The failure travels **inside** the report: whoever asks "how many backups
    // do I really have?" needs the full list, not just the verdict.
    Ok(report.with_failure(CliError::operation(format!(
        "{failed} of {} artifacts of target `{}` do not add up:\n{}",
        verdicts.len(),
        target.name,
        failure_detail(&verdicts)
    ))))
}

/// Checks the keys one by one. None interrupts the next: the question to answer
/// is "how many backups do I really have?".
async fn check_all(storage: &PluginClient, keys: Vec<String>) -> Vec<Verdict> {
    let mut verdicts = Vec::with_capacity(keys.len());
    for key in keys {
        verdicts.push(match run_verify(storage, &key).await {
            Ok(out) if out.ok => Verdict {
                key,
                ok: true,
                detail: format!("{} bytes", out.bytes),
            },
            Ok(out) => Verdict {
                key,
                ok: false,
                detail: format!(
                    "the manifest expected sha256 {} and the storage target served {} ({} bytes)",
                    out.expected_digest, out.actual_digest, out.bytes
                ),
            },
            // Not being able to issue a verdict is a negative verdict: an
            // artifact without a manifest is not a backup to be trusted.
            Err(source) => Verdict {
                key,
                ok: false,
                detail: source.to_string(),
            },
        });
    }
    verdicts
}

fn compose(target: &str, verdicts: &[Verdict], failed: usize) -> Report {
    let total = verdicts.len();
    let mut lines: Vec<String> = verdicts
        .iter()
        .map(|v| {
            let mark = if v.ok { "ok" } else { "FAILED" };
            format!("{mark} {}: {}", v.key, v.detail)
        })
        .collect();
    lines.push(format!(
        "{}/{total} artifacts of `{target}` verified",
        total - failed
    ));

    let json: Vec<serde_json::Value> = verdicts
        .iter()
        .map(|v| {
            serde_json::json!({
                "artifact_key": v.key,
                "ok": v.ok,
                "detail": v.detail,
            })
        })
        .collect();

    Report::new(
        lines.join("\n"),
        serde_json::json!({
            "command": "verify",
            "target": target,
            "total": total,
            "failed": failed,
            "artifacts": json,
        }),
    )
}

fn failure_detail(verdicts: &[Verdict]) -> String {
    verdicts
        .iter()
        .filter(|v| !v.ok)
        .map(|v| format!("  {}: {}", v.key, v.detail))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(key: &str, ok: bool) -> Verdict {
        Verdict {
            key: key.into(),
            ok,
            detail: if ok { "100 bytes" } else { "does not add up" }.into(),
        }
    }

    #[test]
    fn the_report_counts_how_many_passed() {
        // It is the question this command answers: not "did something fail?"
        // but "how many backups do I really have?".
        let report = compose(
            "prod",
            &[verdict("a", true), verdict("b", false), verdict("c", true)],
            1,
        );
        assert_eq!(report.json["total"], 3);
        assert_eq!(report.json["failed"], 1);
        assert!(report.human.contains("2/3 artifacts"));
    }

    #[test]
    fn zero_artifacts_is_not_a_failure_but_it_shows() {
        // A freshly created target has no backups yet, and saying "0/0" is more
        // honest than staying quiet.
        let report = compose("new", &[], 0);
        assert_eq!(report.json["total"], 0);
        assert!(report.human.contains("0/0"));
    }

    #[test]
    fn the_failures_are_detailed_one_by_one() {
        let text = failure_detail(&[verdict("a", true), verdict("b", false)]);
        assert!(text.contains('b'));
        assert!(
            !text.contains("a:"),
            "the ones that passed are not failures"
        );
    }
}
