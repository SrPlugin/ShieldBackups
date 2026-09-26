//! `shieldbk doctor [target]`.
//!
//! `doctor` does not abort. Ever. A plugin that does not start is a line of the
//! report, not the end of the diagnosis: if it aborted, the user would fix one
//! problem to discover the next, once per attempt. That is why this command
//! wraps even start-up failures -- which in any other command would be a plugin
//! error and exit code 3 -- in one more `CheckResult`.
//!
//! The check the CLI adds and the core cannot is the `recipient` one. It is
//! cheap -- parsing a string -- and turns a typo in the public key into an
//! immediate failure instead of into an artifact nobody will ever be able to
//! decrypt. With origin `config`, because what has to be fixed is in the file
//! and not in any plugin.

use sb_config::Target;
use sb_core::ops::doctor::{CheckResult, DoctorReport, run_doctor};
use sb_core::plugin::PluginClient;
use sb_crypto::Recipient;

use crate::commands::concurrency::in_batches;
use crate::context::Context;
use crate::error::CliError;
use crate::output::Report;
use crate::plugins::{self, Role};

/// Origin of the checks that come from the configuration and not from a plugin.
const ORIGIN_CONFIG: &str = "config";

/// # Errors
/// Returns [`CliError::Config`] if the target does not exist. Nothing else: a
/// plugin that does not start is a line of the report, not an error of this
/// command.
pub async fn run(ctx: &Context, target: Option<&str>) -> Result<Report, CliError> {
    let targets = ctx.targets(target)?;
    let reports = in_batches(targets, ctx.jobs, |t| diagnose(ctx, t)).await;

    let failed = reports.iter().filter(|i| !i.ok()).count();
    let report = compose(&reports, failed);

    if failed == 0 {
        return Ok(report);
    }
    // The report is **not** replaced by the error: the day `doctor` finds
    // problems is exactly the day its list is needed.
    Ok(report.with_failure(CliError::operation(format!(
        "{failed} of {} targets have problems:\n{}",
        reports.len(),
        failure_detail(&reports)
    ))))
}

/// Diagnoses a whole target, without letting anything abort.
async fn diagnose(ctx: &Context, target: &Target) -> DoctorReport {
    let mut checks = vec![check_recipient(target)];

    // The plugins are started one at a time and their failures are recorded:
    // here, a plugin that is not there is a finding, not an exception.
    let source = start(ctx, target, Role::Source, &mut checks).await;
    let storage = start(ctx, target, Role::Storage, &mut checks).await;

    if let (Some(source), Some(storage)) = (&source, &storage) {
        checks.extend(run_doctor(&target.name, source, storage).await.checks);
    }

    if let Some(source) = source {
        plugins::close(source).await;
    }
    if let Some(storage) = storage {
        plugins::close(storage).await;
    }

    DoctorReport {
        target: target.name.clone(),
        checks,
    }
}

/// Starts a plugin and records the outcome instead of propagating it.
async fn start(
    ctx: &Context,
    target: &Target,
    role: Role,
    checks: &mut Vec<CheckResult>,
) -> Option<PluginClient> {
    match plugins::start_for(ctx, target, role).await {
        Ok(client) => Some(client),
        Err(source) => {
            checks.push(CheckResult {
                origin: role.section().to_owned(),
                name: "startup".to_owned(),
                ok: false,
                detail: source.to_string(),
                remedy: "the plugin's diagnosis could not be run because the plugin never \
                         started: fix this first"
                    .to_owned(),
            });
            None
        }
    }
}

/// The only check that does not come from a plugin: that the public key things
/// are encrypted to really exists.
fn check_recipient(target: &Target) -> CheckResult {
    match Recipient::parse(&target.recipient) {
        Ok(_) => CheckResult {
            origin: ORIGIN_CONFIG.to_owned(),
            name: "recipient".to_owned(),
            ok: true,
            // The **public** key is shown: it is not a secret, and seeing it is
            // the only way to notice it belongs to another system.
            detail: target.recipient.clone(),
            remedy: String::new(),
        },
        Err(source) => CheckResult {
            origin: ORIGIN_CONFIG.to_owned(),
            name: "recipient".to_owned(),
            ok: false,
            detail: format!("`{}` is not a valid age key: {source}", target.recipient),
            remedy: format!(
                "fix `recipient` in target `{}`: it has to be the `age1...` public key that \
                 `age-keygen` printed. With an invalid key the backup cannot be encrypted, and \
                 with the wrong key it will never be decryptable",
                target.name
            ),
        },
    }
}

fn compose(reports: &[DoctorReport], failed: usize) -> Report {
    let mut lines = Vec::new();
    let mut json = Vec::with_capacity(reports.len());

    for report in reports {
        lines.push(format!(
            "{} - {}",
            report.target,
            if report.ok() { "ok" } else { "HAS PROBLEMS" }
        ));
        for check in &report.checks {
            let mark = if check.ok { "  ok " } else { "  x  " };
            lines.push(format!(
                "{mark}[{}] {}: {}",
                check.origin, check.name, check.detail
            ));
            if !check.ok && !check.remedy.is_empty() {
                lines.push(format!("       remedy: {}", check.remedy));
            }
        }

        json.push(serde_json::json!({
            "target": report.target,
            "ok": report.ok(),
            "source_version": report.source_version(),
            "checks": report.checks.iter().map(|c| serde_json::json!({
                "origin": c.origin,
                "name": c.name,
                "ok": c.ok,
                "detail": c.detail,
                "remedy": c.remedy,
            })).collect::<Vec<_>>(),
        }));
    }

    Report::new(
        lines.join("\n"),
        serde_json::json!({
            "command": "doctor",
            "total": reports.len(),
            "failed": failed,
            "targets": json,
        }),
    )
}

fn failure_detail(reports: &[DoctorReport]) -> String {
    reports
        .iter()
        .filter(|i| !i.ok())
        .flat_map(|i| {
            i.failures()
                .into_iter()
                .map(move |c| format!("  {} [{}] {}: {}", i.target, c.origin, c.name, c.detail))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target_with(recipient: &str) -> Target {
        Target {
            name: "prod".into(),
            source: "postgres".into(),
            storage: "r2".into(),
            recipient: recipient.into(),
            source_config: sb_config::ConfigTable::new(),
            storage_config: sb_config::ConfigTable::new(),
            compression_level: None,
            artifact_template: None,
            retention_days: None,
        }
    }

    #[test]
    fn a_valid_public_key_passes_the_check() {
        let public = sb_crypto::Identity::generate().to_recipient().to_string();
        let check = check_recipient(&target_with(&public));
        assert!(check.ok, "{}", check.detail);
        assert_eq!(check.origin, ORIGIN_CONFIG);
        assert_eq!(check.name, "recipient");
    }

    #[test]
    fn a_typo_in_the_public_key_is_detected_with_a_remedy() {
        // It is this check's whole reason: one extra letter here gives no error
        // until somebody tries to restore, and then there is nothing to be
        // done.
        let check = check_recipient(&target_with("age1this-is-not-a-key"));
        assert!(!check.ok);
        assert_eq!(check.origin, ORIGIN_CONFIG);
        assert!(
            check.remedy.contains("age-keygen"),
            "a check that fails without saying what to do is useless: {}",
            check.remedy
        );
        assert!(check.detail.contains("age1this-is-not-a-key"));
    }

    #[test]
    fn an_empty_recipient_also_fails() {
        assert!(!check_recipient(&target_with("")).ok);
    }

    #[test]
    fn the_json_report_carries_the_origin_of_each_check() {
        // A backup has two live plugins: "permission missing" without saying
        // from which forces guessing.
        let report = DoctorReport {
            target: "prod".into(),
            checks: vec![
                check_recipient(&target_with("not valid")),
                CheckResult {
                    origin: "storage".into(),
                    name: "bucket".into(),
                    ok: true,
                    detail: "exists".into(),
                    remedy: String::new(),
                },
            ],
        };
        let out = compose(std::slice::from_ref(&report), 1);
        assert_eq!(out.json["targets"][0]["checks"][0]["origin"], "config");
        assert_eq!(out.json["targets"][0]["checks"][1]["origin"], "storage");
        assert_eq!(out.json["targets"][0]["ok"], false);
        assert!(out.human.contains("remedy:"));
    }
}
