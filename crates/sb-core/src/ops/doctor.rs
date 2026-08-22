//! The `doctor` operation: finding out what is wrong **before** the backup.
//!
//! The other three operations abort at the first problem, and rightly so:
//! halfway through a dump there is nothing left to do. This one is the opposite,
//! and that is why it lives apart. `doctor` exists so that a two-hour backup does
//! not break at the ninety-minute mark over an expired credential, and for that
//! it has to report **everything** in one go: a plugin that does not answer is a
//! line of the report, not the end of the diagnosis. If it aborted, the user
//! would fix one problem only to discover the next one, once per attempt.
//!
//! Hence the signature: [`run_doctor`] does not return a `Result`. It is not that
//! its failures are ignored —each one ends up in the report, with its origin and
//! its remedy—, it is that there is none that stops the report from being
//! produced.

use crate::plugin::{Capability, PluginClient};

/// Name of the check that carries the source's version.
///
/// The engine reports it in its `Preflight` and a backup's manifest needs it, so
/// it travels as one more check instead of as a separate field: it is diagnostic
/// information —"which version of `PostgreSQL` am I talking to"— and the user
/// wants to see it in the report, not just the program.
const CHECK_SOURCE_VERSION: &str = "source version";

/// A check already performed, with its verdict and with **whose it is**.
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// "engine" or "storage": which plugin the check comes from.
    ///
    /// A backup has two live plugins at once; "missing permission" without
    /// saying which of the two forces you to guess.
    pub origin: String,
    pub name: String,
    pub ok: bool,
    /// What was seen: the path that does not exist, the error the server
    /// returned.
    pub detail: String,
    /// What to do to fix it. Empty if there is nothing to fix.
    pub remedy: String,
}

/// Everything that could be found out about a target, together.
#[derive(Debug, Clone)]
pub struct DoctorReport {
    pub target: String,
    pub checks: Vec<CheckResult>,
}

impl DoctorReport {
    /// A report **with no checks is not fine**: it means something never got to
    /// run.
    ///
    /// The alternative —`all()` over an empty list, which is true— would say
    /// "everything in order" without having looked at anything, and that is the
    /// only verdict worse than a failure: the user would go off to launch the
    /// backup with peace of mind.
    #[must_use]
    pub fn ok(&self) -> bool {
        !self.checks.is_empty() && self.checks.iter().all(|c| c.ok)
    }

    /// The checks that failed, **all of them**.
    #[must_use]
    pub fn failures(&self) -> Vec<&CheckResult> {
        self.checks.iter().filter(|c| !c.ok).collect()
    }

    /// Version of the source detected by the engine, if it reported one.
    #[must_use]
    pub fn server_version(&self) -> Option<&str> {
        self.checks
            .iter()
            .find(|c| c.origin == Capability::Engine.as_str() && c.name == CHECK_SOURCE_VERSION)
            .map(|c| c.detail.as_str())
    }
}

/// Runs the preflight of both plugins and joins the results.
///
/// **It never aborts because a plugin fails**: a plugin that does not respond is
/// a finding of the report, not an error of the operation. The user wants to see
/// everything that is wrong in one go.
///
/// The two are asked in series and not in parallel on purpose: they are two short
/// RPCs, gaining a few milliseconds does not make up for one plugin's messages
/// getting mixed with the other's in the log, and the report comes out with the
/// engine first, which is how it reads.
pub async fn run_doctor(
    target: &str,
    engine: &PluginClient,
    storage: &PluginClient,
) -> DoctorReport {
    let mut checks = Vec::new();
    interrogate(&mut checks, Capability::Engine, engine).await;
    interrogate(&mut checks, Capability::Storage, storage).await;

    DoctorReport {
        target: target.to_string(),
        checks,
    }
}

/// Asks a plugin for its preflight and dumps whatever it says —or whatever
/// fails— into the report.
async fn interrogate(checks: &mut Vec<CheckResult>, role: Capability, plugin: &PluginClient) {
    let origin = role.as_str();

    let response = match plugin.preflight().await {
        Ok(response) => response,
        Err(error) => {
            // This is where `doctor` parts ways with the other operations: this
            // `Err` does not leave the function, it becomes one more line.
            checks.push(CheckResult {
                origin: origin.to_string(),
                name: "preflight".to_string(),
                ok: false,
                detail: error.to_string(),
                remedy: format!(
                    "check that the plugin \"{}\" is installed, is executable and is still alive",
                    plugin.name()
                ),
            });
            return;
        }
    };

    if role == Capability::Engine && !response.server_version.is_empty() {
        checks.push(CheckResult {
            origin: origin.to_string(),
            name: CHECK_SOURCE_VERSION.to_string(),
            ok: true,
            detail: response.server_version,
            remedy: String::new(),
        });
    }

    let any_failed = response.checks.iter().any(|c| !c.ok);
    checks.extend(response.checks.into_iter().map(|c| CheckResult {
        origin: origin.to_string(),
        name: c.name,
        ok: c.ok,
        detail: c.detail,
        remedy: c.remediation,
    }));

    // A plugin that says "I am not well" without saying in what cannot slip
    // through as a clean report: without this, an `ok: false` with an empty list
    // of checks —or with all of them green— would make `doctor` give the go
    // ahead.
    if !response.ok && !any_failed {
        checks.push(CheckResult {
            origin: origin.to_string(),
            name: "verdict".to_string(),
            ok: false,
            detail: format!(
                "the plugin \"{}\" declares itself not ready but did not say which check fails",
                plugin.name()
            ),
            remedy:
                "look at the plugin's logs: the failure is there but it did not reach the report"
                    .to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(origin: &str, name: &str, ok: bool, remedy: &str) -> CheckResult {
        CheckResult {
            origin: origin.into(),
            name: name.into(),
            ok,
            detail: String::new(),
            remedy: remedy.into(),
        }
    }

    #[test]
    fn a_report_without_failures_is_ok() {
        let report = DoctorReport {
            target: "t".into(),
            checks: vec![
                check("engine", "binary", true, ""),
                check("storage", "bucket", true, ""),
            ],
        };
        assert!(report.ok());
        assert!(report.failures().is_empty());
    }

    #[test]
    fn a_single_failure_brings_the_report_down() {
        let report = DoctorReport {
            target: "t".into(),
            checks: vec![
                check("engine", "a", true, ""),
                check("storage", "b", false, "grant s3:PutObject"),
            ],
        };
        assert!(!report.ok());
        assert_eq!(report.failures().len(), 1);
        assert_eq!(report.failures()[0].remedy, "grant s3:PutObject");
    }

    #[test]
    fn an_empty_report_is_not_considered_correct() {
        // Zero checks means something never got to run, not that everything is
        // fine. A `doctor` that says "ok" without having checked anything is
        // worse than one that fails.
        let report = DoctorReport {
            target: "t".into(),
            checks: vec![],
        };
        assert!(!report.ok());
    }

    #[test]
    fn the_report_keeps_every_failure_not_just_the_first() {
        // The user wants to see everything that is wrong in one go, not fix one
        // problem to discover the next.
        let report = DoctorReport {
            target: "t".into(),
            checks: vec![
                check("engine", "a", false, "fix a"),
                check("engine", "b", false, "fix b"),
                check("storage", "c", false, "fix c"),
            ],
        };
        assert_eq!(report.failures().len(), 3);
    }

    #[test]
    fn the_failures_keep_which_plugin_they_come_from() {
        // In a backup there are two plugins; "missing permission" without saying
        // which one forces you to guess.
        let report = DoctorReport {
            target: "t".into(),
            checks: vec![check("storage", "permissions", false, "x")],
        };
        assert_eq!(report.failures()[0].origin, "storage");
    }
}
