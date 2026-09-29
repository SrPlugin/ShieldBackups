//! How the result is told: to a person or to a program.
//!
//! The two formats are not two styles of the same text, they are two different
//! contracts. The human one may change between versions without warning; the
//! JSON one may not, because there is a `jq` pointed at it. And there is one
//! rule that binds them and that this module is in charge of upholding: **in
//! `--format json`, standard output contains a single JSON document and
//! nothing else**, even when the command fails. A script that cannot parse the
//! output of a failure is left not knowing what happened exactly when it needs
//! it most.
//!
//! Hence [`Report`] can carry a failure inside instead of having to choose
//! between report **or** error. It is the difference between a `doctor` that
//! says "there are problems" and one that says which: if the failure replaced
//! the report, the command whose job is to enumerate problems would lose its
//! output on exactly the day it finds any.

use std::io::Write as _;

use crate::error::CliError;

/// What a command has to tell, in both languages at once.
///
/// The two are built together and not one from the other: deriving the text
/// from the JSON would give telegraphic sentences, and deriving the JSON from
/// the text would be guesswork. Each command knows what to highlight in each
/// case.
pub struct Report {
    /// What a person reads. No trailing newline: emission adds it.
    pub human: String,
    /// What a program reads. The verdict is added to it on emission.
    pub json: serde_json::Value,
    /// The failure, if the command did its job and what it found was bad.
    pub failure: Option<CliError>,
}

impl Report {
    pub fn new(human: impl Into<String>, json: serde_json::Value) -> Self {
        Self {
            human: human.into(),
            json,
            failure: None,
        }
    }

    /// The same report, but with a negative verdict.
    #[must_use]
    pub fn with_failure(mut self, failure: CliError) -> Self {
        self.failure = Some(failure);
        self
    }

    /// The code the process ends with: zero if there was no failure.
    #[must_use]
    pub fn code(&self) -> i32 {
        self.failure.as_ref().map_or(0, CliError::code)
    }
}

/// The two output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "lower")]
pub enum Format {
    /// Text to read.
    Human,
    /// One JSON document per run.
    Json,
}

/// The result emitter.
pub struct Output {
    format: Format,
}

impl Output {
    #[must_use]
    pub fn new(format: Format) -> Self {
        Self { format }
    }

    /// Emits a report, with or without a failure inside.
    ///
    /// In human mode the text goes to stdout and the failure to stderr, which
    /// is where a person looks for it and where it does not pollute whatever
    /// might have gone down the pipe. In JSON mode everything goes into
    /// stdout's single document, because there the contract is that stdout
    /// **always** carries it: a script that had to read stderr to learn about a
    /// failure would be reading unformatted text, which is exactly what it
    /// asked to avoid.
    pub fn emit(&self, report: &Report) {
        match self.format {
            Format::Human => {
                if !report.human.is_empty() {
                    println!("{}", report.human);
                }
                if let Some(failure) = &report.failure {
                    let mut err = std::io::stderr().lock();
                    let _ = writeln!(err, "error: {failure}");
                }
            }
            Format::Json => write_json(&document(report)),
        }
    }

    /// Emits a failure that happened **before** there was anything to report.
    ///
    /// That is the case of a configuration that cannot be read: no command got
    /// as far as producing a report, but stdout's contract in JSON mode still
    /// stands.
    pub fn failure(&self, error: &CliError) {
        self.emit(&Report::new("", serde_json::json!({})).with_failure(error.duplicate()));
    }
}

/// The JSON document `--format json` prints for `report`: the command's own
/// body with the verdict added.
///
/// It is also what a notifier is handed, so that what a plugin reads and what a
/// script pipes into `jq` are the same thing and cannot drift apart.
#[must_use]
pub fn document(report: &Report) -> serde_json::Value {
    wrap(report.json.clone(), report.failure.as_ref())
}

/// Adds the verdict -- and the failure, if there is one -- to the command's
/// document.
///
/// `ok` goes at the root and always, even when the command already tells its
/// own story: it is the first thing a script looks at and it should not have to
/// learn a different field per command.
fn wrap(body: serde_json::Value, failure: Option<&CliError>) -> serde_json::Value {
    let mut document = match body {
        serde_json::Value::Object(map) => map,
        other => {
            let mut map = serde_json::Map::new();
            map.insert("result".into(), other);
            map
        }
    };
    document.insert("ok".into(), serde_json::Value::Bool(failure.is_none()));
    if let Some(failure) = failure {
        document.insert("class".into(), failure.class().into());
        document.insert("code".into(), failure.code().into());
        document.insert("error".into(), failure.to_string().into());
    }
    serde_json::Value::Object(document)
}

/// Writes the document and **nothing else** to standard output.
///
/// Serialising cannot fail with the values built here, but if it did, what it
/// must not do is stay quiet: an empty stdout in JSON mode breaks the script
/// without telling it why.
fn write_json(document: &serde_json::Value) {
    let text = serde_json::to_string(document).unwrap_or_else(|source| {
        format!(
            r#"{{"ok":false,"class":"operation","error":"could not serialise the output: {source}"}}"#
        )
    });
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{text}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_verdict_is_added_to_the_documents_root() {
        let document = wrap(serde_json::json!({ "targets": [] }), None);
        assert_eq!(document["ok"], serde_json::Value::Bool(true));
        assert!(
            document["targets"].is_array(),
            "and it does not clobber what was there"
        );
        assert!(document.get("error").is_none());
    }

    #[test]
    fn a_report_with_a_failure_keeps_its_content_as_well_as_the_error() {
        // That is `doctor`'s case: the day it finds problems is exactly the day
        // its report is needed.
        let failure = CliError::operation("2 of 3 targets have problems");
        let document = wrap(serde_json::json!({ "targets": [1, 2, 3] }), Some(&failure));
        assert_eq!(document["ok"], serde_json::Value::Bool(false));
        assert_eq!(document["class"], "operation");
        assert_eq!(document["code"], 4);
        assert_eq!(document["targets"].as_array().map(Vec::len), Some(3));
    }

    #[test]
    fn a_body_that_is_not_an_object_is_wrapped_all_the_same() {
        // A script has to be able to look at `.ok` without knowing which
        // command ran.
        let document = wrap(serde_json::json!("loose text"), None);
        assert_eq!(document["ok"], serde_json::Value::Bool(true));
        assert_eq!(document["result"], "loose text");
    }

    #[test]
    fn the_code_of_a_report_without_a_failure_is_zero() {
        let report = Report::new("all good", serde_json::json!({}));
        assert_eq!(report.code(), 0);
        assert_eq!(
            report.with_failure(CliError::plugin("x")).code(),
            crate::error::EXIT_PLUGIN
        );
    }
}
