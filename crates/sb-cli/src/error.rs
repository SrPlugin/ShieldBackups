//! The CLI's error and, with it, the code the process ends with.
//!
//! A script calling `shieldbk` from a `cron` needs to react differently
//! depending on **what** failed: a badly written configuration is fixed by
//! editing a file and there is no point retrying it, an altered plugin is a
//! security incident, and a backup that breaks halfway can probably be repeated
//! in an hour. A single "it went wrong" would force all of them to read the
//! message, which is exactly what a program should not have to do.
//!
//! That is why this enum has exactly three variants and not one per kind of
//! core error: the classes are the ones a script can tell apart, not the ones
//! the code produces. The full detail goes inside the message.

use sb_config::{ConfigError, ValidationError};
use sb_core::lockfile::LockfileError;
use sb_core::naming::NamingError;
use sb_core::ops::BackupError;
use sb_core::plugin::PluginError;
use sb_crypto::AgeError;

/// The configuration is unusable: it is missing, unreadable or says something
/// impossible.
pub const EXIT_CONFIG: i32 = 2;
/// A plugin could not be used: it is not there, it is not registered, or it
/// changed.
pub const EXIT_PLUGIN: i32 = 3;
/// The operation failed: the dump, the upload, the download or the diagnosis.
pub const EXIT_OPERATION: i32 = 4;

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Nothing got to run because what was asked for makes no sense.
    #[error("{0}")]
    Config(String),
    /// The plugin could not be started, or should not have been.
    #[error("{0}")]
    Plugin(String),
    /// Everything was in place and the operation failed anyway.
    #[error("{0}")]
    Operation(String),
}

impl CliError {
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    pub fn plugin(message: impl Into<String>) -> Self {
        Self::Plugin(message.into())
    }

    pub fn operation(message: impl Into<String>) -> Self {
        Self::Operation(message.into())
    }

    /// The code the process ends with.
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Self::Config(_) => EXIT_CONFIG,
            Self::Plugin(_) => EXIT_PLUGIN,
            Self::Operation(_) => EXIT_OPERATION,
        }
    }

    /// The class name, for the JSON. It is the same fact as the code, but
    /// readable: `jq '.class'` is clearer than memorising that 3 means plugin.
    #[must_use]
    pub fn class(&self) -> &'static str {
        match self {
            Self::Config(_) => "config",
            Self::Plugin(_) => "plugin",
            Self::Operation(_) => "operation",
        }
    }

    /// A copy with the same class and the same message.
    ///
    /// `CliError` is deliberately not `Clone`: an error is propagated, not
    /// duplicated. The two exceptions are real and bounded -- emitting it on
    /// the output and grouping several targets' errors without taking them out
    /// of the report -- and having the copy here keeps each of them from
    /// writing its own `match`.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        match self {
            Self::Config(m) => Self::Config(m.clone()),
            Self::Plugin(m) => Self::Plugin(m.clone()),
            Self::Operation(m) => Self::Operation(m.clone()),
        }
    }

    /// Joins several targets' failures into a single one.
    ///
    /// The class is kept **only if they all agree**. With a single target that
    /// means an unregistered plugin exits with the plugin code, which is what a
    /// script needs in order not to retry something that will never fix itself.
    /// With several targets failing for different reasons there is no class
    /// that represents them, and pretending there is would be worse than saying
    /// "the operation failed": it would send the script off to fix the wrong
    /// thing.
    ///
    /// With an empty list there is nothing to group and it returns `None`.
    #[must_use]
    pub fn group(message: impl Into<String>, failures: &[Self]) -> Option<Self> {
        let first = failures.first()?.class();
        let message = message.into();
        if failures.iter().all(|f| f.class() == first) {
            Some(match failures[0] {
                Self::Config(_) => Self::Config(message),
                Self::Plugin(_) => Self::Plugin(message),
                Self::Operation(_) => Self::Operation(message),
            })
        } else {
            Some(Self::Operation(message))
        }
    }
}

impl From<ConfigError> for CliError {
    fn from(e: ConfigError) -> Self {
        Self::Config(format!("the configuration could not be used: {e}"))
    }
}

impl From<ValidationError> for CliError {
    fn from(e: ValidationError) -> Self {
        // Validating against the plugin's schema is late in time but early in
        // cause: what is wrong is the configuration file, so the exit code has
        // to be the configuration one even though a plugin had to be started to
        // discover it.
        Self::Config(e.to_string())
    }
}

impl From<NamingError> for CliError {
    fn from(e: NamingError) -> Self {
        Self::Config(e.to_string())
    }
}

impl From<AgeError> for CliError {
    fn from(e: AgeError) -> Self {
        Self::Config(e.to_string())
    }
}

impl From<LockfileError> for CliError {
    fn from(e: LockfileError) -> Self {
        // The message from `sb-core::lockfile` already says what to do --
        // including the `shieldbk plugin lock` that has to be typed --
        // so it is not wrapped in anything: wrapping it would only push it away
        // from the eye.
        Self::Plugin(e.to_string())
    }
}

impl From<PluginError> for CliError {
    fn from(e: PluginError) -> Self {
        Self::Plugin(e.to_string())
    }
}

impl From<BackupError> for CliError {
    fn from(e: BackupError) -> Self {
        // A `BackupError` arrives once the operation was already under way,
        // including those of its own that wrap a `PluginError`: for whoever
        // retries, the relevant fact is that the backup is not there.
        Self::Operation(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_class_has_its_own_code() {
        // It is this module's whole reason to exist: a script must be able to
        // tell "fix the TOML" from "try again".
        assert_eq!(CliError::config("x").code(), EXIT_CONFIG);
        assert_eq!(CliError::plugin("x").code(), EXIT_PLUGIN);
        assert_eq!(CliError::operation("x").code(), EXIT_OPERATION);

        let codes = [EXIT_CONFIG, EXIT_PLUGIN, EXIT_OPERATION];
        assert!(!codes.contains(&0), "no error class can exit successfully");
    }

    #[test]
    fn a_lockfile_that_does_not_add_up_is_a_plugin_error_and_keeps_its_remedy() {
        let error = CliError::from(LockfileError::NotRegistered {
            name: "postgres".into(),
            path: "/opt/sb-plugin-postgres".into(),
        });
        assert_eq!(error.code(), EXIT_PLUGIN);
        assert!(
            error.to_string().contains("plugin lock"),
            "the core's remedy has to arrive intact: {error}"
        );
    }

    #[test]
    fn grouping_a_single_failure_keeps_its_class() {
        // The case that matters: one target, one unregistered plugin. The
        // script has to see a 3 and not retry something that will never fix
        // itself.
        let grouped = CliError::group("1 of 1 failed", &[CliError::plugin("not registered")]);
        assert_eq!(grouped.map(|e| e.code()), Some(EXIT_PLUGIN));
    }

    #[test]
    fn grouping_failures_of_the_same_class_keeps_it() {
        let grouped = CliError::group("2 of 2", &[CliError::plugin("a"), CliError::plugin("b")]);
        assert_eq!(grouped.map(|e| e.code()), Some(EXIT_PLUGIN));
    }

    #[test]
    fn grouping_different_classes_falls_back_to_the_general_one() {
        // There is no class that represents "one because of the TOML and
        // another because of the network": pretending there is would send the
        // script off to fix the wrong thing.
        let grouped = CliError::group("2 of 3", &[CliError::config("a"), CliError::operation("b")]);
        assert_eq!(grouped.map(|e| e.code()), Some(EXIT_OPERATION));
    }

    #[test]
    fn grouping_no_failures_does_not_invent_one() {
        assert!(CliError::group("nothing", &[]).is_none());
    }

    #[test]
    fn a_validation_failure_counts_as_configuration() {
        // A live plugin is needed to discover it, but what has to be fixed is
        // the file: retrying will not change it.
        let error = CliError::from(ValidationError::MissingRequiredField {
            section: "source".into(),
            field: "host".into(),
        });
        assert_eq!(error.code(), EXIT_CONFIG);
        assert_eq!(error.class(), "config");
    }
}
