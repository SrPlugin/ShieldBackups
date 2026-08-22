//! Model of `shieldbk`'s TOML configuration.
//!
//! Two decisions govern this module:
//!
//! 1. **`engine_config` and `storage_config` are opaque to the core.** The core
//!    does not know what a database port or a bucket is: it keeps those tables as
//!    generic key/value pairs ([`ConfigTable`]) and validates them later against
//!    the schema each plugin declares over gRPC. Encoding the fields of a
//!    specific engine here would mean recompiling the core to support a new
//!    plugin, which is exactly what the plugin architecture avoids.
//! 2. **A secret is never a literal.** A secret field is written as a reference
//!    to its origin ([`SecretRef`]), so the configuration file —which is kept
//!    under version control, copied and shared— contains no passwords.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

/// Minimum accepted compression level (zstd's).
const MIN_LEVEL: i32 = 1;
/// Maximum accepted compression level (zstd's).
const MAX_LEVEL: i32 = 22;

/// Default compression level.
///
/// Deliberately far from the maximum: compressing at 19 or 22 multiplies the CPU
/// time on the machine taking the dump —normally the same server that serves the
/// database— in exchange for a few percentage points of size. Whoever prefers the
/// opposite trade-off asks for it explicitly.
const DEFAULT_LEVEL: i32 = 6;

/// Origin of a secret. Never the secret itself.
///
/// The configuration file is an artifact that is kept in git, copied between
/// machines and shows up in error reports. A literal in there is a leak waiting
/// to happen, so the model simply does not accept one: it is only possible to say
/// *where* the secret is.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretRef {
    /// Environment variable of the `shieldbk` process.
    Env(String),
    /// File whose contents are the secret. Restrictive permissions are required.
    File(String),
    /// Entry of the system keyring, in `service/key` format.
    Keyring(String),
    /// Command and arguments separately: there is no shell, so there is no
    /// injection.
    Command(Vec<String>),
    /// Accepts open permissions and warns. It exists only for secrets mounted by
    /// an orchestrator: Docker uses 0444 in `/run/secrets` and Kubernetes 0644 by
    /// default. Rejecting them without an alternative would rule out the most
    /// common use case in a container; relaxing the check by default would be
    /// worse. The name is deliberately awkward.
    FileInsecure(String),
}

/// Any value inside an opaque plugin table.
///
/// The order of the variants is significant: with `untagged`, serde tries them
/// one after another and keeps the first that fits. [`SecretRef`] goes first so
/// that a table such as `{ env = "PGPASSWORD" }` is recognized as a secret
/// reference and not as just another structured value.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum ConfigValue {
    /// Reference to the origin of a secret.
    Secret(SecretRef),
    /// Literal boolean.
    Bool(bool),
    /// Literal integer.
    Int(i64),
    /// Literal string.
    String(String),
    /// List of strings. A bare array lands here; one inside
    /// `{ command = [...] }` is recognized earlier as [`SecretRef::Command`].
    List(Vec<String>),
}

/// A configuration table that is opaque to the core, validated later against the
/// schema declared by the corresponding plugin.
pub type ConfigTable = BTreeMap<String, ConfigValue>;

/// Where the plugins and their lockfile live.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PluginsConfig {
    /// Directory where plugin binaries are looked for.
    pub dir: String,
    /// File with the hashes of the authorized binaries.
    pub lockfile: String,
}

impl Default for PluginsConfig {
    fn default() -> Self {
        Self {
            dir: "~/.shieldbk/plugins".to_owned(),
            lockfile: "~/.shieldbk/plugins.lock".to_owned(),
        }
    }
}

/// Values applied to every target that does not override them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Defaults {
    /// Global compression level, in `1..=22`.
    pub compression_level: i32,
    /// Template of the artifact's key in the destination.
    pub artifact_template: String,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            compression_level: DEFAULT_LEVEL,
            artifact_template:
                "{target}/{yyyy}/{mm}/{dd}/{target}-{timestamp}-{engine}.dump.zst.age".to_owned(),
        }
    }
}

/// A database to back up, with its engine and its storage.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Name of the target. It is used as part of the artifact's key.
    pub name: String,
    /// Name of the engine plugin (`postgres`, `mysql`, …). The core does not
    /// interpret this value: it only uses it to locate the plugin.
    pub engine: String,
    /// Name of the storage plugin. Just as opaque as `engine`.
    pub storage: String,
    /// age public key the backup is encrypted to.
    pub recipient: String,
    /// Configuration of the engine plugin. Opaque here.
    #[serde(default)]
    pub engine_config: ConfigTable,
    /// Configuration of the storage plugin. Opaque here.
    #[serde(default)]
    pub storage_config: ConfigTable,
    /// Its own compression level; if absent, [`Defaults`]' one wins.
    #[serde(default)]
    pub compression_level: Option<i32>,
    /// Its own template; if absent, [`Defaults`]' one wins.
    #[serde(default)]
    pub artifact_template: Option<String>,
}

impl Target {
    /// Compression level that will be applied: the target's if it defines one,
    /// otherwise the global one.
    #[must_use]
    pub fn effective_level(&self, defaults: &Defaults) -> i32 {
        self.compression_level.unwrap_or(defaults.compression_level)
    }

    /// Artifact template that will be applied: the target's if it defines one,
    /// otherwise the global one.
    #[must_use]
    pub fn effective_template<'a>(&'a self, defaults: &'a Defaults) -> &'a str {
        self.artifact_template
            .as_deref()
            .unwrap_or(&defaults.artifact_template)
    }
}

/// The complete configuration of `shieldbk`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where the plugins are.
    #[serde(default)]
    pub plugins: PluginsConfig,
    /// Global values.
    #[serde(default)]
    pub defaults: Defaults,
    /// The declared targets, in file order.
    #[serde(rename = "target", default)]
    pub targets: Vec<Target>,
}

/// What can go wrong while reading a configuration.
///
/// Every variant names the offending element: whoever receives the error has to
/// be able to go to the file and fix it without guessing.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The text is not valid TOML or does not match the model.
    #[error("the configuration is not valid TOML: {0}")]
    InvalidToml(Box<toml::de::Error>),

    /// Two targets share a name.
    #[error(
        "there are two targets called \"{name}\". The name identifies the target on the command \
         line and is part of the artifact's key, so it has to be unique"
    )]
    DuplicateName {
        /// The repeated name.
        name: String,
    },

    /// There is no target to back up.
    #[error(
        "the configuration declares no target: add at least one `[[target]]` block with `name`, \
         `engine`, `storage` and `recipient`"
    )]
    NoTargets,

    /// A value is outside the accepted range.
    #[error("the value of \"{field}\" in {location} is not valid ({value}): {reason}")]
    InvalidValue {
        /// Name of the field.
        field: String,
        /// Where it appears: `[defaults]` or the specific target.
        location: String,
        /// The rejected value.
        value: String,
        /// Why it is rejected.
        reason: String,
    },

    /// A target's name cannot be used in an artifact's key.
    #[error("the target name \"{name}\" is not valid: {reason}")]
    InvalidName {
        /// The rejected name.
        name: String,
        /// Why it is rejected.
        reason: String,
    },
}

impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self {
        Self::InvalidToml(Box::new(e))
    }
}

impl Config {
    /// Reads a configuration from TOML text and validates it.
    ///
    /// The validation done here is the one the core can do on its own: usable
    /// target names, uniqueness, compression ranges. Whatever is inside
    /// `engine_config` and `storage_config` is left untouched: that is validated
    /// against the schema each plugin declares.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidToml`] if the text is not valid TOML, is
    /// missing a mandatory field or carries an unknown one;
    /// [`ConfigError::NoTargets`] if there is no `[[target]]` —the commands that
    /// back nothing up use [`Config::parse_without_requiring_targets`]—;
    /// [`ConfigError::DuplicateName`] or [`ConfigError::InvalidName`] if the
    /// target names are unusable, and [`ConfigError::InvalidValue`] if a
    /// compression level is outside `1..=22`.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config = Self::parse_without_requiring_targets(text)?;
        if config.targets.is_empty() {
            return Err(ConfigError::NoTargets);
        }
        Ok(config)
    }

    /// The same as [`Config::parse`] but **without** requiring any target.
    ///
    /// It exists for the commands that only need the `[plugins]` section:
    /// registering, verifying or listing plugin binaries has nothing to do with
    /// which databases are backed up, and in fact it is what is done *before*
    /// deciding that —when installing, or when building an image—. Requiring a
    /// `[[target]]` there would force inventing one with a fake `recipient`.
    ///
    /// Everything else is validated the same. Whoever is actually going to back
    /// something up calls [`Config::parse`], which is the one that requires
    /// targets.
    ///
    /// # Errors
    ///
    /// The same as [`Config::parse`] minus [`ConfigError::NoTargets`].
    pub fn parse_without_requiring_targets(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text)?;

        validate_level(config.defaults.compression_level, "[defaults]")?;

        let mut seen = BTreeSet::new();
        for target in &config.targets {
            validate_name(&target.name)?;
            if !seen.insert(target.name.as_str()) {
                return Err(ConfigError::DuplicateName {
                    name: target.name.clone(),
                });
            }
            if let Some(level) = target.compression_level {
                validate_level(level, &format!("the target \"{}\"", target.name))?;
            }
        }

        tracing::debug!(targets = config.targets.len(), "configuration loaded");
        Ok(config)
    }

    /// Looks up a target by its name.
    #[must_use]
    pub fn target(&self, name: &str) -> Option<&Target> {
        self.targets.iter().find(|t| t.name == name)
    }
}

/// Checks that a compression level is within zstd's range.
fn validate_level(level: i32, location: &str) -> Result<(), ConfigError> {
    if (MIN_LEVEL..=MAX_LEVEL).contains(&level) {
        return Ok(());
    }
    Err(ConfigError::InvalidValue {
        field: "compression_level".to_owned(),
        location: location.to_owned(),
        value: level.to_string(),
        reason: format!("zstd only accepts levels from {MIN_LEVEL} to {MAX_LEVEL}"),
    })
}

/// Checks that a target name can be part of an artifact's key without surprises.
///
/// The name ends up concatenated into a path on the remote destination. A slash
/// would create hierarchy where none was expected, `..` could escape the target's
/// prefix when writing to a file-system destination, and a null byte truncates
/// strings in any underlying C API.
fn validate_name(name: &str) -> Result<(), ConfigError> {
    let reason = if name.is_empty() {
        "it cannot be empty"
    } else if name.contains('/') || name.contains('\\') {
        "it cannot contain slashes: the name is part of the artifact's key"
    } else if name.contains("..") {
        "it cannot contain \"..\": it could escape the target's prefix in the destination"
    } else if name.contains('\0') {
        "it cannot contain null bytes"
    } else {
        return Ok(());
    };
    Err(ConfigError::InvalidName {
        name: name.to_owned(),
        reason: reason.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
[plugins]
dir = "~/.shieldbk/plugins"
lockfile = "~/.shieldbk/plugins.lock"

[defaults]
compression_level = 6
artifact_template = "{target}/{yyyy}/{mm}/{dd}/{target}-{timestamp}-{engine}.dump.zst.age"

[[target]]
name = "production"
engine = "postgres"
storage = "r2"
recipient = "age1qqqqqqqqqq"

[target.engine_config]
host = "db.internal"
port = 5432
ssl = true
password = { env = "PGPASSWORD" }

[target.storage_config]
bucket = "backups"
secret_access_key = { keyring = "shieldbk/r2" }
"#;

    #[test]
    fn parses_a_complete_configuration() {
        let c = Config::parse(EXAMPLE).unwrap();
        assert_eq!(c.targets.len(), 1);
        assert_eq!(c.targets[0].name, "production");
        assert_eq!(c.targets[0].engine, "postgres");
        assert_eq!(c.targets[0].storage, "r2");
        assert_eq!(c.defaults.compression_level, 6);
    }

    #[test]
    fn literal_values_and_references_live_side_by_side() {
        let c = Config::parse(EXAMPLE).unwrap();
        let ec = &c.targets[0].engine_config;
        assert!(matches!(ec.get("host"), Some(ConfigValue::String(s)) if s == "db.internal"));
        assert!(matches!(ec.get("port"), Some(ConfigValue::Int(5432))));
        assert!(matches!(ec.get("ssl"), Some(ConfigValue::Bool(true))));
        assert!(
            matches!(ec.get("password"), Some(ConfigValue::Secret(SecretRef::Env(v))) if v == "PGPASSWORD")
        );
    }

    #[test]
    fn recognizes_the_five_secret_sources() {
        let toml = r#"
[[target]]
name = "t"
engine = "e"
storage = "s"
recipient = "age1x"
[target.engine_config]
a = { env = "A" }
b = { file = "/path/b" }
c = { keyring = "service/c" }
d = { command = ["vault", "read", "x"] }
e = { file_insecure = "/run/secrets/e" }
"#;
        let c = Config::parse(toml).unwrap();
        let ec = &c.targets[0].engine_config;
        assert!(matches!(
            ec.get("a"),
            Some(ConfigValue::Secret(SecretRef::Env(_)))
        ));
        assert!(matches!(
            ec.get("b"),
            Some(ConfigValue::Secret(SecretRef::File(_)))
        ));
        assert!(matches!(
            ec.get("c"),
            Some(ConfigValue::Secret(SecretRef::Keyring(_)))
        ));
        assert!(matches!(
            ec.get("d"),
            Some(ConfigValue::Secret(SecretRef::Command(_)))
        ));
        assert!(matches!(
            ec.get("e"),
            Some(ConfigValue::Secret(SecretRef::FileInsecure(_)))
        ));
    }

    #[test]
    fn a_list_of_strings_is_not_mistaken_for_a_command() {
        // `command` is an array of strings, just like a normal list. The
        // difference is being inside a table with that key.
        let toml = r#"
[[target]]
name = "t"
engine = "e"
storage = "s"
recipient = "age1x"
[target.engine_config]
exclusions = ["table_a", "table_b"]
"#;
        let c = Config::parse(toml).unwrap();
        assert!(matches!(
            c.targets[0].engine_config.get("exclusions"),
            Some(ConfigValue::List(v)) if v.len() == 2
        ));
    }

    #[test]
    fn two_targets_with_the_same_name_are_rejected() {
        let toml = r#"
[[target]]
name = "dup"
engine = "e"
storage = "s"
recipient = "age1x"
[[target]]
name = "dup"
engine = "e"
storage = "s"
recipient = "age1x"
"#;
        let err = Config::parse(toml).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateName { .. }));
        assert!(
            err.to_string().contains("dup"),
            "it must name the duplicate"
        );
    }

    #[test]
    fn a_configuration_without_targets_is_rejected() {
        assert!(matches!(
            Config::parse("[plugins]\ndir = \"/x\"").unwrap_err(),
            ConfigError::NoTargets
        ));
    }

    #[test]
    fn without_requiring_targets_a_plugins_only_config_is_valid() {
        // Installing plugins comes before deciding what is backed up: whoever is
        // only going to seal the lockfile does not have to invent a target.
        let c = Config::parse_without_requiring_targets("[plugins]\ndir = \"/opt/sb\"").unwrap();
        assert!(c.targets.is_empty());
        assert_eq!(c.plugins.dir, "/opt/sb");
    }

    #[test]
    fn without_requiring_targets_the_rest_of_the_validation_still_holds() {
        // The only thing relaxed is the requirement of targets. A badly written
        // target is still rejected the same.
        for bad in [
            "[defaults]\ncompression_level = 99\n",
            "[[target]]\nname = \"with/slash\"\nengine = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\n",
            "this is not toml [[[",
        ] {
            assert!(
                Config::parse_without_requiring_targets(bad).is_err(),
                "\"{bad}\" should be rejected just as in `parse`"
            );
        }
    }

    #[test]
    fn a_target_without_a_recipient_is_rejected() {
        // Without a public key nothing can be encrypted, and an unencrypted
        // backup is not what this tool promises.
        let toml = "[[target]]\nname = \"t\"\nengine = \"e\"\nstorage = \"s\"\n";
        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn the_global_compression_level_is_validated() {
        let toml = format!("[defaults]\ncompression_level = 99\n{EXAMPLE_TARGET}");
        assert!(matches!(
            Config::parse(&toml).unwrap_err(),
            ConfigError::InvalidValue { .. }
        ));
    }

    #[test]
    fn the_per_target_compression_level_is_validated() {
        let toml = "[[target]]\nname = \"t\"\nengine = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\ncompression_level = 0\n";
        let err = Config::parse(toml).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
        assert!(err.to_string().contains('t'), "it must say in which target");
    }

    const EXAMPLE_TARGET: &str = r#"
[[target]]
name = "t"
engine = "e"
storage = "s"
recipient = "age1x"
"#;

    #[test]
    fn a_target_is_looked_up_by_name() {
        let c = Config::parse(EXAMPLE).unwrap();
        assert!(c.target("production").is_some());
        assert!(c.target("does-not-exist").is_none());
    }

    #[test]
    fn the_target_level_beats_the_global_one() {
        let toml = "[defaults]\ncompression_level = 3\n[[target]]\nname = \"t\"\nengine = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\ncompression_level = 19\n";
        let c = Config::parse(toml).unwrap();
        assert_eq!(c.targets[0].effective_level(&c.defaults), 19);
    }

    #[test]
    fn without_a_level_in_the_target_the_global_one_is_used() {
        let c = Config::parse(EXAMPLE).unwrap();
        assert_eq!(c.targets[0].effective_level(&c.defaults), 6);
    }

    #[test]
    fn the_target_template_beats_the_global_one() {
        let toml = "[[target]]\nname = \"t\"\nengine = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\nartifact_template = \"own\"\n";
        let c = Config::parse(toml).unwrap();
        assert_eq!(c.targets[0].effective_template(&c.defaults), "own");
    }

    #[test]
    fn the_default_values_are_reasonable() {
        let c = Config::parse(EXAMPLE_TARGET).unwrap();
        assert!(
            (1..=9).contains(&c.defaults.compression_level),
            "the default level must be fast, not maximal"
        );
        assert!(c.defaults.artifact_template.contains("{target}"));
        assert!(c.plugins.dir.contains("plugins"));
    }

    #[test]
    fn an_invalid_toml_is_an_error_and_not_a_panic() {
        assert!(matches!(
            Config::parse("this is not toml [[[").unwrap_err(),
            ConfigError::InvalidToml(_)
        ));
    }

    #[test]
    fn an_unknown_field_in_a_target_is_rejected() {
        // A typo in a field name cannot be ignored in silence: the user would
        // believe they had configured something that is not in effect.
        let toml = "[[target]]\nname = \"t\"\nengine = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\ncompresion_level = 5\n";
        assert!(
            Config::parse(toml).is_err(),
            "an unknown field must be rejected"
        );
    }

    #[test]
    fn target_names_cannot_be_empty_nor_carry_slashes() {
        // The target's name goes into the artifact's key: a slash or an empty
        // name would produce absurd or unsafe paths in the destination.
        for bad in ["", "with/slash", "..", "with space/and slash"] {
            let toml = format!(
                "[[target]]\nname = \"{bad}\"\nengine = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\n"
            );
            assert!(
                Config::parse(&toml).is_err(),
                "\"{bad}\" should be rejected"
            );
        }
    }
}
