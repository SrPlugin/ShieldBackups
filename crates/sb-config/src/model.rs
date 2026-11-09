//! Model of `shieldbk`'s TOML configuration.
//!
//! Three decisions govern this module:
//!
//! 1. **`source_config` and `storage_config` are opaque to the core.** The core
//!    does not know what a database port or a bucket is: it keeps those tables as
//!    generic key/value pairs ([`ConfigTable`]) and validates them later against
//!    the schema each plugin declares over gRPC. Encoding the fields of a
//!    specific plugin here would mean recompiling the core to support a new
//!    plugin, which is exactly what the plugin architecture avoids.
//! 2. **A secret is never a literal.** A secret field is written as a reference
//!    to its origin ([`SecretRef`]), so the configuration file —which is kept
//!    under version control, copied and shared— contains no passwords.
//! 3. **The role is called `source`, with no alias for the old `engine`.** The
//!    keys were `engine` and `engine_config` up to 0.1.0. They were renamed
//!    outright rather than accepted under `#[serde(alias = "engine")]`, and the
//!    reason is that [`Target`] carries `deny_unknown_fields`: this model has
//!    already decided that a name it does not recognize is an error, never
//!    something to swallow. An alias would be the one exception to that rule,
//!    and it would be permanent — an alias is a promise you keep, test and
//!    document forever, and documenting two spellings teaches every new reader
//!    that both exist. Renaming outright costs an old configuration one loud,
//!    precise error naming the offending key; keeping the alias would cost
//!    every future reader an ambiguity. The same argument applies to the
//!    `{source}` placeholder in [`Defaults::artifact_template`], whose error
//!    already lists the valid placeholders.

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
    /// How many days an artifact is kept before `storage prune` deletes it.
    ///
    /// `None` by default: deleting a backup is destructive, so a target that
    /// never opted in keeps every artifact forever instead of silently losing
    /// one to a config a future reader never noticed.
    pub retention_days: Option<u32>,
    /// Grandfather-father-son alternative to [`Defaults::retention_days`].
    /// Naming both is a configuration error.
    pub retention: Option<GfsRetention>,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            compression_level: DEFAULT_LEVEL,
            artifact_template:
                "{target}/{yyyy}/{mm}/{dd}/{target}-{timestamp}-{source}.dump.zst.age".to_owned(),
            retention_days: None,
            retention: None,
        }
    }
}

/// How many artifacts a grandfather-father-son retention keeps for each kind
/// of period. `0` -- or leaving the key out -- means that period is not used.
///
/// For every period, the **newest artifact of each of the `keep_*` most recent
/// periods that have one** is kept, and an artifact kept by any of them is kept.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GfsRetention {
    /// Newest artifact of each of this many most recent days (UTC).
    pub keep_daily: u32,
    /// Newest artifact of each of this many most recent ISO weeks.
    pub keep_weekly: u32,
    /// Newest artifact of each of this many most recent months.
    pub keep_monthly: u32,
    /// Newest artifact of each of this many most recent years.
    pub keep_yearly: u32,
}

impl GfsRetention {
    /// Whether it keeps nothing at all, which would delete every artifact.
    #[must_use]
    pub fn keeps_nothing(&self) -> bool {
        self.keep_daily == 0
            && self.keep_weekly == 0
            && self.keep_monthly == 0
            && self.keep_yearly == 0
    }
}

/// What `storage prune` keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retention {
    /// Everything younger than this many days.
    Days(u32),
    /// A grandfather-father-son schedule.
    Gfs(GfsRetention),
}

impl Retention {
    /// The retention a `retention_days` / `[retention]` pair means. Validation
    /// guarantees that at most one of them is set.
    fn from_parts(days: Option<u32>, gfs: Option<GfsRetention>) -> Option<Self> {
        days.map(Self::Days).or(gfs.map(Self::Gfs))
    }
}

/// How a target proves its backups restore: the question to ask after
/// restoring into a disposable place, and, if the default will not do, where
/// that place is.
///
/// The core does not know what a database is, so it cannot run the question. It
/// hands `check` to the source plugin, which does -- see the `Drill` service in
/// the protocol -- and `source_config` is how an operator points that plugin at
/// somewhere other than the production database (a staging server with a role
/// that may create databases, say).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Drill {
    /// What to ask once the artifact is restored. Opaque here: for a SQL source
    /// it is a query that has to return `true`.
    pub check: String,
    /// Fields laid **over** the target's `source_config` for the drill, and
    /// only for it. Left out, the drill connects exactly as the backup does.
    #[serde(default)]
    pub source_config: ConfigTable,
}

impl Drill {
    /// The source configuration a drill runs with: the target's own, with this
    /// block's fields on top of it.
    ///
    /// It is an overlay and not a replacement because a drill almost always
    /// differs from the backup in two or three fields (a host, a user) and
    /// repeating the other six invites them to drift apart.
    #[must_use]
    pub fn source_config_over(&self, target_source_config: &ConfigTable) -> ConfigTable {
        let mut merged = target_source_config.clone();
        merged.extend(self.source_config.clone());
        merged
    }
}

/// Something to back up, with the source that produces it and the storage that
/// keeps it.
///
/// The source is not necessarily a database: it is whatever plugin can turn the
/// thing into a byte stream and rebuild it from one.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Name of the target. It is used as part of the artifact's key.
    pub name: String,
    /// Name of the source plugin (`postgres`, `mysql`, `directory`, `docker-volume`,
    /// …). The core does not interpret this value: it only uses it to locate the
    /// plugin.
    pub source: String,
    /// Name of the storage plugin. Just as opaque as `source`.
    pub storage: String,
    /// age public key the backup is encrypted to.
    pub recipient: String,
    /// Configuration of the source plugin. Opaque here.
    #[serde(default)]
    pub source_config: ConfigTable,
    /// Configuration of the storage plugin. Opaque here.
    #[serde(default)]
    pub storage_config: ConfigTable,
    /// Its own compression level; if absent, [`Defaults`]' one wins.
    #[serde(default)]
    pub compression_level: Option<i32>,
    /// Its own template; if absent, [`Defaults`]' one wins.
    #[serde(default)]
    pub artifact_template: Option<String>,
    /// Its own retention, in days; if absent, [`Defaults`]' one wins.
    #[serde(default)]
    pub retention_days: Option<u32>,
    /// Its own grandfather-father-son retention. Like `retention_days`, it
    /// replaces whatever [`Defaults`] say, of either kind.
    #[serde(default)]
    pub retention: Option<GfsRetention>,
    /// How `shieldbk drill` proves this target's backups restore. Without it
    /// the target cannot be drilled.
    #[serde(default)]
    pub drill: Option<Drill>,
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

    /// Retention that will be applied: the target's if it defines one,
    /// otherwise the global one. `None` means "keep forever".
    ///
    /// The target's replaces the defaults **whole and of either kind**: a
    /// target with its own `[retention]` does not also inherit the defaults'
    /// `retention_days`, and a `[retention]` is never merged field by field,
    /// because what a target keeps has to be readable in one place.
    #[must_use]
    pub fn effective_retention(&self, defaults: &Defaults) -> Option<Retention> {
        Retention::from_parts(self.retention_days, self.retention)
            .or_else(|| Retention::from_parts(defaults.retention_days, defaults.retention))
    }
}

/// When a [`Notify`] is told about a command.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotifyOn {
    /// Only when the command failed. The default: an alert that fires on every
    /// success is one people learn to ignore.
    #[default]
    Failure,
    /// Only when it succeeded -- what a dead-man's-switch ping wants.
    Success,
    /// Every time.
    Always,
}

impl NotifyOn {
    /// Whether a command that ended `ok` is to be told about.
    #[must_use]
    pub fn matches(self, ok: bool) -> bool {
        match self {
            Self::Failure => !ok,
            Self::Success => ok,
            Self::Always => true,
        }
    }
}

/// Somebody who wants to hear how a command went.
///
/// The core does not know what a Slack channel or a mailbox is: `plugin` names a
/// notifier plugin and `config` is that plugin's opaque table, validated later
/// against its schema, exactly as a target's `source_config` is.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notify {
    /// Name of the notifier plugin (`webhook`, …). Opaque, like a target's
    /// `source`.
    pub plugin: String,
    /// When to tell it.
    #[serde(default)]
    pub on: NotifyOn,
    /// Configuration of the notifier plugin. Opaque here.
    #[serde(default)]
    pub config: ConfigTable,
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
    /// Who is told how each command went, in file order.
    #[serde(rename = "notify", default)]
    pub notify: Vec<Notify>,
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
         `source`, `storage` and `recipient`"
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
    /// `source_config` and `storage_config` is left untouched: that is validated
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
        validate_retention(
            config.defaults.retention_days,
            config.defaults.retention,
            "[defaults]",
        )?;

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
            validate_retention(
                target.retention_days,
                target.retention,
                &format!("the target \"{}\"", target.name),
            )?;
            if let Some(drill) = &target.drill {
                validate_drill(drill, &target.name)?;
            }
        }

        for notify in &config.notify {
            validate_plugin_name(&notify.plugin)?;
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

/// Checks that a plugin name can be turned into a binary name without surprises.
///
/// `plugin` ends up in a path (`<dir>/sb-plugin-<name>`), so anything but the
/// characters a binary is realistically named with is refused instead of being
/// sanitised: a `/` or a `..` here would point outside the plugins directory.
fn validate_plugin_name(name: &str) -> Result<(), ConfigError> {
    if !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Ok(());
    }
    Err(ConfigError::InvalidValue {
        field: "plugin".to_owned(),
        location: "a [[notify]] block".to_owned(),
        value: name.to_owned(),
        reason: "a plugin name is letters, digits, `-` and `_`, because it becomes part of the \
                 binary's file name"
            .to_owned(),
    })
}

/// Checks that a drill asks something.
///
/// An empty `check` would restore the artifact into the scratch place and then
/// verify nothing, which is the failure a drill exists to catch: a green result
/// that proves no more than "the restore did not crash".
fn validate_drill(drill: &Drill, target: &str) -> Result<(), ConfigError> {
    if !drill.check.trim().is_empty() {
        return Ok(());
    }
    Err(ConfigError::InvalidValue {
        field: "check".to_owned(),
        location: format!("the drill of the target \"{target}\""),
        value: drill.check.clone(),
        reason: "it is empty, so the drill would restore the artifact and verify nothing: write \
                 the question whose answer shows the data is there"
            .to_owned(),
    })
}

/// Checks that a retention says one thing and that thing keeps something.
///
/// Both mistakes end the same way -- backups deleted that nobody meant to
/// delete -- so neither is resolved by picking a winner or a default.
fn validate_retention(
    days: Option<u32>,
    gfs: Option<GfsRetention>,
    location: &str,
) -> Result<(), ConfigError> {
    let reason = match (days, gfs) {
        (Some(_), Some(_)) => {
            "`retention_days` and `[retention]` are two ways of saying what \
                               to keep: pick one, because guessing which wins deletes backups"
        }
        (_, Some(gfs)) if gfs.keeps_nothing() => {
            "every `keep_*` is zero, so it would delete every artifact, the newest included"
        }
        _ => return Ok(()),
    };
    Err(ConfigError::InvalidValue {
        field: "retention".to_owned(),
        location: location.to_owned(),
        value: "retention".to_owned(),
        reason: reason.to_owned(),
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
artifact_template = "{target}/{yyyy}/{mm}/{dd}/{target}-{timestamp}-{source}.dump.zst.age"

[[target]]
name = "production"
source = "postgres"
storage = "r2"
recipient = "age1qqqqqqqqqq"

[target.source_config]
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
        assert_eq!(c.targets[0].source, "postgres");
        assert_eq!(c.targets[0].storage, "r2");
        assert_eq!(c.defaults.compression_level, 6);
    }

    #[test]
    fn literal_values_and_references_live_side_by_side() {
        let c = Config::parse(EXAMPLE).unwrap();
        let ec = &c.targets[0].source_config;
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
source = "e"
storage = "s"
recipient = "age1x"
[target.source_config]
a = { env = "A" }
b = { file = "/path/b" }
c = { keyring = "service/c" }
d = { command = ["vault", "read", "x"] }
e = { file_insecure = "/run/secrets/e" }
"#;
        let c = Config::parse(toml).unwrap();
        let ec = &c.targets[0].source_config;
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
source = "e"
storage = "s"
recipient = "age1x"
[target.source_config]
exclusions = ["table_a", "table_b"]
"#;
        let c = Config::parse(toml).unwrap();
        assert!(matches!(
            c.targets[0].source_config.get("exclusions"),
            Some(ConfigValue::List(v)) if v.len() == 2
        ));
    }

    #[test]
    fn two_targets_with_the_same_name_are_rejected() {
        let toml = r#"
[[target]]
name = "dup"
source = "e"
storage = "s"
recipient = "age1x"
[[target]]
name = "dup"
source = "e"
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
            "[[target]]\nname = \"with/slash\"\nsource = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\n",
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
        let toml = "[[target]]\nname = \"t\"\nsource = \"e\"\nstorage = \"s\"\n";
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
        let toml = "[[target]]\nname = \"t\"\nsource = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\ncompression_level = 0\n";
        let err = Config::parse(toml).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
        assert!(err.to_string().contains('t'), "it must say in which target");
    }

    const EXAMPLE_TARGET: &str = r#"
[[target]]
name = "t"
source = "e"
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
        let toml = "[defaults]\ncompression_level = 3\n[[target]]\nname = \"t\"\nsource = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\ncompression_level = 19\n";
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
        let toml = "[[target]]\nname = \"t\"\nsource = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\nartifact_template = \"own\"\n";
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
        let toml = "[[target]]\nname = \"t\"\nsource = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\ncompresion_level = 5\n";
        assert!(
            Config::parse(toml).is_err(),
            "an unknown field must be rejected"
        );
    }

    fn with_retention(defaults: &str, target: &str) -> String {
        format!(
            "{defaults}\n[[target]]\nname = \"t\"\nsource = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\n{target}\n"
        )
    }

    #[test]
    fn without_any_retention_nothing_is_ever_deleted() {
        let c = Config::parse(EXAMPLE_TARGET).unwrap();
        assert_eq!(c.targets[0].effective_retention(&c.defaults), None);
    }

    #[test]
    fn retention_days_is_still_the_simple_case() {
        let c = Config::parse(&with_retention("[defaults]\nretention_days = 30", "")).unwrap();
        assert_eq!(
            c.targets[0].effective_retention(&c.defaults),
            Some(Retention::Days(30))
        );
    }

    #[test]
    fn a_gfs_retention_is_read_from_its_own_table() {
        let toml = with_retention(
            "",
            "[target.retention]\nkeep_daily = 7\nkeep_weekly = 4\nkeep_monthly = 12\nkeep_yearly = 3",
        );
        let c = Config::parse(&toml).unwrap();
        assert_eq!(
            c.targets[0].effective_retention(&c.defaults),
            Some(Retention::Gfs(GfsRetention {
                keep_daily: 7,
                keep_weekly: 4,
                keep_monthly: 12,
                keep_yearly: 3,
            }))
        );
    }

    #[test]
    fn a_gfs_bucket_left_out_keeps_nothing_for_that_period() {
        let toml = with_retention("", "[target.retention]\nkeep_monthly = 6");
        let c = Config::parse(&toml).unwrap();
        let Some(Retention::Gfs(gfs)) = c.targets[0].effective_retention(&c.defaults) else {
            panic!("expected a GFS retention");
        };
        assert_eq!((gfs.keep_daily, gfs.keep_monthly), (0, 6));
    }

    #[test]
    fn the_targets_own_retention_replaces_the_defaults_whole_and_of_either_kind() {
        // Merging field by field would let a target inherit `keep_daily` from
        // the defaults without ever writing it: what a target keeps has to be
        // readable in one place.
        let toml = with_retention(
            "[defaults]\nretention_days = 30\n[defaults.retention]\nkeep_daily = 1",
            "",
        );
        assert!(
            Config::parse(&toml).is_err(),
            "the defaults name both kinds: see the next test"
        );

        let toml = with_retention(
            "[defaults]\nretention_days = 30",
            "[target.retention]\nkeep_monthly = 6",
        );
        let c = Config::parse(&toml).unwrap();
        assert!(matches!(
            c.targets[0].effective_retention(&c.defaults),
            Some(Retention::Gfs(_))
        ));

        let toml = with_retention(
            "[defaults.retention]\nkeep_monthly = 6",
            "retention_days = 5",
        );
        let c = Config::parse(&toml).unwrap();
        assert_eq!(
            c.targets[0].effective_retention(&c.defaults),
            Some(Retention::Days(5))
        );
    }

    #[test]
    fn naming_both_kinds_of_retention_at_once_is_rejected() {
        // Which one wins is exactly the kind of guess that deletes backups.
        for toml in [
            with_retention("", "retention_days = 5\n[target.retention]\nkeep_daily = 1"),
            with_retention(
                "[defaults]\nretention_days = 5\n[defaults.retention]\nkeep_daily = 1",
                "",
            ),
        ] {
            let err = Config::parse(&toml).unwrap_err();
            assert!(matches!(err, ConfigError::InvalidValue { .. }), "{err}");
            assert!(err.to_string().contains("retention_days"), "{err}");
        }
    }

    #[test]
    fn a_retention_that_keeps_nothing_is_rejected() {
        // It would delete every artifact on the first run, the newest included.
        for toml in [
            with_retention("", "[target.retention]\nkeep_daily = 0"),
            with_retention("", "[target.retention]"),
            with_retention("[defaults.retention]", ""),
        ] {
            let err = Config::parse(&toml).unwrap_err();
            assert!(matches!(err, ConfigError::InvalidValue { .. }), "{err}");
        }
    }

    #[test]
    fn a_misspelt_gfs_bucket_is_rejected() {
        let toml = with_retention("", "[target.retention]\nkeep_dayly = 7");
        assert!(Config::parse(&toml).is_err());
    }

    #[test]
    fn a_notify_block_is_read_with_its_opaque_config() {
        let toml = format!(
            "{EXAMPLE_TARGET}\n[[notify]]\nplugin = \"webhook\"\non = \"always\"\n\
             [notify.config]\nurl = {{ env = \"HOOK\" }}\nformat = \"slack\"\n"
        );
        let c = Config::parse(&toml).unwrap();
        assert_eq!(c.notify.len(), 1);
        assert_eq!(c.notify[0].plugin, "webhook");
        assert_eq!(c.notify[0].on, NotifyOn::Always);
        assert!(matches!(
            c.notify[0].config.get("url"),
            Some(ConfigValue::Secret(SecretRef::Env(v))) if v == "HOOK"
        ));
    }

    #[test]
    fn nobody_is_notified_unless_the_config_says_so() {
        assert!(Config::parse(EXAMPLE_TARGET).unwrap().notify.is_empty());
    }

    #[test]
    fn a_notify_block_defaults_to_telling_only_about_failures() {
        let toml = format!("{EXAMPLE_TARGET}\n[[notify]]\nplugin = \"webhook\"\n");
        let c = Config::parse(&toml).unwrap();
        assert_eq!(c.notify[0].on, NotifyOn::Failure);
    }

    #[test]
    fn each_moment_matches_the_outcomes_it_names() {
        for (on, when_ok, when_failed) in [
            (NotifyOn::Failure, false, true),
            (NotifyOn::Success, true, false),
            (NotifyOn::Always, true, true),
        ] {
            assert_eq!(on.matches(true), when_ok, "{on:?} on success");
            assert_eq!(on.matches(false), when_failed, "{on:?} on failure");
        }
    }

    #[test]
    fn a_notify_block_with_a_bad_moment_or_a_typo_is_rejected() {
        for extra in ["on = \"sometimes\"", "plugn = \"x\""] {
            let toml = format!("{EXAMPLE_TARGET}\n[[notify]]\nplugin = \"webhook\"\n{extra}\n");
            assert!(Config::parse(&toml).is_err(), "{extra}");
        }
    }

    #[test]
    fn a_notify_plugin_name_cannot_escape_the_plugins_directory() {
        for bad in ["", "../evil", "a/b", "with space", "dot.dot", "nul\\u0000"] {
            let toml = format!("{EXAMPLE_TARGET}\n[[notify]]\nplugin = \"{bad}\"\n");
            let err = Config::parse(&toml).unwrap_err();
            assert!(
                matches!(
                    err,
                    ConfigError::InvalidValue { .. } | ConfigError::InvalidToml(_)
                ),
                "{bad:?}: {err}"
            );
        }
    }

    #[test]
    fn target_names_cannot_be_empty_nor_carry_slashes() {
        // The target's name goes into the artifact's key: a slash or an empty
        // name would produce absurd or unsafe paths in the destination.
        for bad in ["", "with/slash", "..", "with space/and slash"] {
            let toml = format!(
                "[[target]]\nname = \"{bad}\"\nsource = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\n"
            );
            assert!(
                Config::parse(&toml).is_err(),
                "\"{bad}\" should be rejected"
            );
        }
    }

    fn with_drill(drill: &str) -> String {
        format!("{EXAMPLE_TARGET}\n[target.drill]\n{drill}\n")
    }

    #[test]
    fn a_target_has_no_drill_unless_the_config_says_so() {
        assert!(
            Config::parse(EXAMPLE_TARGET).unwrap().targets[0]
                .drill
                .is_none()
        );
    }

    #[test]
    fn a_drill_is_read_with_its_check_and_its_overlay() {
        let toml = with_drill(
            "check = \"SELECT count(*) > 0 FROM users\"\n\
             [target.drill.source_config]\nhost = \"staging\"\npassword = { env = \"P\" }",
        );
        let c = Config::parse(&toml).unwrap();
        let drill = c.targets[0].drill.as_ref().unwrap();
        assert_eq!(drill.check, "SELECT count(*) > 0 FROM users");
        assert!(matches!(
            drill.source_config.get("host"),
            Some(ConfigValue::String(s)) if s == "staging"
        ));
        assert!(matches!(
            drill.source_config.get("password"),
            Some(ConfigValue::Secret(SecretRef::Env(_)))
        ));
    }

    #[test]
    fn a_drill_without_a_check_or_with_a_blank_one_is_rejected() {
        // It would restore and then verify nothing: a green light that proves
        // less than it seems to.
        assert!(Config::parse(&with_drill("source_config = {}")).is_err());
        for blank in ["", "   ", "\\t"] {
            let err = Config::parse(&with_drill(&format!("check = \"{blank}\""))).unwrap_err();
            assert!(matches!(err, ConfigError::InvalidValue { .. }), "{err}");
            assert!(
                err.to_string().contains("\"t\""),
                "it must name the target: {err}"
            );
        }
    }

    #[test]
    fn a_misspelt_drill_field_is_rejected() {
        assert!(Config::parse(&with_drill("check = \"x\"\nchek = \"y\"")).is_err());
    }

    #[test]
    fn the_drill_overlay_wins_field_by_field_and_leaves_the_rest_alone() {
        let toml = format!(
            "{}\n[target.source_config]\nhost = \"prod\"\ndatabase = \"app\"\n\
             [target.drill]\ncheck = \"x\"\n[target.drill.source_config]\nhost = \"staging\"\n",
            "[[target]]\nname = \"t\"\nsource = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\""
        );
        let c = Config::parse(&toml).unwrap();
        let target = &c.targets[0];
        let merged = target
            .drill
            .as_ref()
            .unwrap()
            .source_config_over(&target.source_config);
        assert!(matches!(merged.get("host"), Some(ConfigValue::String(s)) if s == "staging"));
        assert!(matches!(merged.get("database"), Some(ConfigValue::String(s)) if s == "app"));
        // And the target's own table is untouched: the backup still goes to prod.
        assert!(
            matches!(target.source_config.get("host"), Some(ConfigValue::String(s)) if s == "prod")
        );
    }
}
