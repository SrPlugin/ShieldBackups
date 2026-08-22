//! The loaded configuration, already resolved against the filesystem.
//!
//! Every command starts from the same thing: a TOML file read, its paths
//! expanded and a way of choosing which targets are worked on. If each command
//! did it on its own, "expand the tilde" would be a rule with six
//! implementations and forgetting it in a single one would be enough to make a
//! command look for the plugins where they are not.

use std::path::{Path, PathBuf};

use sb_config::{Config, Target};

use crate::cli::{Cli, DEFAULT_CONFIG};
use crate::error::CliError;
use crate::paths;

/// Everything a command needs to know before starting.
pub struct Context {
    pub config: Config,
    /// The path it was read from, so it can be named in the errors.
    pub config_path: PathBuf,
    pub plugins_dir: PathBuf,
    pub lockfile_path: PathBuf,
    /// How many targets are processed at a time. Never zero.
    pub jobs: usize,
}

impl Context {
    /// Reads the configuration the command line asked for.
    ///
    /// It requires at least one `[[target]]`: that is what the commands that
    /// really back up or restore something need. The ones that only look at the
    /// plugins directory use [`Context::load_without_requiring_targets`].
    ///
    /// # Errors
    /// Returns [`CliError::Config`] if the file does not exist -- the message
    /// names the exact path that was looked for, which is the only thing that
    /// tells "I got the path wrong" from "I forgot to create it" --, if it
    /// cannot be read or if its content is not a valid configuration.
    pub fn load(cli: &Cli) -> Result<Self, CliError> {
        Self::read(cli, sb_config::Config::parse)
    }

    /// The same, but without requiring the configuration to declare any target.
    ///
    /// It is for the `plugin` commands: the plugins directory and the lockfile
    /// are all they look at, and registering a binary is an installation step
    /// that happens **before** deciding which databases get backed up.
    /// Requiring a `[[target]]` from them forces inventing one with a fake
    /// `recipient` just to be able to seal the lockfile.
    ///
    /// # Errors
    /// The same as [`Context::load`] minus "there are no targets".
    pub fn load_without_requiring_targets(cli: &Cli) -> Result<Self, CliError> {
        Self::read(cli, sb_config::Config::parse_without_requiring_targets)
    }

    /// The common body: locate the file, read it, parse it with whichever
    /// parser applies and expand the paths. The only thing that differs between
    /// the two entry points is that function, so "expand the tilde" still has a
    /// single implementation.
    fn read(
        cli: &Cli,
        parse: fn(&str) -> Result<Config, sb_config::ConfigError>,
    ) -> Result<Self, CliError> {
        let config_path = cli
            .config
            .clone()
            .unwrap_or_else(|| paths::expand(DEFAULT_CONFIG));

        let text = std::fs::read_to_string(&config_path).map_err(|source| {
            CliError::config(format!(
                "could not read the configuration `{}`: {source}. Point at another one with \
                 `--config <path>` or create that one",
                config_path.display()
            ))
        })?;

        let config = parse(&text).map_err(|source| {
            CliError::config(format!(
                "the configuration `{}` could not be used: {source}",
                config_path.display()
            ))
        })?;

        let plugins_dir = paths::expand(&config.plugins.dir);
        let lockfile_path = paths::expand(&config.plugins.lockfile);

        // Zero concurrent jobs means nothing and would leave the process
        // waiting for a permit that never comes: it is corrected rather than
        // rejected, because the user clearly meant "few", not "none".
        let jobs = cli.jobs.max(1);

        tracing::debug!(
            config = %config_path.display(),
            plugins = %plugins_dir.display(),
            lockfile = %lockfile_path.display(),
            targets = config.targets.len(),
            jobs,
            "context loaded"
        );

        Ok(Self {
            config,
            config_path,
            plugins_dir,
            lockfile_path,
            jobs,
        })
    }

    /// The target that was asked for by name.
    ///
    /// # Errors
    /// Returns [`CliError::Config`] naming the target that is not there **and
    /// the ones that are**: whoever mistypes a name needs to see the list, not
    /// to open the file again.
    pub fn target(&self, name: &str) -> Result<&Target, CliError> {
        self.config.target(name).ok_or_else(|| {
            CliError::config(format!(
                "there is no target named `{name}` in `{}`. The declared ones are: {}",
                self.config_path.display(),
                self.target_names().join(", ")
            ))
        })
    }

    /// The targets to work on: the one that was asked for, or all of them.
    ///
    /// # Errors
    /// Returns [`CliError::Config`] if a target that does not exist was named.
    pub fn targets(&self, filter: Option<&str>) -> Result<Vec<&Target>, CliError> {
        match filter {
            Some(name) => Ok(vec![self.target(name)?]),
            None => Ok(self.config.targets.iter().collect()),
        }
    }

    fn target_names(&self) -> Vec<&str> {
        self.config
            .targets
            .iter()
            .map(|t| t.name.as_str())
            .collect()
    }

    /// The path of a plugin's binary: `<plugins.dir>/sb-plugin-<name>`.
    #[must_use]
    pub fn plugin_path(&self, name: &str) -> PathBuf {
        plugin_path(&self.plugins_dir, name)
    }
}

/// Prefix a plugin's binary is named with.
///
/// It is what allows listing the directory and knowing what is a plugin and
/// what is a file somebody left there.
pub const BINARY_PREFIX: &str = "sb-plugin-";

/// The path of `name`'s binary inside `dir`.
#[must_use]
pub fn plugin_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{BINARY_PREFIX}{name}"))
}

/// The plugin name a file corresponds to, if it is one at all.
#[must_use]
pub fn plugin_name_of(file: &str) -> Option<&str> {
    file.strip_prefix(BINARY_PREFIX)
        .filter(|rest| !rest.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plugin_binary_is_recognised_by_its_prefix() {
        assert_eq!(plugin_name_of("sb-plugin-postgres"), Some("postgres"));
        assert_eq!(plugin_name_of("sb-plugin-mock"), Some("mock"));
    }

    #[test]
    fn what_is_not_a_plugin_binary_does_not_look_like_one() {
        // The plugins directory is a normal directory: it may hold a README, a
        // `.bak` of somebody's, or the lockfile itself.
        for foreign in ["README.txt", "plugins.lock", "sb-plugin-", "postgres"] {
            assert_eq!(plugin_name_of(foreign), None, "`{foreign}` is not a plugin");
        }
    }

    #[test]
    fn a_plugins_path_is_the_prefix_plus_the_name() {
        assert_eq!(
            plugin_path(Path::new("/opt/sb"), "r2"),
            PathBuf::from("/opt/sb/sb-plugin-r2")
        );
    }
}
