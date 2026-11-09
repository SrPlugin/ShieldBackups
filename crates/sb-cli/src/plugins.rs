//! Starting a plugin, with the check that comes before all the others.
//!
//! A plugin is a process `shieldbk` hands the database password and the storage
//! credentials to. That turns "which binary is this?" into the most important
//! question of start-up, and that is why **nothing in this module runs a binary
//! without having verified it against the lockfile first**. The check lives
//! here and not in each command precisely because forgetting it once would be
//! enough to void it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sb_config::{ConfigTable, Drill, Notify, Target, validate_and_convert};
use sb_core::lockfile::Lockfile;
use sb_core::plugin::{Capability, PluginClient};

use crate::context::{Context, plugin_name_of};
use crate::error::CliError;

/// What part a plugin plays in a target: where the bytes come from or where
/// they go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Source,
    Storage,
}

impl Role {
    /// The configuration section its fields come from. It is also what shows up
    /// in the validation messages.
    pub const fn section(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Storage => "storage",
        }
    }

    const fn capability(self) -> Capability {
        match self {
            Self::Source => Capability::Source,
            Self::Storage => Capability::Storage,
        }
    }

    fn name_in(self, target: &Target) -> &str {
        match self {
            Self::Source => &target.source,
            Self::Storage => &target.storage,
        }
    }

    fn config_in(self, target: &Target) -> &ConfigTable {
        match self {
            Self::Source => &target.source_config,
            Self::Storage => &target.storage_config,
        }
    }
}

/// The plugin binaries in the directory, in alphabetical order.
///
/// A directory that does not exist yet is a directory with no plugins and not
/// an error: it is the state of a freshly made installation, and telling that
/// to whoever runs `plugin list` explains more than an I/O failure.
///
/// # Errors
/// Returns [`CliError::Plugin`] if the directory exists but cannot be read.
pub fn binaries(dir: &Path) -> Result<Vec<(String, PathBuf)>, CliError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(CliError::plugin(format!(
                "could not read the plugins directory `{}`: {source}",
                dir.display()
            )));
        }
    };

    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| {
            CliError::plugin(format!(
                "could not walk the plugins directory `{}`: {source}",
                dir.display()
            ))
        })?;
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let Some(name) = plugin_name_of(&file_name) else {
            continue;
        };
        if entry.path().is_file() {
            found.push((name.to_owned(), entry.path()));
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(found)
}

/// Checks that `name`'s binary is where it should be and is the one that was
/// registered.
///
/// # Errors
/// Returns [`CliError::Plugin`] if the binary is not there -- the message says
/// where it was looked for -- or if the lockfile does not authorise it. The
/// lockfile's message arrives intact: it already carries the
/// `shieldbk plugin lock <name>` that has to be typed.
pub fn verify(ctx: &Context, name: &str) -> Result<PathBuf, CliError> {
    let path = ctx.plugin_path(name);
    if !path.is_file() {
        return Err(CliError::plugin(format!(
            "the plugin `{name}` was not found: it was looked for at `{}`. Install it there or \
             change `plugins.dir` in the configuration",
            path.display()
        )));
    }

    let lockfile = Lockfile::load(&ctx.lockfile_path)?;
    lockfile.verify(name, &path)?;
    tracing::debug!(plugin = name, path = %path.display(), "binary verified");
    Ok(path)
}

/// Starts a verified plugin, **without configuring it**.
///
/// It is what `plugin docs` needs: a live plugin that will only be asked which
/// fields it accepts.
///
/// # Errors
/// Returns [`CliError::Plugin`] if the binary does not pass verification or if
/// the process never gets to talk.
pub async fn start(ctx: &Context, name: &str) -> Result<PluginClient, CliError> {
    let path = verify(ctx, name)?;
    Ok(PluginClient::start(name, &path).await?)
}

/// Starts the plugin that plays `role` in `target`, already configured and with
/// its capability checked.
///
/// The order matters and is the same in all four operations: verify the binary,
/// start it, **ask it for its schema**, validate what the configuration says
/// against it -- resolving the secrets along the way -- and only then hand it
/// over. Validating against the plugin's schema rather than against a list in
/// the core is what lets adding a new source not require recompiling
/// `shieldbk`.
///
/// # Errors
/// Returns [`CliError::Plugin`] if the plugin does not start or cannot play the
/// part it is asked for, and [`CliError::Config`] if its configuration does not
/// match the schema or a secret could not be resolved.
pub async fn start_for(
    ctx: &Context,
    target: &Target,
    role: Role,
) -> Result<PluginClient, CliError> {
    start_configured(
        ctx,
        role.name_in(target),
        role.capability(),
        role.section(),
        role.config_in(target),
        &format!("target `{}`", target.name),
    )
    .await
}

/// Starts the source plugin of `target` configured **for its drill**: the
/// target's own `source_config` with the `[target.drill]` overlay on top, and
/// the `drill` capability checked on top of `source`.
///
/// It is the same plugin binary and the same schema validation as
/// [`start_for`]; what changes is only which fields it is handed, so a drill
/// can aim a plugin at a staging server without the backup's configuration
/// moving.
///
/// # Errors
/// The same as [`start_for`], plus [`CliError::Config`] if the plugin is a
/// source but cannot take part in a drill.
pub async fn start_drill_source(
    ctx: &Context,
    target: &Target,
    drill: &Drill,
) -> Result<PluginClient, CliError> {
    let owner = format!("target `{}`", target.name);
    let config = drill.source_config_over(&target.source_config);
    let client = start_configured(
        ctx,
        &target.source,
        Capability::Source,
        Role::Source.section(),
        &config,
        &owner,
    )
    .await?;

    // Checked here, with the plugin's name in the message, and not left for
    // `run_drill` to find after the storage plugin has also been started.
    if let Err(source) = client.require_capability(Capability::Drill) {
        close(client).await;
        return Err(CliError::config(format!(
            "the {owner} has a `[target.drill]` block, but {source}: its source plugin has to \
             implement the `drill` capability to be restored into a disposable place"
        )));
    }
    Ok(client)
}

/// Starts the notifier plugin a `[[notify]]` block names, already configured
/// and with its capability checked, the same way [`start_for`] does for a
/// target's roles.
///
/// # Errors
/// The same as [`start_for`].
pub async fn start_notifier(ctx: &Context, notify: &Notify) -> Result<PluginClient, CliError> {
    start_configured(
        ctx,
        &notify.plugin,
        Capability::Notifier,
        "notify",
        &notify.config,
        "a `[[notify]]` block",
    )
    .await
}

/// What [`start_for`] and [`start_notifier`] share: verify, start, check the
/// capability, validate the configuration against the plugin's schema and hand
/// it over. `owner` only feeds the messages, saying whose plugin it is.
async fn start_configured(
    ctx: &Context,
    name: &str,
    capability: Capability,
    section: &str,
    config: &ConfigTable,
    owner: &str,
) -> Result<PluginClient, CliError> {
    let client = start(ctx, name).await?;

    // The capability is checked here and not at use time: asking a plugin that
    // only knows how to store for a dump has to fail when it is chosen, not
    // halfway through the backup.
    if let Err(source) = client.require_capability(capability) {
        let _ = client.shutdown().await;
        return Err(CliError::config(format!(
            "the {owner} uses `{name}` as {section}, but {source}"
        )));
    }

    match configure(&client, config, section, owner).await {
        Ok(()) => Ok(client),
        Err(error) => {
            // A plugin that could not be configured cannot be left alive: it is
            // a process holding session key material that nobody is going to
            // ask anything of any more.
            let _ = client.shutdown().await;
            Err(error)
        }
    }
}

/// Asks it for the schema, validates the configuration against it and hands it
/// over.
async fn configure(
    client: &PluginClient,
    config: &ConfigTable,
    section: &str,
    owner: &str,
) -> Result<(), CliError> {
    let schema = client.schema().await?;
    let values = validate_and_convert(config, &schema, section).map_err(|source| {
        CliError::config(format!(
            "the `{section}` configuration of {owner} is not valid: {source}"
        ))
    })?;

    // What gets logged is **how many** fields go, never which ones nor their
    // values: among them there are passwords.
    tracing::debug!(
        plugin = client.name(),
        role = section,
        fields = values.len(),
        "configuring plugin"
    );
    deliver(client, values).await
}

/// The handover itself, kept apart so it is clear that the map -- which carries
/// the already resolved secrets -- goes nowhere else.
async fn deliver(
    client: &PluginClient,
    values: HashMap<String, sb_proto::Value>,
) -> Result<(), CliError> {
    Ok(client.configure(values).await?)
}

/// Shuts a plugin down without letting its failure cover up the operation's.
///
/// A shutdown that fails is a note in the log; the backup's result is what the
/// user came to find out. Returning the shutdown error would make a correct
/// backup look broken.
pub async fn close(client: PluginClient) {
    let name = client.name().to_owned();
    if let Err(source) = client.shutdown().await {
        tracing::warn!(plugin = %name, %source, "the plugin did not shut down cleanly");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_role_knows_which_section_and_capability_it_talks_about() {
        assert_eq!(Role::Source.section(), "source");
        assert_eq!(Role::Storage.section(), "storage");
        assert_eq!(Role::Source.capability(), Capability::Source);
        assert_eq!(Role::Storage.capability(), Capability::Storage);
    }

    #[test]
    fn a_directory_that_does_not_exist_is_a_directory_with_no_plugins() {
        // It is the state of a freshly made installation, not a failure.
        let empty = binaries(Path::new("/does/not/exist/this/directory"));
        assert!(matches!(empty, Ok(v) if v.is_empty()));
    }

    #[test]
    fn only_the_files_with_the_projects_prefix_are_listed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("sb-plugin-zeta"), b"z").unwrap();
        std::fs::write(dir.path().join("sb-plugin-alpha"), b"a").unwrap();
        std::fs::write(dir.path().join("plugins.lock"), b"l").unwrap();
        std::fs::create_dir(dir.path().join("sb-plugin-dir")).unwrap();

        let found = binaries(dir.path()).unwrap();
        let names: Vec<&str> = found.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec!["alpha", "zeta"],
            "only files, and in a stable order"
        );
    }
}
