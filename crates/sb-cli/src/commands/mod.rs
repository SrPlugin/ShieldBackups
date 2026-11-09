//! The dispatch, and only the dispatch.
//!
//! This file exists so that "where is `verify`'s code?" can be answered without
//! reading anything else. Each subcommand lives in its own file and none of
//! them needs to know the others; the only shared part -- loading the context
//! and limiting how many targets are processed at a time -- is in
//! [`concurrency`], because it is a decision of the tool and not of any
//! particular command.

mod backup;
mod concurrency;
mod doctor;
mod drill;
mod keygen;
mod notify;
mod plugin;
mod restore;
mod storage;
mod verify;

use crate::cli::{Cli, Command, PluginAction, StorageAction};
use crate::context::Context;
use crate::error::CliError;
use crate::output::Report;

/// Runs what was asked for and returns what has to be told.
///
/// # Errors
/// Returns [`CliError`] with the failure's class, which is what decides the
/// process's exit code.
pub async fn run(cli: &Cli) -> Result<Report, CliError> {
    // `keygen` is answered before the configuration is even looked for, and
    // that is the whole point: it is the command somebody runs **first**, when
    // there is no configuration file yet and no `recipient` to write in one --
    // because generating that `recipient` is exactly what is being asked for.
    // Demanding a file here would make the tool impossible to start using.
    if let Command::Keygen { output } = &cli.command {
        return keygen::run(cli.format, output.as_deref());
    }

    // Every other command loads the configuration, the `plugin` ones included:
    // the plugins directory and the lockfile come from it, so without it there
    // would be no way to know where to look. What changes between them is how
    // much they demand of it (see [`context`]).
    let ctx = context(cli)?;

    let result = execute(&ctx, cli).await;
    if let Some(command) = notified_as(&cli.command) {
        notify::tell(&ctx, command, &result).await;
    }
    result
}

/// The name a command is told to notifiers under, or `None` for the ones that
/// are not: `keygen` runs before there is a configuration, and the `plugin`
/// commands are installation chores, not something whose outcome anybody is
/// paged about.
const fn notified_as(command: &Command) -> Option<&'static str> {
    match command {
        Command::Backup { .. } => Some("backup"),
        Command::Restore { .. } => Some("restore"),
        Command::Verify { .. } => Some("verify"),
        Command::Doctor { .. } => Some("doctor"),
        Command::Drill { .. } => Some("drill"),
        Command::Storage {
            action: StorageAction::Gc { .. },
        } => Some("storage gc"),
        Command::Storage {
            action: StorageAction::Prune { .. },
        } => Some("storage prune"),
        Command::Keygen { .. } | Command::Plugin { .. } => None,
    }
}

async fn execute(ctx: &Context, cli: &Cli) -> Result<Report, CliError> {
    match &cli.command {
        Command::Keygen { .. } => {
            unreachable!("`keygen` returns above, before any configuration is read")
        }
        Command::Backup { target } => backup::run(ctx, target.as_deref()).await,
        Command::Restore {
            target,
            artifact,
            identity,
        } => restore::run(ctx, target, artifact, identity).await,
        Command::Drill {
            target,
            identity,
            artifact,
        } => drill::run(ctx, target, artifact.as_deref(), identity).await,
        Command::Verify { target, artifact } => verify::run(ctx, target, artifact.as_deref()).await,
        Command::Doctor { target } => doctor::run(ctx, target.as_deref()).await,
        Command::Plugin { action } => match action {
            PluginAction::List => plugin::list(ctx),
            PluginAction::Docs { plugin: name } => plugin::docs(ctx, name).await,
            PluginAction::Verify => plugin::verify(ctx),
            PluginAction::Lock => plugin::lock(ctx),
        },
        Command::Storage { action } => match action {
            StorageAction::Gc { target } => storage::gc(ctx, target).await,
            StorageAction::Prune { target, dry_run } => storage::prune(ctx, target, *dry_run).await,
        },
    }
}

/// The context each command gets.
///
/// The `plugin` ones only use the `[plugins]` section: registering a binary's
/// hash, checking it or listing it has nothing to do with which databases get
/// backed up, and it is what is done **before** deciding that -- at install
/// time, or while building an image. The rest do work on targets and have to
/// keep requiring them: a `backup` that started with an empty configuration
/// would do nothing and end up saying everything went well, which is worse than
/// refusing.
///
/// The general case is requiring them, so a new command will do so by default.
/// `keygen` is not in this function at all: it never gets here, because it
/// needs no configuration of any kind.
fn context(cli: &Cli) -> Result<Context, CliError> {
    match &cli.command {
        Command::Plugin { .. } => Context::load_without_requiring_targets(cli),
        _ => Context::load(cli),
    }
}
