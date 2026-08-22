//! `shieldbk storage gc <target>`.
//!
//! An upload that gets cut halfway -- the process dies, the network goes down
//! -- does not disappear on its own: in a storage target with multipart uploads
//! the parts already written stay there, invisible to the listing and
//! **billable**. Nobody sees them and everybody pays for them, until somebody
//! looks at the invoice and does not understand why the "empty" bucket costs
//! money.
//!
//! This command is the only way to sweep them up. It is deliberately scoped to
//! the target's prefix and not to the whole bucket: a storage target may hold
//! more than this `shieldbk`'s backups, and aborting somebody else's uploads
//! would be worse than the problem it came to solve.

use crate::artifacts;
use crate::context::Context;
use crate::error::CliError;
use crate::output::Report;
use crate::plugins::{self, Role};

/// # Errors
/// Returns [`CliError::Config`] if the target does not exist,
/// [`CliError::Plugin`] if the storage target does not start and
/// [`CliError::Operation`] if the storage target rejects the cleanup.
pub async fn gc(ctx: &Context, target: &str) -> Result<Report, CliError> {
    let target = ctx.target(target)?;
    let prefix = artifacts::prefix_for(target, &ctx.config.defaults);

    let storage = plugins::start_for(ctx, target, Role::Storage).await?;
    let outcome = artifacts::abort_incomplete(&storage, &prefix).await;
    plugins::close(storage).await;

    let aborted = outcome?;
    tracing::info!(target = %target.name, %prefix, aborted, "storage cleanup finished");

    Ok(Report::new(
        format!(
            "{}: {aborted} incomplete uploads aborted under `{prefix}`",
            target.name
        ),
        serde_json::json!({
            "command": "storage gc",
            "target": target.name,
            "prefix": prefix,
            "aborted": aborted,
        }),
    ))
}
