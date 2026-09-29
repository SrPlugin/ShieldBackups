//! `shieldbk storage gc <target>` and `shieldbk storage prune <target>`.
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
//!
//! `prune` lives in this file too: it is the same shape of operation as `gc`
//! -- list what belongs to the target under its prefix, then delete what does
//! not need to be kept any more -- and the core stays exactly as agnostic doing
//! it. Retention is not a Postgres or an R2 concept, it is "how long an
//! artifact is kept", so deciding from `ArtifactMeta.modified_at` (see
//! [`crate::retention`]) and calling `Delete` never needs to know what is inside
//! the artifact.

use sb_config::Retention;
use sb_core::model::manifest_key_for;
use sb_core::plugin::PluginClient;
use time::OffsetDateTime;

use super::concurrency::in_batches;
use crate::artifacts;
use crate::context::Context;
use crate::error::CliError;
use crate::output::Report;
use crate::plugins::{self, Role};
use crate::retention;

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

/// # Errors
/// Returns [`CliError::Config`] if the target does not exist, or if it has no
/// retention -- `retention_days` or `[retention]`, either on the target or in
/// `[defaults]`: pruning deletes backups, so unlike compression or the template
/// it is opt-in and never assumed --; [`CliError::Plugin`] if the storage target
/// does not start; and [`CliError::Operation`] if listing or deleting fails.
pub async fn prune(ctx: &Context, target: &str, dry_run: bool) -> Result<Report, CliError> {
    let target = ctx.target(target)?;
    let retention = target
        .effective_retention(&ctx.config.defaults)
        .ok_or_else(|| {
            CliError::config(format!(
                "target `{}` has no `retention_days` or `[retention]`: set one under `[defaults]` \
                 or on the target before running `storage prune` -- pruning deletes backups, so \
                 it does not run on a guessed default",
                target.name
            ))
        })?;
    let prefix = artifacts::prefix_for(target, &ctx.config.defaults);

    let storage = plugins::start_for(ctx, target, Role::Storage).await?;
    let outcome = prune_expired(&storage, &prefix, retention, dry_run).await;
    plugins::close(storage).await;

    let outcome = outcome?;
    tracing::info!(
        target = %target.name, %prefix, ?retention, dry_run,
        expired = outcome.expired.len(), deleted = outcome.deleted, kept = outcome.kept,
        "prune finished"
    );

    let what = if dry_run {
        format!(
            "{} artifacts would be deleted (dry run)",
            outcome.expired.len()
        )
    } else {
        format!("{} artifacts deleted", outcome.deleted)
    };
    Ok(Report::new(
        format!(
            "{}: {what} under `{prefix}` ({} kept)",
            target.name, outcome.kept
        ),
        serde_json::json!({
            "command": "storage prune",
            "target": target.name,
            "prefix": prefix,
            "policy": policy_json(retention),
            "retention_days": match retention {
                Retention::Days(days) => Some(days),
                Retention::Gfs(_) => None,
            },
            "dry_run": dry_run,
            "deleted": outcome.deleted,
            "kept": outcome.kept,
            "expired": outcome.expired,
        }),
    ))
}

fn policy_json(retention: Retention) -> serde_json::Value {
    match retention {
        Retention::Days(days) => serde_json::json!({ "kind": "days", "days": days }),
        Retention::Gfs(gfs) => serde_json::json!({
            "kind": "gfs",
            "keep_daily": gfs.keep_daily,
            "keep_weekly": gfs.keep_weekly,
            "keep_monthly": gfs.keep_monthly,
            "keep_yearly": gfs.keep_yearly,
        }),
    }
}

/// What a prune pass did, or -- in a dry run -- would do.
struct PruneOutcome {
    /// Artifacts actually deleted. Always zero in a dry run.
    deleted: u32,
    /// Artifacts the policy keeps.
    kept: u32,
    /// Keys the policy let go of, whether or not they were deleted.
    expired: Vec<String>,
}

/// How many artifacts are deleted at the same time. Deleting is one round trip
/// per key against a remote store, so a first prune over a long backlog is
/// latency-bound; a small fixed number hides that latency without turning the
/// cleanup into a burst of requests against the same bucket.
const DELETES_AT_ONCE: usize = 8;

/// Deletes every artifact under `prefix` that `retention` no longer keeps,
/// along with its manifest.
///
/// The manifest goes **first**. `artifacts::list` hides manifests, so once an
/// artifact is gone nothing would ever select its manifest again: deleting the
/// artifact first and dying in between leaves an orphan for good, whereas
/// deleting the manifest first leaves an artifact that the next run selects
/// again and finishes -- `delete` is idempotent.
///
/// One artifact that cannot be deleted does not stop the others: they are all
/// attempted, and the first failure is what comes back. An incomplete prune
/// that pretends to have finished is worse than one that says so and can be
/// re-run.
async fn prune_expired(
    storage: &PluginClient,
    prefix: &str,
    retention: Retention,
    dry_run: bool,
) -> Result<PruneOutcome, CliError> {
    let candidates = artifacts::list(storage, prefix).await?;
    let expired = retention::expired(retention, &candidates, OffsetDateTime::now_utc());
    let kept = u32::try_from(candidates.len() - expired.len()).unwrap_or(u32::MAX);
    let keys: Vec<String> = expired.iter().map(|a| a.key.clone()).collect();

    if dry_run {
        return Ok(PruneOutcome {
            deleted: 0,
            kept,
            expired: keys,
        });
    }

    let results = in_batches(keys.clone(), DELETES_AT_ONCE, |key| async move {
        artifacts::delete(storage, &manifest_key_for(&key)).await?;
        artifacts::delete(storage, &key).await
    })
    .await;

    let mut deleted = 0_u32;
    let mut first_error = None;
    for result in results {
        match result {
            Ok(()) => deleted += 1,
            Err(error) => {
                tracing::warn!(%error, "an artifact could not be deleted");
                first_error.get_or_insert(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(PruneOutcome {
            deleted,
            kept,
            expired: keys,
        }),
    }
}
