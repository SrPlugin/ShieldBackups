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
//! it. `retention_days` is not a Postgres or an R2 concept, it is "how long an
//! artifact is kept", so comparing `ArtifactMeta.modified_at` against a cutoff
//! and calling `Delete` never needs to know what is inside the artifact.

use sb_core::model::manifest_key_for;
use sb_core::plugin::PluginClient;
use sb_proto::ArtifactMeta;
use time::OffsetDateTime;

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

/// # Errors
/// Returns [`CliError::Config`] if the target does not exist, or if it has no
/// `retention_days` -- either on the target or in `[defaults]`: pruning
/// deletes backups, so unlike compression or the template it is opt-in and
/// never assumed --; [`CliError::Plugin`] if the storage target does not
/// start; and [`CliError::Operation`] if listing or deleting fails.
pub async fn prune(ctx: &Context, target: &str) -> Result<Report, CliError> {
    let target = ctx.target(target)?;
    let days = target
        .effective_retention_days(&ctx.config.defaults)
        .ok_or_else(|| {
            CliError::config(format!(
                "target `{}` has no `retention_days`: set it under `[defaults]` or on the target \
                 before running `storage prune` -- pruning deletes backups, so it does not run \
                 on a guessed default",
                target.name
            ))
        })?;
    let prefix = artifacts::prefix_for(target, &ctx.config.defaults);
    let cutoff = cutoff_timestamp(OffsetDateTime::now_utc(), days);

    let storage = plugins::start_for(ctx, target, Role::Storage).await?;
    let outcome = prune_expired(&storage, &prefix, &cutoff).await;
    plugins::close(storage).await;

    let (deleted, kept) = outcome?;
    tracing::info!(
        target = %target.name, %prefix, days, %cutoff, deleted, kept,
        "prune finished"
    );

    Ok(Report::new(
        format!(
            "{}: {deleted} artifacts older than {days}d deleted under `{prefix}` ({kept} kept)",
            target.name
        ),
        serde_json::json!({
            "command": "storage prune",
            "target": target.name,
            "prefix": prefix,
            "retention_days": days,
            "cutoff": cutoff,
            "deleted": deleted,
            "kept": kept,
        }),
    ))
}

/// Deletes every artifact under `prefix` whose `modified_at` is older than
/// `cutoff`, along with its manifest -- an artifact without its manifest is
/// already unrestorable and unverifiable, so leaving the manifest behind would
/// only waste the same space this command exists to reclaim.
///
/// Returns `(deleted, kept)`. One artifact that cannot be deleted stops the
/// pass and returns its error: an incomplete prune that pretends to have
/// finished is worse than one that stops and can be re-run, since `delete` is
/// already idempotent.
async fn prune_expired(
    storage: &PluginClient,
    prefix: &str,
    cutoff: &str,
) -> Result<(u32, u32), CliError> {
    let candidates = artifacts::list(storage, prefix).await?;
    let mut deleted = 0_u32;
    let mut kept = 0_u32;

    for artifact in candidates {
        if !is_expired(&artifact, cutoff) {
            kept += 1;
            continue;
        }
        artifacts::delete(storage, &artifact.key).await?;
        artifacts::delete(storage, &manifest_key_for(&artifact.key)).await?;
        deleted += 1;
    }
    Ok((deleted, kept))
}

/// Whether `artifact` is older than `cutoff`.
///
/// Both are the same fixed-width `YYYY-MM-DDTHH:MM:SSZ` shape, always UTC, so
/// comparing them as strings agrees with comparing them as instants -- the
/// same property `sb-plugin-r2::admin` relies on to keep two storage targets'
/// timestamps sortable against each other. An artifact whose storage target
/// did not report `modified_at` is left alone: an unknown age is not the same
/// as an old one, and deleting on a guess is the one mistake this command
/// cannot recover from.
fn is_expired(artifact: &ArtifactMeta, cutoff: &str) -> bool {
    !artifact.modified_at.is_empty() && artifact.modified_at.as_str() < cutoff
}

/// The `modified_at` cutoff: `now` minus `days`, in the same shape the storage
/// targets report. Built from a Unix timestamp, the same way
/// [`sb_core::naming`] builds `{timestamp}`, rather than through `Duration`
/// subtraction: a `u32` count of days that overflows the representable range
/// falls back to the epoch, which prunes everything instead of panicking mid
/// backup-maintenance run.
fn cutoff_timestamp(now: OffsetDateTime, days: u32) -> String {
    let seconds = i64::from(days).saturating_mul(86_400);
    let cutoff = OffsetDateTime::from_unix_timestamp(now.unix_timestamp().saturating_sub(seconds))
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        cutoff.year(),
        u8::from(cutoff.month()),
        cutoff.day(),
        cutoff.hour(),
        cutoff.minute(),
        cutoff.second()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(key: &str, modified_at: &str) -> ArtifactMeta {
        ArtifactMeta {
            key: key.into(),
            size: 0,
            modified_at: modified_at.into(),
        }
    }

    #[test]
    fn an_artifact_older_than_the_cutoff_is_expired() {
        assert!(is_expired(
            &artifact("a", "2026-01-01T00:00:00Z"),
            "2026-01-05T00:00:00Z"
        ));
    }

    #[test]
    fn an_artifact_newer_than_the_cutoff_is_kept() {
        assert!(!is_expired(
            &artifact("a", "2026-01-10T00:00:00Z"),
            "2026-01-05T00:00:00Z"
        ));
    }

    #[test]
    fn an_artifact_without_a_reported_age_is_never_guessed_at() {
        // Deleting on a guess is the one mistake `prune` cannot take back.
        assert!(!is_expired(&artifact("a", ""), "2026-01-05T00:00:00Z"));
    }

    #[test]
    fn the_cutoff_is_five_days_before_now() {
        let now = OffsetDateTime::from_unix_timestamp(1_768_000_000).unwrap();
        let cutoff = cutoff_timestamp(now, 5);
        let expected = OffsetDateTime::from_unix_timestamp(1_768_000_000 - 5 * 86_400).unwrap();
        assert_eq!(
            cutoff,
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                expected.year(),
                u8::from(expected.month()),
                expected.day(),
                expected.hour(),
                expected.minute(),
                expected.second()
            )
        );
    }

    #[test]
    fn a_retention_that_would_overflow_falls_back_to_the_epoch_instead_of_panicking() {
        let now = OffsetDateTime::now_utc();
        let cutoff = cutoff_timestamp(now, u32::MAX);
        assert_eq!(cutoff, "1970-01-01T00:00:00Z");
    }
}
