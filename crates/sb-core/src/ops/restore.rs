//! The restore operation: storage → core → source, the backup in reverse.
//!
//! ```text
//! storage-plugin ──[data socket]──▶ core ──[data socket]──▶ source-plugin
//!                          SHA-256 → age⁻¹ → zstd⁻¹
//! ```
//!
//! Just as in the backup, the bytes cross the process boundary **twice** without
//! being materialized whole anywhere.
//!
//! # The order of the calls
//!
//! Here the consumer is the **source** —it is the one receiving the dump—, so
//! `Source.Restore` is called **before** `Storage.Get`. It is the same rule as in
//! [`crate::ops::backup::run_backup`], whose doc comment carries the measured
//! reasoning: the consumer is placed before the producer.

use sb_crypto::{Digest, Identity, RestoreOptions};
use tokio::io::AsyncWriteExt as _;

use crate::ops::channel::{
    BackupError, OP_GET, OP_RESTORE, accept, create_channel, start_get, start_restore,
    wait_for_progress,
};
use crate::plugin::{Capability, PluginClient};

/// Everything a restore needs, already resolved.
///
/// The plugins arrive **started and configured**, as in the backup: this
/// operation does not choose a plugin nor resolve configuration, it only makes
/// them talk.
pub struct RestoreRequest<'a> {
    pub source: &'a PluginClient,
    pub storage: &'a PluginClient,
    pub artifact_key: String,
    /// The private key. Without it no restore is possible: it is exactly what
    /// `verify` does **not** need.
    pub identity: &'a Identity,
    /// The digest the manifest says the artifact must have.
    ///
    /// It is optional because the manifest may be missing —or the caller may
    /// already have checked it with `verify`—, but omitting it gives up on
    /// detecting that the storage served a **different** artifact from the one
    /// requested. age's AEAD does not cover that case: a well-formed foreign
    /// artifact addressed to the same identity would decrypt without complaint.
    pub expected_ciphertext_sha256: Option<Digest>,
}

/// Downloads the artifact, verifies it, decrypts it, decompresses it and hands
/// it to the source.
///
/// Returns the plaintext bytes delivered.
///
/// # Warning: an error may leave partial plaintext in the source
///
/// age delivers the AEAD blocks **already verified** incrementally, so with a
/// truncated artifact the read fails after having written everything that came
/// before the cut: legitimate plaintext, but partial (65,536 bytes were
/// measured). The same applies, and worse, to
/// [`RestoreRequest::expected_ciphertext_sha256`]: the digest can only be checked
/// once the whole stream has been read, that is, once the source has already
/// received everything.
///
/// The core does here the only thing it can do: **not** close the source's
/// channel in an orderly fashion when something fails —the source sees the cut,
/// not a normal end of stream—, abandon the transfers and return an error
/// without waiting for the plugins to say they finished well.
///
/// That is not enough, and it is worth saying it plainly: **discarding what was
/// written is the source's responsibility**, because it is the only one that
/// knows what undoing it means. In Phase 1 the concrete defence is that
/// `pg_restore` runs with `--single-transaction`, so a half-finished dump is
/// never committed. That is a defence **of the plugin**, not of the core: a
/// future source that writes files directly will have to bring its own.
///
/// # Errors
/// Returns [`BackupError`] if some plugin lacks the capability it is asked for,
/// if it does not connect to its data channel within the deadline, if the
/// transfer breaks, if the artifact is not addressed to `identity`, if it is
/// corrupt or truncated, or if its digest is not the expected one.
pub async fn run_restore(req: RestoreRequest<'_>) -> Result<u64, BackupError> {
    // 1. First of all: that each plugin can play the role it is assigned.
    //    Finding out here costs a string comparison; finding out halfway through
    //    the restore costs a half-written database.
    req.source.require_capability(Capability::Source)?;
    req.storage.require_capability(Capability::Storage)?;

    // 2. One channel per plugin, each inside the runtime directory of its owner:
    //    it is the only place that process is guaranteed to have access to.
    let source_channel = create_channel(req.source)?;
    let download_channel = create_channel(req.storage)?;

    // 3 and 4. THE CONSUMER FIRST, which here is the source. The measured reason
    //    is in the doc comment of `run_backup`.
    let write = start_restore(req.source, &source_channel).await?;
    let download = start_get(req.storage, &req.artifact_key, &download_channel).await?;

    // 5. Both plugins now have their orders; now they must show up on the
    //    socket.
    let download_stream = accept(&download_channel, req.storage.name(), OP_GET).await?;
    let mut sink = accept(&source_channel, req.source.name(), OP_RESTORE).await?;

    // 6. The core is nothing more than the stretch of pipe between the two
    //    sockets. The sink is lent instead of being given away: it has to be
    //    kept in order to decide **how** it is closed, which is the only thing
    //    that tells a complete dump apart from one cut halfway.
    let options = RestoreOptions {
        identity: req.identity,
        expected_ciphertext_sha256: req.expected_ciphertext_sha256,
    };
    let written = match sb_crypto::restore(download_stream, &mut sink, &options).await {
        Ok(written) => written,
        Err(failure) => {
            // The source may already hold partial plaintext. Its channel is cut
            // without the orderly `shutdown` and both transfers are abandoned:
            // what cannot happen is that this returns `Ok`.
            write.abort();
            download.abort();
            drop(sink);
            tracing::error!(
                key = %req.artifact_key,
                error = %failure,
                "restore aborted: the source may have received incomplete data"
            );
            return Err(failure.into());
        }
    };

    // 7. Closing the write side is what the source sees as end of stream, and
    //    therefore as "this is complete". It is only done when it really is.
    sink.shutdown().await.map_err(|source| BackupError::Io {
        plugin: req.source.name().to_string(),
        source,
    })?;

    // 8. The pipeline has finished, but the plugins have not necessarily: the
    //    source may still be closing its own work. Without waiting here, a
    //    restore could be taken as good while the source is still halfway.
    wait_for_progress(write, req.source.name(), OP_RESTORE).await?;
    wait_for_progress(download, req.storage.name(), OP_GET).await?;

    tracing::info!(
        key = %req.artifact_key,
        plaintext = written,
        "restore completed"
    );

    Ok(written)
}
