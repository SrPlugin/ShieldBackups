//! The backup operation: engine → core → storage, in a single pass and without
//! touching the local disk.
//!
//! ```text
//! engine-plugin ──[data socket]──▶ core ──[data socket]──▶ storage-plugin
//!                             zstd → age → SHA-256
//! ```
//!
//! The bytes cross the process boundary **twice** and at no point are they
//! materialized whole: the memory a one-terabyte backup uses is the same as that
//! of a one-megabyte one.
//!
//! # The order of the calls
//!
//! `Storage.Put` is called first and `Engine.Dump` **afterwards**, which is
//! exactly the opposite of how the diagram reads. The reason is in [`run_backup`]
//! and it is not a stylistic preference: it is the difference between a backup
//! that finishes and one that hangs.

use sb_crypto::{BackupOptions, BackupSummary, CompressionLevel, Recipient};

use crate::model::{CompressionInfo, EncryptionInfo, EngineInfo, MANIFEST_VERSION, Manifest};
use crate::ops::channel::{
    OP_DUMP, OP_PUT, accept, create_channel, start_dump, start_put, upload_blob, wait_for_progress,
};
use crate::plugin::{Capability, PluginClient};

// The error and the mechanics of the transfers belong to the three operations,
// not just to this one: they live in `ops/channel.rs`. It is re-exported here
// because `ops::backup::BackupError` is the path it is already known by.
pub use crate::ops::channel::BackupError;

/// Compression algorithm recorded in the manifest. It is fixed by the
/// `sb-crypto` pipeline, not by the configuration.
const COMPRESSION_ALGORITHM: &str = "zstd";
/// Encryption algorithm, for the same reason.
const ENCRYPTION_ALGORITHM: &str = "age";

/// Everything a backup needs, already resolved.
///
/// The plugins arrive **started and configured**: this operation does not decide
/// which plugin to use nor how to configure it, it only makes them talk.
pub struct BackupRequest<'a> {
    pub target: String,
    pub engine: &'a PluginClient,
    pub storage: &'a PluginClient,
    pub artifact_key: String,
    pub recipient: Recipient,
    pub level: CompressionLevel,
    pub engine_version: String,
    pub server_version: String,
    /// ISO-8601 timestamp in UTC. The caller computes it, so that the operation
    /// is deterministic and testable.
    pub created_at: String,
}

/// What is left of a backup that went well.
#[derive(Debug, Clone)]
pub struct BackupOutcome {
    pub summary: BackupSummary,
    pub artifact_key: String,
}

/// Runs a complete backup and leaves the artifact and its manifest in the
/// storage.
///
/// # The order of `Put` and `Dump`, deliberately counter-intuitive
///
/// `Storage.Put` is called **before** `Engine.Dump`. Reading the diagram above
/// you would say the producer goes first, and that is exactly the change
/// somebody will try to make some day.
///
/// Do not do it, and here is the reason with the measurements behind it.
///
/// The dump socket has a kernel buffer of about 208 KiB
/// (`net.core.wmem_default`). If the engine starts before the storage is in
/// place, it writes into a socket nobody is going to drain yet and blocks on its
/// `write` as soon as that buffer fills up. **What happens next depends on
/// something this code does not control: on how the plugin is written.**
///
/// Reversing the order was tried and the tests in `tests/backup_mock.rs` still
/// pass, even inserting three seconds of delay between the two calls: with
/// plugins like the mock —whose `Dump` returns the RPC headers immediately and
/// does the work in a separate task— the engine does not hang, it just stalls on
/// its `write` until the core reaches the `accept` and the pipeline starts
/// draining. That it does not show up here does not mean it does not matter:
///
/// * A plugin whose `Dump` writes **before** returning the RPC response —the
///   protocol does not forbid it— would never answer, and `Dump` first would
///   mean `Put` never gets called at all. That really is the hang, and only the
///   open deadline in `ops::channel` cuts it short.
/// * With `Dump` first, a `Put` that fails —invalid key, storage down— leaves
///   behind an engine already launched, writing into a socket that is about to
///   be closed under it. Putting `Put` first makes that failure happen before a
///   single byte has been moved.
///
/// The underlying rule is the one worth remembering: **the consumer is placed
/// before the producer**, always. It is free and it removes a whole class of
/// hangs that, by definition, do not show up in tests where everything goes
/// well.
///
/// # Errors
/// Returns [`BackupError`] if some plugin lacks the capability it is asked for,
/// if it does not connect to its data channel within the deadline, if the
/// transfer breaks or if the pipeline fails.
pub async fn run_backup(req: BackupRequest<'_>) -> Result<BackupOutcome, BackupError> {
    // 1. First of all: that each plugin can play the role it is assigned.
    //    Finding out here costs a string comparison; finding out halfway through
    //    the dump costs the dump.
    req.engine.require_capability(Capability::Engine)?;
    req.storage.require_capability(Capability::Storage)?;

    // 2. One channel per plugin, each inside the runtime directory of its owner:
    //    it is the only place that process is guaranteed to have access to.
    let dump_channel = create_channel(req.engine)?;
    let upload_channel = create_channel(req.storage)?;

    // 3 and 4. THE CONSUMER FIRST. See the note above before touching this.
    let upload = start_put(req.storage, &req.artifact_key, &upload_channel).await?;
    let dump = start_dump(req.engine, &dump_channel).await?;

    // 6. Both plugins now have their orders; now they must show up on the
    //    socket.
    let source = accept(&dump_channel, req.engine.name(), OP_DUMP).await?;
    let sink = accept(&upload_channel, req.storage.name(), OP_PUT).await?;

    // 7. The core is nothing more than the stretch of pipe between the two
    //    sockets.
    let recipient = req.recipient.to_string();
    let summary = sb_crypto::backup(
        source,
        sink,
        &BackupOptions {
            recipient: req.recipient,
            level: req.level,
        },
    )
    .await?;

    // 8. The pipeline has finished, but the plugins have not necessarily: the
    //    storage may still be closing its file. Without waiting here, the
    //    manifest could describe an artifact that is not complete yet.
    wait_for_progress(dump, req.engine.name(), OP_DUMP).await?;
    wait_for_progress(upload, req.storage.name(), OP_PUT).await?;

    // 9. The manifest goes up the same way as the artifact —another channel,
    //    another `Put`—. A second path (a separate RPC that wrote the JSON)
    //    would be shorter, but it would allow the artifact and the manifest to
    //    end up in different places or with different permissions without anyone
    //    noticing.
    let manifest = Manifest {
        version: MANIFEST_VERSION,
        target: req.target,
        engine: EngineInfo {
            plugin: req.engine.name().to_string(),
            plugin_version: req.engine_version,
            server_version: req.server_version,
        },
        created_at: req.created_at,
        artifact_key: req.artifact_key.clone(),
        plaintext_bytes: summary.plaintext_bytes,
        ciphertext_bytes: summary.ciphertext_bytes,
        plaintext_sha256: summary.plaintext_sha256.to_hex(),
        ciphertext_sha256: summary.ciphertext_sha256.to_hex(),
        compression: CompressionInfo {
            algorithm: COMPRESSION_ALGORITHM.to_string(),
            level: req.level.get(),
        },
        encryption: EncryptionInfo {
            algorithm: ENCRYPTION_ALGORITHM.to_string(),
            recipient,
        },
    };
    upload_blob(
        req.storage,
        &manifest.manifest_key(),
        manifest.to_json()?.as_bytes(),
    )
    .await?;

    tracing::info!(
        key = %req.artifact_key,
        plaintext = summary.plaintext_bytes,
        ciphertext = summary.ciphertext_bytes,
        "backup completed"
    );

    Ok(BackupOutcome {
        summary,
        artifact_key: req.artifact_key,
    })
}
