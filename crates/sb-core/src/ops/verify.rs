//! The verify operation: checking an artifact **without being able to read it**.
//!
//! ```text
//! storage-plugin ──[data socket]──▶ core ──▶ SHA-256 ──▶ /dev/null
//! ```
//!
//! This operation is the reason the pipeline hashes the ciphertext and not the
//! plaintext. A plaintext digest would force decryption in order to check
//! anything, and decrypting requires the private key; by hashing the ciphertext,
//! **a machine can check that its backups are still intact without having
//! anything to read them with**. That is why [`run_verify`] does not receive any
//! `Identity`: it is not that it does not use one, it is that it cannot.
//!
//! The second thing that defines this operation is what it does **not** do: it
//! does not load the artifact into memory. The bytes go from the pipe to the
//! hasher and from there to [`tokio::io::sink`], so verifying a three-hundred
//! gigabyte artifact costs the same in RAM as verifying a three kilobyte one.

use sb_crypto::Sha256Reader;

use crate::model::{Manifest, manifest_key_for};
use crate::ops::channel::{
    BackupError, OP_GET, accept, create_channel, download_blob, start_get, wait_for_progress,
};
use crate::plugin::{Capability, PluginClient};

/// The verdict on an artifact.
///
/// Both digests go inside even when they match: a report that only said
/// `ok: false` would be of no use to whoever has to decide whether the problem is
/// the artifact, the manifest or the storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOutcome {
    /// True only if **both the digest and the byte count** match.
    pub ok: bool,
    /// The one the manifest states.
    pub expected_digest: String,
    /// The one computed by reading the artifact from the storage.
    pub actual_digest: String,
    /// The bytes the storage actually served.
    pub bytes: u64,
}

/// Fetches from the storage the manifest that describes `artifact_key`.
///
/// It is the first thing [`run_verify`] does, and it lives apart because it is
/// not only its own: `restore` needs the same manifest —to know which digest the
/// artifact it is served must have— and without this it would have to repeat the
/// rule for how the key is derived and how the contents are parsed.
///
/// # Errors
/// Returns [`BackupError::NoManifest`] if it could not be fetched —the message
/// names the exact key that was looked up— or [`BackupError::Manifest`] if it
/// cannot be parsed.
pub async fn read_manifest(
    storage: &PluginClient,
    artifact_key: &str,
) -> Result<Manifest, BackupError> {
    let manifest_key = manifest_key_for(artifact_key);
    let raw = download_blob(storage, &manifest_key)
        .await
        .map_err(|source| BackupError::NoManifest {
            plugin: storage.name().to_string(),
            key: manifest_key.clone(),
            reason: source.to_string(),
        })?;
    let text = String::from_utf8(raw).map_err(|_| BackupError::NoManifest {
        plugin: storage.name().to_string(),
        key: manifest_key.clone(),
        reason: "it is not UTF-8 text".to_string(),
    })?;
    Ok(Manifest::parse(&text)?)
}

/// Downloads the artifact and checks its digest against the manifest.
///
/// That an artifact does not match is **not** an error of this function: it is
/// its answer, and it is exactly what has to be shown to the caller. It only
/// fails if a verdict cannot be reached at all: if the manifest is missing, if it
/// cannot be parsed, or if the download breaks.
///
/// # Why the manifest is read first
///
/// Without it there is nothing to compare against, and downloading a hundred
/// gigabytes only to find that out at the end is a cost that cannot be given
/// back. Besides, the asymmetry of the failure matters: "I cannot find the
/// manifest" has a remedy —look for it, restore it, check whether the key was a
/// different one— and the message says which exact key was looked up so that
/// remedy is possible.
///
/// # Errors
/// Returns [`BackupError::NoManifest`] if the manifest could not be fetched —the
/// message names the key—, [`BackupError::Manifest`] if it cannot be parsed, and
/// the transfer variants if the artifact download breaks.
pub async fn run_verify(
    storage: &PluginClient,
    artifact_key: &str,
) -> Result<VerifyOutcome, BackupError> {
    storage.require_capability(Capability::Storage)?;

    // 1. The manifest first: it is small and it is the only thing that says what
    //    is expected. It goes into memory because it fits; the artifact does
    //    not.
    let manifest = read_manifest(storage, artifact_key).await?;

    // 2. The artifact is read **as a stream**, against a sink that throws it
    //    away. The only thing that matters is what the hasher accumulates along
    //    the way: loading the artifact into memory would make verifying a large
    //    backup impossible on exactly the small machine that needs it most.
    let channel = create_channel(storage)?;
    let download = start_get(storage, artifact_key, &channel).await?;
    let source = accept(&channel, storage.name(), OP_GET).await?;

    let mut reader = Sha256Reader::new(source);
    let bytes = tokio::io::copy(&mut reader, &mut tokio::io::sink())
        .await
        .map_err(|source| BackupError::Io {
            plugin: storage.name().to_string(),
            source,
        })?;
    let actual = reader.digest().to_hex();

    // 3. The plugin may still have something to say: a `Get` that broke halfway
    //    arrives through the progress stream and not through the pipe, where all
    //    that is seen is a premature end of stream that would look like a short
    //    artifact.
    wait_for_progress(download, storage.name(), OP_GET).await?;

    // 4. Both criteria, not one: the digest covers the contents and the size
    //    covers the degenerate case of a storage serving less than it claims to
    //    have. That the second one is redundant in practice does not make it
    //    useless: it is the cheap check that also explains the failure.
    let ok = actual == manifest.ciphertext_sha256 && bytes == manifest.ciphertext_bytes;
    if !ok {
        tracing::warn!(
            key = %artifact_key,
            expected = %manifest.ciphertext_sha256,
            actual = %actual,
            bytes,
            expected_bytes = manifest.ciphertext_bytes,
            "the artifact does not match its manifest"
        );
    }

    Ok(VerifyOutcome {
        ok,
        expected_digest: manifest.ciphertext_sha256,
        actual_digest: actual,
        bytes,
    })
}
