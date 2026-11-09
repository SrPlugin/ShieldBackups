//! `shieldbk restore <target> <artifact> --identity <path>`.
//!
//! It is the only command that needs the private key, and that is why it is the
//! only one that asks for it explicitly in an argument instead of taking it
//! from the configuration: a private key referenced from a file that gets
//! versioned would end up, sooner or later, inside the repository.
//!
//! Before moving a byte the manifest is read to learn which digest the artifact
//! the storage target is about to serve should have. It is not redundant with
//! age's AEAD: a **foreign** but well-formed artifact addressed to the same
//! identity would decrypt without complaint, and without the digest nobody
//! would notice the database has been restored with another system's backup.

use std::path::Path;

use sb_core::ops::restore::{RestoreRequest, run_restore};
use sb_core::ops::verify::read_manifest;
use sb_crypto::{Digest, Identity};

use crate::context::Context;
use crate::error::CliError;
use crate::output::Report;
use crate::plugins::{self, Role};

/// # Errors
/// Returns [`CliError::Config`] if the target does not exist or the identity
/// cannot be read, [`CliError::Plugin`] if some plugin does not start and
/// [`CliError::Operation`] if the restore fails.
pub async fn run(
    ctx: &Context,
    target: &str,
    artifact: &str,
    identity: &Path,
) -> Result<Report, CliError> {
    let target = ctx.target(target)?;
    let identity = read_identity(identity)?;

    let source = plugins::start_for(ctx, target, Role::Source).await?;
    let storage = match plugins::start_for(ctx, target, Role::Storage).await {
        Ok(storage) => storage,
        Err(error) => {
            plugins::close(source).await;
            return Err(error);
        }
    };

    let outcome = restore(&source, &storage, artifact, &identity).await;

    plugins::close(source).await;
    plugins::close(storage).await;

    let written = outcome?;
    Ok(Report::new(
        format!("{}: restored {written} bytes from {artifact}", target.name),
        serde_json::json!({
            "command": "restore",
            "target": target.name,
            "artifact_key": artifact,
            "plaintext_bytes": written,
        }),
    ))
}

async fn restore(
    source: &sb_core::plugin::PluginClient,
    storage: &sb_core::plugin::PluginClient,
    artifact: &str,
    identity: &Identity,
) -> Result<u64, CliError> {
    Ok(run_restore(RestoreRequest {
        source,
        storage,
        artifact_key: artifact.to_owned(),
        identity,
        expected_ciphertext_sha256: expected_digest(storage, artifact).await,
    })
    .await?)
}

/// The digest the manifest says `artifact` has, if there is a manifest to ask.
///
/// The manifest may be missing -- an artifact copied by hand, a half-migrated
/// storage target -- and that cannot stop a restore: if it is missing, a
/// warning is issued and the extra check is skipped. Refusing would mean
/// leaving unrecovered data that can in fact be recovered. `drill` goes through
/// the same function, so the two cannot disagree about it.
pub(super) async fn expected_digest(
    storage: &sb_core::plugin::PluginClient,
    artifact: &str,
) -> Option<Digest> {
    match read_manifest(storage, artifact).await {
        Ok(manifest) => Digest::from_hex(&manifest.ciphertext_sha256).ok(),
        Err(source) => {
            tracing::warn!(
                key = artifact,
                %source,
                "no manifest: restoring without checking that the storage target served the \
                 artifact that was asked for"
            );
            None
        }
    }
}

/// Reads the private key file.
///
/// The error names the path but **never the content**: what was being read is a
/// private key, and a message quoting it would leave it written in the log of
/// whoever picked the wrong file.
pub(super) fn read_identity(path: &Path) -> Result<Identity, CliError> {
    let text = std::fs::read_to_string(path).map_err(|source| {
        CliError::config(format!(
            "could not read the private key `{}`: {source}",
            path.display()
        ))
    })?;

    Identity::parse(&text).map_err(|source| {
        CliError::config(format!(
            "`{}` does not contain an age private key: {source}",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identity_is_read_from_the_file_age_keygen_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.txt");
        let original = Identity::generate();
        std::fs::write(
            &path,
            format!(
                "# created: 2026-08-21T00:00:00Z\n# public key: {}\n{}\n",
                original.to_recipient(),
                original.to_secret_string().expose()
            ),
        )
        .unwrap();

        let read = read_identity(&path).unwrap();
        assert_eq!(
            read.to_recipient().to_string(),
            original.to_recipient().to_string()
        );
    }

    #[test]
    fn a_file_that_does_not_exist_is_explained_by_naming_the_path() {
        let error = read_identity(Path::new("/does/not/exist/key.txt"))
            .err()
            .unwrap();
        assert_eq!(error.class(), "config");
        assert!(error.to_string().contains("/does/not/exist/key.txt"));
    }

    #[test]
    fn a_file_that_is_not_a_key_does_not_give_away_its_content() {
        // The real case: somebody points `--identity` at the wrong file that
        // happens to contain another secret.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("other.txt");
        std::fs::write(&path, "production-password-1234").unwrap();

        let error = read_identity(&path).err().unwrap();
        assert_eq!(error.class(), "config");
        assert!(
            !error.to_string().contains("production-password-1234"),
            "the message cannot repeat what was inside: {error}"
        );
    }
}
