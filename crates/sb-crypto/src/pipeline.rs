//! Composition of the three layers: `zstd → age → SHA-256`.

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    AgeError, CompressionLevel, Digest, Identity, Recipient, Sha256Reader, Sha256Writer,
    compressor, decompressor, decrypt_from, encrypt_to,
};

#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Age(#[from] AgeError),
    #[error("digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },
}

pub struct BackupOptions {
    pub recipient: Recipient,
    pub level: CompressionLevel,
}

/// What has to be stored in the manifest in order to verify and restore later.
#[derive(Debug, Clone, Copy)]
pub struct BackupSummary {
    pub plaintext_bytes: u64,
    pub ciphertext_bytes: u64,
    pub plaintext_sha256: Digest,
    pub ciphertext_sha256: Digest,
}

/// Reads from `source`, compresses, encrypts, hashes and writes to `sink`.
///
/// Memory usage is constant and independent of the size of the input.
///
/// The layer order is `zstd → age → SHA-256`: it is the ciphertext that gets
/// hashed, so an artifact can be verified at the target without having the
/// private key.
///
/// The **shutdown** order matters just as much, and it is the reason for the
/// nested block: zstd must emit its final frame inside the age layer, and age
/// must close its last AEAD block before the last hashed byte is counted.
/// Reversing that produces a truncated artifact whose failure does not surface
/// until the restore.
///
/// # Errors
/// Returns an error if reading, encrypting or writing fails.
pub async fn backup<R, W>(
    source: R,
    sink: W,
    opts: &BackupOptions,
) -> Result<BackupSummary, PipelineError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut hashed_source = Sha256Reader::new(source);
    let mut hasher = Sha256Writer::new(sink);

    let plaintext_bytes = {
        let encryptor = encrypt_to(&mut hasher, &opts.recipient).await?;
        let mut encoder = compressor(encryptor, opts.level);

        let copied = tokio::io::copy(&mut hashed_source, &mut encoder).await?;

        // Shut down in order: zstd first (it emits its final frame inside age),
        // then age (it closes the AEAD block and writes to the hasher).
        encoder.shutdown().await?;
        let mut encryptor = encoder.into_inner();
        encryptor.shutdown().await?;

        copied
    };

    hasher.shutdown().await?;
    let (_, ciphertext_sha256, ciphertext_bytes) = hasher.into_parts();

    Ok(BackupSummary {
        plaintext_bytes,
        ciphertext_bytes,
        plaintext_sha256: hashed_source.digest(),
        ciphertext_sha256,
    })
}

pub struct RestoreOptions<'a> {
    pub identity: &'a Identity,
    /// If supplied, it is checked against the digest of the artifact that was
    /// read, and the restore fails when they do not match.
    pub expected_ciphertext_sha256: Option<Digest>,
}

/// Reads an artifact from `source`, decrypts, decompresses and writes to `sink`.
///
/// # Integrity, and why two checks are needed
///
/// The age AEAD verifies every block as it is read, so a tampered ciphertext
/// fails on read. The extra digest check catches something different: that the
/// target served a **different** artifact from the one the manifest recorded.
///
/// The digest can only be checked **after** the whole stream has been read,
/// because until then it is not complete. By that point `sink` has already
/// received data.
///
/// # Warning for callers of this function
///
/// age delivers already-verified AEAD blocks incrementally. Faced with a
/// truncated artifact, the read fails **after** having written to `sink`
/// everything that came before the cut — legitimate plaintext, but partial.
///
/// Therefore: **if this function returns `Err`, everything written to `sink`
/// must be discarded, not merely no longer written to.** Keeping what arrived
/// before the failure means keeping half a database with no sign that that is
/// what it is.
///
/// # Errors
/// Returns an error if the artifact is not addressed to `identity`, if it is
/// corrupt or truncated, or if the digest does not match the expected one.
pub async fn restore<R, W>(
    source: R,
    sink: W,
    opts: &RestoreOptions<'_>,
) -> Result<u64, PipelineError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut hashed_source = Sha256Reader::new(source);
    let mut sink = sink;

    let written = {
        let decryptor = decrypt_from(&mut hashed_source, opts.identity).await?;
        let mut decoder = decompressor(decryptor);
        tokio::io::copy(&mut decoder, &mut sink).await?
    };
    sink.flush().await?;

    if let Some(expected) = opts.expected_ciphertext_sha256 {
        let actual = hashed_source.digest();
        if actual != expected {
            return Err(PipelineError::DigestMismatch {
                expected: expected.to_hex(),
                actual: actual.to_hex(),
            });
        }
    }

    Ok(written)
}

#[cfg(test)]
// The local `use` statements inside the tests are deliberate: they scope the
// extension trait to the block that needs it.
#[allow(clippy::items_after_statements)]
mod tests {
    use super::*;
    use crate::{CompressionLevel, Identity, Sha256Writer};

    #[tokio::test]
    async fn produces_both_digests_and_the_sizes() {
        let id = Identity::generate();
        let data = b"content ".repeat(1000);
        let mut target = Vec::new();

        let summary = backup(
            &data[..],
            &mut target,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        assert_eq!(summary.plaintext_bytes, data.len() as u64);
        assert_eq!(summary.ciphertext_bytes, target.len() as u64);
        assert_ne!(summary.plaintext_sha256, summary.ciphertext_sha256);

        // The ciphertext digest must match what was actually written.
        use tokio::io::AsyncWriteExt;
        let mut w = Sha256Writer::new(Vec::new());
        w.write_all(&target).await.unwrap();
        w.shutdown().await.unwrap();
        assert_eq!(w.into_parts().1, summary.ciphertext_sha256);
    }

    #[tokio::test]
    async fn the_plaintext_digest_is_the_digest_of_the_input() {
        // Without this, `plaintext_sha256` could be anything and nobody would
        // notice: it is the only value in the manifest that cannot be
        // recomputed from the artifact without the private key.
        let id = Identity::generate();
        let data = b"known input".repeat(100);

        let mut expected = Sha256Writer::new(Vec::new());
        {
            use tokio::io::AsyncWriteExt;
            expected.write_all(&data).await.unwrap();
            expected.shutdown().await.unwrap();
        }
        let expected_digest = expected.into_parts().1;

        let mut target = Vec::new();
        let summary = backup(
            &data[..],
            &mut target,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        assert_eq!(summary.plaintext_sha256, expected_digest);
    }

    #[tokio::test]
    async fn the_artifact_is_compressed_and_encrypted() {
        let id = Identity::generate();
        let data = vec![0_u8; 500_000];
        let mut target = Vec::new();

        backup(
            &data[..],
            &mut target,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        assert!(
            target.len() < 10_000,
            "500 KB of zeros must compress enormously"
        );
        assert!(
            !target.windows(4).any(|w| w == [0, 0, 0, 0]),
            "an encrypted artifact must not contain long runs of zeros"
        );
    }

    #[tokio::test]
    async fn works_with_empty_input() {
        let id = Identity::generate();
        let mut target = Vec::new();

        let summary = backup(
            &b""[..],
            &mut target,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        assert_eq!(summary.plaintext_bytes, 0);
        assert!(
            !target.is_empty(),
            "an age header and a zstd frame must still be emitted"
        );
    }

    #[tokio::test]
    async fn two_backups_of_the_same_content_give_the_same_plaintext_digest() {
        // The ciphertext differs between runs (age uses a random file key), but
        // the plaintext digest must not depend on that.
        let id = Identity::generate();
        let data = b"stable content".repeat(50);

        let mut d1 = Vec::new();
        let r1 = backup(
            &data[..],
            &mut d1,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        let mut d2 = Vec::new();
        let r2 = backup(
            &data[..],
            &mut d2,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        assert_eq!(r1.plaintext_sha256, r2.plaintext_sha256);
        assert_ne!(r1.ciphertext_sha256, r2.ciphertext_sha256);
    }

    #[tokio::test]
    async fn the_compression_level_reaches_the_zstd_layer() {
        // The input is deliberately large and only partly compressible. An
        // earlier version of this test used 90 KB of repeated text and was
        // flaky: the artifact came out at 300-400 bytes, where the variance of
        // zstd's framing dominates the real difference between levels and the
        // comparison turned into a coin flip. With several megabytes of
        // dump-like content, the difference between level 1 and level 19 is
        // orders of magnitude above that noise.
        let id = Identity::generate();
        let data = dump_like_data(4 * 1024 * 1024);

        let compress_at = |level: i32| {
            let data = &data;
            let rec = id.to_recipient();
            async move {
                let mut out = Vec::new();
                backup(
                    &data[..],
                    &mut out,
                    &BackupOptions {
                        recipient: rec,
                        level: CompressionLevel::new(level).unwrap(),
                    },
                )
                .await
                .unwrap();
                out.len()
            }
        };

        let low = compress_at(1).await;
        let high = compress_at(19).await;

        assert!(
            high < low,
            "the level is not reaching zstd: level 1 gave {low} bytes and level 19 gave {high}"
        );
    }

    /// Content resembling a database dump: a bounded, highly repetitive
    /// vocabulary, but with enough variation for the compression level to
    /// change the result measurably.
    fn dump_like_data(bytes: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes + 128);
        let mut x: u32 = 0x1234_5678;
        while out.len() < bytes {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let n = x % 10_000;
            out.extend_from_slice(
                format!("INSERT INTO customers VALUES ({n}, 'customer-{n}', '2026-08-21');\n")
                    .as_bytes(),
            );
        }
        out.truncate(bytes);
        out
    }

    #[tokio::test]
    async fn full_round_trip() {
        let id = Identity::generate();
        let data = b"any database content whatsoever ".repeat(2000);

        let mut artifact = Vec::new();
        let summary = backup(
            &data[..],
            &mut artifact,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        let mut restored = Vec::new();
        restore(
            &artifact[..],
            &mut restored,
            &RestoreOptions {
                identity: &id,
                expected_ciphertext_sha256: Some(summary.ciphertext_sha256),
            },
        )
        .await
        .unwrap();

        assert_eq!(restored, data);
    }

    #[tokio::test]
    async fn round_trip_of_empty_input() {
        // The case that exposes a skipped layer shutdown: a truncated artifact
        // has the right shape but does not restore.
        let id = Identity::generate();
        let mut artifact = Vec::new();
        let summary = backup(
            &b""[..],
            &mut artifact,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        let mut restored = Vec::new();
        let written = restore(
            &artifact[..],
            &mut restored,
            &RestoreOptions {
                identity: &id,
                expected_ciphertext_sha256: Some(summary.ciphertext_sha256),
            },
        )
        .await
        .unwrap();

        assert_eq!(written, 0);
        assert!(restored.is_empty());
    }

    #[tokio::test]
    async fn round_trip_with_bulk_data_at_several_levels() {
        // Forces several AEAD blocks and several zstd frames.
        let id = Identity::generate();
        let data: Vec<u8> = (0..400_000_u32).map(|i| (i % 251) as u8).collect();

        for level in [1_i32, 3, 19] {
            let mut artifact = Vec::new();
            let summary = backup(
                &data[..],
                &mut artifact,
                &BackupOptions {
                    recipient: id.to_recipient(),
                    level: CompressionLevel::new(level).unwrap(),
                },
            )
            .await
            .unwrap();

            let mut restored = Vec::new();
            restore(
                &artifact[..],
                &mut restored,
                &RestoreOptions {
                    identity: &id,
                    expected_ciphertext_sha256: Some(summary.ciphertext_sha256),
                },
            )
            .await
            .unwrap();

            assert_eq!(restored, data, "failed at level {level}");
        }
    }

    #[tokio::test]
    async fn a_digest_that_does_not_match_aborts_the_restore() {
        let id = Identity::generate();
        let mut artifact = Vec::new();
        backup(
            &b"data"[..],
            &mut artifact,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        let bogus =
            Digest::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();

        let mut restored = Vec::new();
        let err = restore(
            &artifact[..],
            &mut restored,
            &RestoreOptions {
                identity: &id,
                expected_ciphertext_sha256: Some(bogus),
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(err, PipelineError::DigestMismatch { .. }));
    }

    #[tokio::test]
    async fn a_truncated_artifact_fails() {
        let id = Identity::generate();
        let mut artifact = Vec::new();
        backup(
            &vec![3_u8; 200_000][..],
            &mut artifact,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        artifact.truncate(artifact.len() / 2);

        let mut restored = Vec::new();
        assert!(
            restore(
                &artifact[..],
                &mut restored,
                &RestoreOptions {
                    identity: &id,
                    expected_ciphertext_sha256: None,
                }
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn a_foreign_identity_cannot_restore() {
        let id = Identity::generate();
        let intruder = Identity::generate();
        let mut artifact = Vec::new();
        backup(
            &b"secret"[..],
            &mut artifact,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        let mut restored = Vec::new();
        assert!(
            restore(
                &artifact[..],
                &mut restored,
                &RestoreOptions {
                    identity: &intruder,
                    expected_ciphertext_sha256: None,
                }
            )
            .await
            .is_err()
        );
    }
}
