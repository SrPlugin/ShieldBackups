//! The tests that justify the project.
//!
//! Example-based tests check the cases somebody happened to think of. These
//! check properties over arbitrary inputs, which is where the bugs nobody
//! foresaw show up.

use proptest::prelude::*;
use sb_crypto::{BackupOptions, CompressionLevel, Identity, RestoreOptions, backup, restore};

// `expect` is not allowed outside `#[test]` functions, and this helper is not
// one: failing here is not a failure of the property but of the environment.
fn runtime() -> tokio::runtime::Runtime {
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => panic!("could not build the tokio runtime: {e}"),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Any sequence of bytes survives backup + restore, at any compression
    /// level.
    #[test]
    fn any_input_survives_the_cycle(
        data in prop::collection::vec(any::<u8>(), 0..200_000),
        level in 1_i32..=9,
    ) {
        runtime().block_on(async {
            let id = Identity::generate();
            let level = CompressionLevel::new(level).unwrap();

            let mut artifact = Vec::new();
            let summary = backup(&data[..], &mut artifact, &BackupOptions {
                recipient: id.to_recipient(),
                level,
            })
            .await
            .unwrap();

            prop_assert_eq!(summary.plaintext_bytes, data.len() as u64);
            prop_assert_eq!(summary.ciphertext_bytes, artifact.len() as u64);

            let mut restored = Vec::new();
            restore(&artifact[..], &mut restored, &RestoreOptions {
                identity: &id,
                expected_ciphertext_sha256: Some(summary.ciphertext_sha256),
            })
            .await
            .unwrap();

            prop_assert_eq!(restored, data);
            Ok(())
        })?;
    }

    /// Tampering with any byte of the artifact makes the restore fail.
    /// This is the property that turns "encrypted" into "authenticated
    /// encryption", and the one that stops an altered copy from being restored
    /// in silence.
    #[test]
    fn tampering_with_one_byte_is_always_detected(
        data in prop::collection::vec(any::<u8>(), 1..20_000),
        position in any::<prop::sample::Index>(),
        mask in 1_u8..=255,
    ) {
        runtime().block_on(async {
            let id = Identity::generate();
            let mut artifact = Vec::new();
            backup(&data[..], &mut artifact, &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            })
            .await
            .unwrap();

            let idx = position.index(artifact.len());
            artifact[idx] ^= mask;

            let mut restored = Vec::new();
            let result = restore(&artifact[..], &mut restored, &RestoreOptions {
                identity: &id,
                expected_ciphertext_sha256: None,
            })
            .await;

            prop_assert!(
                result.is_err(),
                "an artifact tampered with at byte {} must never restore",
                idx
            );
            Ok(())
        })?;
    }

    /// Truncating the artifact at any point is always detected.
    /// This covers the interrupted upload, which is a far more frequent failure
    /// in production than deliberate tampering.
    #[test]
    fn truncating_at_any_point_is_detected(
        data in prop::collection::vec(any::<u8>(), 5_000..50_000),
        cut in any::<prop::sample::Index>(),
    ) {
        runtime().block_on(async {
            let id = Identity::generate();
            let mut artifact = Vec::new();
            backup(&data[..], &mut artifact, &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            })
            .await
            .unwrap();

            // Any strict cut: from 0 up to len-1 bytes kept. `Index::index(len)`
            // always returns a value in `0..len`, so the cut never leaves the
            // artifact intact.
            let original = artifact.len();
            let up_to = cut.index(original);
            artifact.truncate(up_to);

            let mut restored = Vec::new();
            let result = restore(&artifact[..], &mut restored, &RestoreOptions {
                identity: &id,
                expected_ciphertext_sha256: None,
            })
            .await;

            prop_assert!(
                result.is_err(),
                "an artifact truncated to {} of {} bytes must never restore as valid",
                up_to, original
            );
            Ok(())
        })?;
    }

    /// No foreign identity can read an artifact, whatever its content.
    #[test]
    fn a_foreign_identity_can_never_restore(
        data in prop::collection::vec(any::<u8>(), 0..10_000),
    ) {
        runtime().block_on(async {
            let addressee = Identity::generate();
            let intruder = Identity::generate();

            let mut artifact = Vec::new();
            backup(&data[..], &mut artifact, &BackupOptions {
                recipient: addressee.to_recipient(),
                level: CompressionLevel::default(),
            })
            .await
            .unwrap();

            let mut restored = Vec::new();
            let result = restore(&artifact[..], &mut restored, &RestoreOptions {
                identity: &intruder,
                expected_ciphertext_sha256: None,
            })
            .await;

            prop_assert!(result.is_err(), "a foreign identity cannot decrypt");
            prop_assert!(restored.is_empty(), "and must not have written anything");
            Ok(())
        })?;
    }
}
