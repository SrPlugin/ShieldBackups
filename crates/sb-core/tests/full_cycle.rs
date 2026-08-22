// Same as in `backup_mock.rs`: this file is all test code and there an `unwrap`
// is exactly what is wanted —for the test to blow up right where it failed—.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The full cycle: backup → verify → restore, against `sb-plugin-mock`.
//!
//! `backup_mock.rs` checks that the artifact reaches the storage. That is not
//! enough: **a backup that does not restore is not a backup**. What is proved
//! here is the only thing that justifies the whole project —that the bytes that
//! came out of the engine go back into it, identical, after crossing the process
//! boundary four times and three pipeline layers— and the property that makes
//! that checkable without risking anything: that `verify` does not need the
//! private key.

mod common;

use common::{RESTORED_FILE, engine_data, prepare, request};

use sb_core::ops::backup::run_backup;
use sb_core::ops::restore::{RestoreRequest, run_restore};
use sb_core::ops::verify::run_verify;
use sb_crypto::{CompressionLevel, Digest, Identity};

/// What the engine received via `Restore`.
fn restored(dir: &std::path::Path) -> Vec<u8> {
    std::fs::read(dir.join(RESTORED_FILE)).unwrap()
}

#[tokio::test]
async fn the_full_cycle_reproduces_the_original_data_byte_for_byte() {
    // THIS is the test that justifies the project. Everything else is support.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (seed, size) = (7_u64, 2 * 1024 * 1024_usize);
    let (engine, storage) = prepare(dir.path(), 7, 2 * 1024 * 1024).await;

    let backup = run_backup(request(&engine, &storage, "cycle/artifact.age", &id))
        .await
        .unwrap();

    // 1. Verify before restoring: it is the order in which someone who has just
    //    lost the database would do it.
    let v = run_verify(&storage, "cycle/artifact.age").await.unwrap();
    assert!(v.ok, "a freshly uploaded artifact must verify");
    assert_eq!(v.actual_digest, backup.summary.ciphertext_sha256.to_hex());
    assert_eq!(v.bytes, backup.summary.ciphertext_bytes);

    // 2. Restore against the engine.
    let written = run_restore(RestoreRequest {
        engine: &engine,
        storage: &storage,
        artifact_key: "cycle/artifact.age".into(),
        identity: &id,
        expected_ciphertext_sha256: Some(backup.summary.ciphertext_sha256),
    })
    .await
    .unwrap();

    assert_eq!(written, u64::try_from(size).unwrap());
    assert_eq!(
        restored(dir.path()),
        engine_data(seed, size),
        "the full cycle did not reproduce the original data"
    );

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn verify_does_not_need_the_private_key() {
    // The reason the pipeline hashes the ciphertext and not the plaintext: a
    // machine can check that its backups are still intact without having anything
    // to read them with. `run_verify` does not even receive an `Identity`, so the
    // type guarantees it; the test writes it down.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (engine, storage) = prepare(dir.path(), 13, 512 * 1024).await;

    let backup = run_backup(request(&engine, &storage, "nokey.age", &id))
        .await
        .unwrap();

    // The identity is destroyed before verifying: from here on there is nothing
    // to decrypt anything with.
    drop(id);

    let v = run_verify(&storage, "nokey.age").await.unwrap();
    assert!(v.ok);
    assert_eq!(v.expected_digest, backup.summary.ciphertext_sha256.to_hex());
    assert_eq!(v.actual_digest, v.expected_digest);

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn verify_detects_a_corrupt_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (engine, storage) = prepare(dir.path(), 21, 256 * 1024).await;

    let backup = run_backup(request(&engine, &storage, "corrupt.age", &id))
        .await
        .unwrap();

    // A single bit, in the middle of the artifact and without touching the
    // manifest: it is exactly what a dying disk does.
    let path = dir.path().join("corrupt.age");
    let mut bytes = std::fs::read(&path).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();

    let v = run_verify(&storage, "corrupt.age").await.unwrap();
    assert!(!v.ok, "an artifact with one bit flipped cannot come out ok");
    assert_eq!(v.expected_digest, backup.summary.ciphertext_sha256.to_hex());
    assert_ne!(v.actual_digest, v.expected_digest);
    assert_eq!(
        v.bytes, backup.summary.ciphertext_bytes,
        "the size did not change: what gives it away is the digest"
    );

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn verify_detects_a_truncated_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (engine, storage) = prepare(dir.path(), 22, 256 * 1024).await;

    let backup = run_backup(request(&engine, &storage, "truncated.age", &id))
        .await
        .unwrap();

    let path = dir.path().join("truncated.age");
    let bytes = std::fs::read(&path).unwrap();
    std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();

    let v = run_verify(&storage, "truncated.age").await.unwrap();
    assert!(!v.ok);
    assert!(
        v.bytes < backup.summary.ciphertext_bytes,
        "here both give it away: the size and the digest"
    );
    assert_ne!(v.actual_digest, v.expected_digest);

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn verify_without_a_manifest_fails_saying_which_key_it_looked_for() {
    // Without a manifest there is nothing to compare against. The message has to
    // say the exact key that was looked up: whoever reads it at three in the
    // morning needs to know whether the manifest was lost or whether it was never
    // called that.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (engine, storage) = prepare(dir.path(), 4, 64 * 1024).await;

    run_backup(request(&engine, &storage, "orphan.age", &id))
        .await
        .unwrap();
    std::fs::remove_file(dir.path().join("orphan.age.manifest.json")).unwrap();

    let text = run_verify(&storage, "orphan.age")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        text.contains("orphan.age.manifest.json"),
        "the error must name the key it looked for: {text}"
    );
    assert!(text.contains("manifest"), "and say what is missing: {text}");

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn restore_checks_the_expected_digest() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (seed, size) = (31_u64, 128 * 1024_usize);
    let (engine, storage) = prepare(dir.path(), 31, 128 * 1024).await;

    let backup = run_backup(request(&engine, &storage, "digest.age", &id))
        .await
        .unwrap();

    // With the right digest: it restores.
    run_restore(RestoreRequest {
        engine: &engine,
        storage: &storage,
        artifact_key: "digest.age".into(),
        identity: &id,
        expected_ciphertext_sha256: Some(backup.summary.ciphertext_sha256),
    })
    .await
    .unwrap();
    assert_eq!(restored(dir.path()), engine_data(seed, size));

    // With a digest that is not its own: it fails, even though the artifact is
    // perfectly decryptable. It is the check that the storage served the artifact
    // the manifest says, and not another one.
    let fake = Digest::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
        .unwrap();
    let error = run_restore(RestoreRequest {
        engine: &engine,
        storage: &storage,
        artifact_key: "digest.age".into(),
        identity: &id,
        expected_ciphertext_sha256: Some(fake),
    })
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("digest"),
        "the error must explain that the digest does not match: {error}"
    );

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn restore_with_a_foreign_identity_fails_without_leaving_usable_data() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let intruder = Identity::generate();
    let (engine, storage) = prepare(dir.path(), 41, 512 * 1024).await;

    run_backup(request(&engine, &storage, "foreign.age", &id))
        .await
        .unwrap();

    let error = run_restore(RestoreRequest {
        engine: &engine,
        storage: &storage,
        artifact_key: "foreign.age".into(),
        identity: &intruder,
        expected_ciphertext_sha256: None,
    })
    .await
    .unwrap_err();
    assert!(!error.to_string().is_empty());

    // age fails while reading the header, before delivering a single block: the
    // engine never receives anything. What cannot happen under any circumstance
    // is that a file with real data is left behind.
    let path = dir.path().join(RESTORED_FILE);
    let left = if path.exists() {
        std::fs::read(&path).unwrap()
    } else {
        Vec::new()
    };
    assert!(
        left.is_empty(),
        "a foreign identity left {} bytes of plaintext in the engine",
        left.len()
    );

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn the_full_cycle_works_with_an_odd_size_and_several_levels() {
    // A size that is not a multiple of anything forces the last partial block in
    // all three layers at once, which is where the bug of a badly ordered close
    // lives.
    let size = 1024 * 1024 + 13_usize;
    let seed = 77_u64;

    for level in [1_i32, 3, 19] {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate();
        let (engine, storage) = prepare(dir.path(), 77, 1024 * 1024 + 13).await;

        let backup = run_backup(sb_core::ops::backup::BackupRequest {
            level: CompressionLevel::new(level).unwrap(),
            ..request(&engine, &storage, "odd.age", &id)
        })
        .await
        .unwrap();
        assert_eq!(backup.summary.plaintext_bytes, u64::try_from(size).unwrap());

        assert!(
            run_verify(&storage, "odd.age").await.unwrap().ok,
            "verify failed at level {level}"
        );

        let written = run_restore(RestoreRequest {
            engine: &engine,
            storage: &storage,
            artifact_key: "odd.age".into(),
            identity: &id,
            expected_ciphertext_sha256: Some(backup.summary.ciphertext_sha256),
        })
        .await
        .unwrap();

        assert_eq!(written, u64::try_from(size).unwrap(), "level {level}");
        assert_eq!(
            restored(dir.path()),
            engine_data(seed, size),
            "the cycle did not reproduce the data at level {level}"
        );

        engine.shutdown().await.unwrap();
        storage.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn the_full_cycle_of_an_empty_source() {
    // Zero bytes is the case that reveals a skipped layer close: the artifact has
    // the right shape and does not restore.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (engine, storage) = prepare(dir.path(), 1, 0).await;

    let backup = run_backup(request(&engine, &storage, "empty.age", &id))
        .await
        .unwrap();
    assert_eq!(backup.summary.plaintext_bytes, 0);

    let v = run_verify(&storage, "empty.age").await.unwrap();
    assert!(v.ok);
    assert_eq!(v.bytes, backup.summary.ciphertext_bytes);
    assert!(v.bytes > 0, "age header and zstd frame");

    let written = run_restore(RestoreRequest {
        engine: &engine,
        storage: &storage,
        artifact_key: "empty.age".into(),
        identity: &id,
        expected_ciphertext_sha256: Some(backup.summary.ciphertext_sha256),
    })
    .await
    .unwrap();

    assert_eq!(written, 0);
    assert!(restored(dir.path()).is_empty());

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn the_manifest_can_be_read_without_downloading_the_artifact() {
    // `restore` needs the digest the manifest promises **before** moving a byte,
    // just like `verify`. That reading the manifest is an operation of its own is
    // what stops each of them from having its own idea of what it is called and
    // what it contains.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (engine, storage) = prepare(dir.path(), 5, 32 * 1024).await;

    let backup = run_backup(request(&engine, &storage, "manifest.age", &id))
        .await
        .unwrap();

    let m = sb_core::ops::verify::read_manifest(&storage, "manifest.age")
        .await
        .unwrap();
    assert_eq!(m.artifact_key, "manifest.age");
    assert_eq!(m.target, "test");
    assert_eq!(
        m.ciphertext_sha256,
        backup.summary.ciphertext_sha256.to_hex()
    );
    assert_eq!(m.ciphertext_bytes, backup.summary.ciphertext_bytes);

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}
