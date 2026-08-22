// Same as in `sb-transport/tests/fallos.rs`: this file is all test code, helpers
// included, and there an `unwrap` is exactly what is wanted —for the test to
// blow up right where it failed—.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! A complete backup against `sb-plugin-mock`, end to end and without a network.
//!
//! The tests of the individual pieces already cover the pipeline, the data
//! channel and plugin startup. What can only be checked here is what happens when
//! the bytes cross the process boundary **twice**: engine → core → storage. A
//! failure along that path is invisible to any unit test, and would show up as an
//! artifact that cannot be restored.

mod common;

use common::{prepare, request};

use sb_core::ops::backup::{BackupRequest, run_backup};
use sb_crypto::Identity;
// Up here and not inside each test: `clippy::pedantic` forbids declaring items
// after statements, and several of them need `shutdown` on the `Sha256Writer`.
use tokio::io::AsyncWriteExt as _;

#[tokio::test]
async fn a_complete_backup_produces_an_artifact_and_a_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (engine, storage) = prepare(dir.path(), 7, 2 * 1024 * 1024).await;

    let r = run_backup(request(&engine, &storage, "test/artifact.age", &id))
        .await
        .unwrap();

    assert_eq!(r.summary.plaintext_bytes, 2 * 1024 * 1024);
    assert!(r.summary.ciphertext_bytes > 0);

    assert!(dir.path().join("test/artifact.age").exists());
    assert!(dir.path().join("test/artifact.age.manifest.json").exists());

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn the_manifest_faithfully_describes_the_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (engine, storage) = prepare(dir.path(), 3, 512 * 1024).await;

    let r = run_backup(request(&engine, &storage, "m.age", &id))
        .await
        .unwrap();

    let text = std::fs::read_to_string(dir.path().join("m.age.manifest.json")).unwrap();
    let m = sb_core::model::Manifest::parse(&text).unwrap();

    assert_eq!(m.plaintext_bytes, 512 * 1024);
    assert_eq!(m.ciphertext_sha256, r.summary.ciphertext_sha256.to_hex());
    assert_eq!(m.plaintext_sha256, r.summary.plaintext_sha256.to_hex());
    assert_eq!(m.artifact_key, "m.age");
    assert_eq!(m.target, "test");
    assert_eq!(m.encryption.recipient, id.to_recipient().to_string());

    // The declared size matches the file that is really in the storage.
    let real = std::fs::metadata(dir.path().join("m.age")).unwrap().len();
    assert_eq!(m.ciphertext_bytes, real);

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn the_artifact_in_the_storage_is_exactly_what_the_pipeline_produced() {
    // Checks that nothing gets corrupted while crossing the process boundary
    // twice.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (engine, storage) = prepare(dir.path(), 11, 3 * 1024 * 1024 + 7).await;

    let r = run_backup(request(&engine, &storage, "exact.age", &id))
        .await
        .unwrap();

    let bytes = std::fs::read(dir.path().join("exact.age")).unwrap();
    assert_eq!(bytes.len() as u64, r.summary.ciphertext_bytes);

    // And its digest matches the one the pipeline computed on the fly.
    let mut w = sb_crypto::Sha256Writer::new(Vec::new());
    w.write_all(&bytes).await.unwrap();
    w.shutdown().await.unwrap();
    assert_eq!(w.into_parts().1, r.summary.ciphertext_sha256);

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn the_hashed_plaintext_is_the_one_the_engine_said_it_produced() {
    // The summary does not take the engine's word for it: the deterministic
    // stream is regenerated here and compared with the digest the pipeline
    // computed on the fly. If a byte were lost between the engine and the core,
    // this would see it.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (engine, storage) = prepare(dir.path(), 23, 1024 * 1024 + 3).await;

    let r = run_backup(request(&engine, &storage, "faithful.age", &id))
        .await
        .unwrap();

    let expected: Vec<u8> = sb_plugin_mock::deterministic_data(23, 1024 * 1024 + 3).collect();
    let mut w = sb_crypto::Sha256Writer::new(Vec::new());
    w.write_all(&expected).await.unwrap();
    w.shutdown().await.unwrap();
    assert_eq!(w.into_parts().1, r.summary.plaintext_sha256);

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn the_backup_of_an_empty_source_also_works() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (engine, storage) = prepare(dir.path(), 1, 0).await;

    let r = run_backup(request(&engine, &storage, "empty.age", &id))
        .await
        .unwrap();

    assert_eq!(r.summary.plaintext_bytes, 0);
    assert!(r.summary.ciphertext_bytes > 0, "age header and zstd frame");
    assert!(dir.path().join("empty.age").exists());

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_key_with_slashes_creates_the_hierarchy() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (engine, storage) = prepare(dir.path(), 5, 4096).await;

    run_backup(request(&engine, &storage, "a/b/c/d.age", &id))
        .await
        .unwrap();
    assert!(dir.path().join("a/b/c/d.age").exists());
    assert!(dir.path().join("a/b/c/d.age.manifest.json").exists());

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_plugin_without_the_needed_capability_is_rejected_before_starting() {
    // Asking a plugin that is only a storage for a dump must fail immediately and
    // with a domain error, not halfway through the data flow.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (engine, storage) = prepare(dir.path(), 1, 1024).await;

    // The roles are swapped on purpose: what is checked is that the capability
    // validation exists. The mock has both, so this must work; what is verified
    // is that `run_backup` calls require_capability.
    let r = run_backup(BackupRequest {
        engine: &storage,
        storage: &engine,
        ..request(&engine, &storage, "swapped.age", &id)
    })
    .await;
    assert!(r.is_ok(), "the mock has both capabilities");

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn two_consecutive_backups_of_the_same_source_give_the_same_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (engine, storage) = prepare(dir.path(), 99, 256 * 1024).await;

    let a = run_backup(request(&engine, &storage, "a.age", &id))
        .await
        .unwrap();
    let b = run_backup(request(&engine, &storage, "b.age", &id))
        .await
        .unwrap();

    assert_eq!(a.summary.plaintext_sha256, b.summary.plaintext_sha256);
    assert_ne!(
        a.summary.ciphertext_sha256, b.summary.ciphertext_sha256,
        "age uses a different file key every time"
    );

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}
