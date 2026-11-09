// Same as in `full_cycle.rs`: this file is all test code and there an `unwrap` is
// exactly what is wanted -- for the test to blow up right where it failed.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The restore drill against `sb-plugin-mock`.
//!
//! The mock's disposable place is a directory, and the markers it understands
//! make each step fail on demand, so every branch of
//! [`sb_core::ops::drill::run_drill`] is taken here with real plugin processes:
//! it passes, the check does not hold, the check cannot be asked, the provision
//! fails, the restore fails, and the teardown fails.
//!
//! Two properties run through all of them and are asserted in each:
//!
//! - **The drill never writes where the backup comes from.** `restore.bin` in the
//!   plugin's own directory is the thing a plain restore would have overwritten,
//!   and it must not exist after a drill.
//! - **The teardown runs whatever happened**, which is read off the order of the
//!   RPCs the mock logged.

mod common;

use std::path::Path;

use common::{RESTORED_FILE, prepare, request};

use sb_core::ops::backup::run_backup;
use sb_core::ops::drill::{DrillOutcome, DrillRequest, Stage, run_drill};
use sb_core::plugin::PluginClient;
use sb_crypto::{Digest, Identity};

const SIZE: i64 = 64 * 1024;

/// Backs up once and returns what the drill needs besides the plugins.
async fn backed_up(dir: &Path) -> (PluginClient, PluginClient, Identity, Digest) {
    let id = Identity::generate();
    let (source, storage) = prepare(dir, 7, SIZE).await;
    let backup = run_backup(request(&source, &storage, "drill/artifact.age", &id))
        .await
        .unwrap();
    (source, storage, id, backup.summary.ciphertext_sha256)
}

async fn drill(
    source: &PluginClient,
    storage: &PluginClient,
    id: &Identity,
    digest: Digest,
    check: &str,
) -> DrillOutcome {
    run_drill(DrillRequest {
        source,
        storage,
        artifact_key: "drill/artifact.age".into(),
        identity: id,
        expected_ciphertext_sha256: Some(digest),
        check: check.into(),
    })
    .await
    .unwrap()
}

/// The RPCs the mock saw, in order.
fn calls(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("drill-calls.log"))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// What a drill must never leave behind or touch.
fn assert_production_untouched(dir: &Path) {
    assert!(
        !dir.join(RESTORED_FILE).exists(),
        "the drill wrote where a plain restore would have: the source's own directory"
    );
}

async fn close(source: PluginClient, storage: PluginClient) {
    source.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_drill_that_restores_and_checks_passes_and_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    let (source, storage, id, digest) = backed_up(dir.path()).await;

    let outcome = drill(&source, &storage, &id, digest, &format!("size={SIZE}")).await;

    assert!(outcome.passed(), "{outcome:?}");
    assert_eq!(outcome.plaintext_bytes, Some(SIZE.unsigned_abs()));
    let check = outcome.check.unwrap();
    assert!(check.ok, "{}", check.detail);
    assert!(outcome.scratch.unwrap().ends_with("drill-scratch"));
    assert!(outcome.restore_elapsed.is_some());
    assert!(outcome.teardown_error.is_none());

    assert_eq!(
        calls(dir.path()),
        ["provision", &format!("check size={SIZE}"), "teardown"]
    );
    assert!(
        !dir.path().join("drill-scratch").exists(),
        "the scratch place was not thrown away"
    );
    assert_production_untouched(dir.path());

    close(source, storage).await;
}

#[tokio::test]
async fn a_check_that_does_not_hold_fails_the_drill_and_still_tears_down() {
    // The restore worked; what landed is wrong. This is the case the drill exists
    // for, and it has to say *which* thing was wrong.
    let dir = tempfile::tempdir().unwrap();
    let (source, storage, id, digest) = backed_up(dir.path()).await;

    let outcome = drill(&source, &storage, &id, digest, "size=1").await;

    let failure = outcome.failure.clone().unwrap();
    assert_eq!(failure.stage, Stage::Check);
    assert!(
        failure.message.contains("expected 1"),
        "{}",
        failure.message
    );
    assert!(!outcome.check.unwrap().ok);
    assert_eq!(
        outcome.plaintext_bytes,
        Some(SIZE.unsigned_abs()),
        "the restore itself did finish, and the report must say so"
    );
    assert_eq!(calls(dir.path()).last().unwrap(), "teardown");
    assert!(!dir.path().join("drill-scratch").exists());
    assert_production_untouched(dir.path());

    close(source, storage).await;
}

#[tokio::test]
async fn a_check_that_cannot_be_asked_fails_the_drill_without_a_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let (source, storage, id, digest) = backed_up(dir.path()).await;

    let outcome = drill(&source, &storage, &id, digest, "error").await;

    let failure = outcome.failure.clone().unwrap();
    assert_eq!(failure.stage, Stage::Check);
    assert!(
        failure.message.contains("failed on Check"),
        "{}",
        failure.message
    );
    assert!(
        outcome.check.is_none(),
        "no answer was given, so there is no verdict to report"
    );
    assert_eq!(calls(dir.path()).last().unwrap(), "teardown");
    assert_production_untouched(dir.path());

    close(source, storage).await;
}

#[tokio::test]
async fn a_provision_that_fails_stops_before_moving_a_byte() {
    let dir = tempfile::tempdir().unwrap();
    let (source, storage, id, digest) = backed_up(dir.path()).await;
    std::fs::write(dir.path().join("drill-fail-provision"), b"").unwrap();

    let outcome = drill(&source, &storage, &id, digest, "restored").await;

    let failure = outcome.failure.clone().unwrap();
    assert_eq!(failure.stage, Stage::Provision);
    assert!(failure.message.contains("Provision"), "{}", failure.message);
    assert!(outcome.scratch.is_none());
    assert!(outcome.plaintext_bytes.is_none(), "nothing was restored");
    assert!(outcome.restore_elapsed.is_none());
    // Teardown is called even here: it is idempotent, and the core does not guess
    // whether a failed provision left something behind.
    assert_eq!(calls(dir.path()), ["provision", "teardown"]);
    assert_production_untouched(dir.path());

    close(source, storage).await;
}

#[tokio::test]
async fn a_restore_that_fails_is_reported_as_such_and_its_partial_output_is_thrown_away() {
    // Somebody else's key: the artifact is addressed to a different identity, so
    // the restore cannot decrypt it. A real failure of the same shape as a
    // truncated artifact -- the source may already hold partial plaintext.
    let dir = tempfile::tempdir().unwrap();
    let (source, storage, _id, digest) = backed_up(dir.path()).await;
    let stranger = Identity::generate();

    let outcome = drill(&source, &storage, &stranger, digest, "restored").await;

    let failure = outcome.failure.clone().unwrap();
    assert_eq!(failure.stage, Stage::Restore);
    assert!(outcome.plaintext_bytes.is_none());
    assert!(outcome.check.is_none(), "a failed restore is never checked");
    assert_eq!(calls(dir.path()), ["provision", "teardown"]);
    assert!(!dir.path().join("drill-scratch").exists());
    assert_production_untouched(dir.path());

    close(source, storage).await;
}

#[tokio::test]
async fn a_restore_of_the_wrong_artifact_is_caught_by_the_digest() {
    // The same protection `restore` has, and the drill inherits it by going
    // through the same function: a well-formed foreign artifact decrypts fine and
    // only the manifest's digest tells.
    let dir = tempfile::tempdir().unwrap();
    let (source, storage, id, _digest) = backed_up(dir.path()).await;
    let wrong = Digest::from_hex(&"ab".repeat(32)).unwrap();

    let outcome = drill(&source, &storage, &id, wrong, "restored").await;

    assert_eq!(outcome.failure.unwrap().stage, Stage::Restore);
    assert_eq!(calls(dir.path()).last().unwrap(), "teardown");
    assert_production_untouched(dir.path());

    close(source, storage).await;
}

#[tokio::test]
async fn a_teardown_that_fails_is_reported_but_does_not_change_the_verdict() {
    // The backup restored and the check held: that is the answer. The leftover
    // scratch place is a leak to tell about, not a reason to call a good backup bad.
    let dir = tempfile::tempdir().unwrap();
    let (source, storage, id, digest) = backed_up(dir.path()).await;
    std::fs::write(dir.path().join("drill-fail-teardown"), b"").unwrap();

    let outcome = drill(&source, &storage, &id, digest, "restored").await;

    assert!(outcome.passed(), "{outcome:?}");
    let error = outcome.teardown_error.unwrap();
    assert!(error.contains("Teardown"), "{error}");
    assert!(
        dir.path().join("drill-scratch").exists(),
        "the mock was told not to clean up, and that is the leak being reported"
    );

    close(source, storage).await;
}
