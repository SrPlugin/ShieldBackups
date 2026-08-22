// Same as in `backup_mock.rs`: this file is all test code, and there an `unwrap`
// is exactly what is wanted —for the test to blow up right where it failed—.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `doctor` against `sb-plugin-mock`, with two real plugins.
//!
//! What can only be seen here is the property that tells `doctor` apart from the
//! other operations: **it does not abort**. An unconfigured plugin, or one that
//! is outright dead, has to show up as a finding of the report and must not stop
//! the other plugin from being checked. No unit test can show that, because a
//! process to kill is needed.

mod common;

use common::{configure, kill, prepare, start};

use sb_core::ops::doctor::run_doctor;

#[tokio::test]
async fn with_both_plugins_configured_the_report_is_clean() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, storage) = prepare(dir.path(), 7, 1024).await;

    let report = run_doctor("test", &engine, &storage).await;

    assert!(report.ok(), "unexpected failures: {:?}", report.failures());
    assert_eq!(report.target, "test");
    assert!(
        report.checks.iter().any(|c| c.origin == "engine"),
        "the report carries no checks from the engine: {:?}",
        report.checks
    );
    assert!(
        report.checks.iter().any(|c| c.origin == "storage"),
        "the report carries no checks from the storage: {:?}",
        report.checks
    );

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn an_unconfigured_plugin_shows_up_as_a_failure_but_the_report_is_produced() {
    let dir = tempfile::tempdir().unwrap();
    let engine = start("mock-engine").await;
    configure(&engine, dir.path()).await;
    // The storage is deliberately left without `Configure`.
    let storage = start("mock-storage").await;

    let report = run_doctor("test", &engine, &storage).await;

    assert!(!report.ok());
    let failures = report.failures();
    assert_eq!(failures.len(), 1, "failures: {failures:?}");
    assert_eq!(failures[0].origin, "storage");
    assert!(
        !failures[0].remedy.is_empty(),
        "a failure without a remedy is of no use to anyone: {:?}",
        failures[0]
    );
    // The engine was checked, and it came out fine.
    assert!(
        report.checks.iter().any(|c| c.origin == "engine" && c.ok),
        "the engine never got checked: {:?}",
        report.checks
    );

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn the_source_version_reported_by_the_engine_reaches_the_report() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, storage) = prepare(dir.path(), 7, 1024).await;

    let report = run_doctor("test", &engine, &storage).await;

    // It is the one the mock declares in its `PreflightResponse`; a backup's
    // manifest will need it to know which version the dump was taken against.
    assert_eq!(report.server_version(), Some("mock"));

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_dead_plugin_is_a_report_failure_and_the_other_is_checked_anyway() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, storage) = prepare(dir.path(), 7, 1024).await;
    kill(&engine).await;

    // No `unwrap`: `run_doctor` does not return a `Result` precisely because
    // this is not an error of the operation.
    let report = run_doctor("test", &engine, &storage).await;

    assert!(!report.ok());
    let failures = report.failures();
    assert!(
        failures.iter().any(|c| c.origin == "engine"),
        "the dead engine does not show up as a failure: {failures:?}"
    );
    assert!(
        failures.iter().all(|c| !c.remedy.is_empty()),
        "a failure without a remedy is of no use to anyone: {failures:?}"
    );
    // What is really being checked: the storage was checked anyway.
    assert!(
        report.checks.iter().any(|c| c.origin == "storage" && c.ok),
        "the storage never got checked: {:?}",
        report.checks
    );

    engine.shutdown().await.unwrap();
    storage.shutdown().await.unwrap();
}
