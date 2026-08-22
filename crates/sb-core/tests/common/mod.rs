// Same as in `sb-transport/tests/fallos.rs`: this is all test code, and there an
// `unwrap` is exactly what is wanted —for the test to blow up right where it
// failed—.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// This module is compiled inside **every** test binary that declares it, and
// none of them uses all of its helpers. Without this, adding a helper for one
// test would break the compilation of the other with a dead-code warning.
#![allow(dead_code)]

//! What the core's integration tests share: locating the mock plugin's binary
//! and leaving an engine and a storage configured over the same directory.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use sb_core::ops::backup::BackupRequest;
use sb_core::plugin::PluginClient;
use sb_crypto::{CompressionLevel, Identity};

/// Path of the mock plugin's binary.
///
/// `CARGO_BIN_EXE_*` is only defined by cargo for the binaries of the **own**
/// package, and the mock lives in another one. It is located next to the test's
/// executable —cargo leaves both under the same `target/<profile>/`— and, if it
/// is not built yet, it is built once so that these files can be run in
/// isolation with `cargo test -p sb-core --test <name>`.
pub fn mock_path() -> PathBuf {
    static MOCK: LazyLock<PathBuf> = LazyLock::new(|| {
        let mut dir = std::env::current_exe().unwrap();
        dir.pop();
        if dir.ends_with("deps") {
            dir.pop();
        }
        let binary = dir.join("sb-plugin-mock");
        if !binary.is_file() {
            let release = dir.file_name() == Some(OsStr::new("release"));
            let mut cargo = std::process::Command::new(env!("CARGO"));
            cargo.args(["build", "-p", "sb-plugin-mock"]);
            if release {
                cargo.arg("--release");
            }
            let status = cargo.status().unwrap();
            assert!(status.success(), "could not build the mock plugin");
        }
        assert!(
            binary.is_file(),
            "the mock plugin binary was not found at {}",
            binary.display()
        );
        binary
    });

    MOCK.clone()
}

pub fn v_str(s: impl Into<String>) -> sb_proto::Value {
    sb_proto::Value {
        kind: Some(sb_proto::value::Kind::StringValue(s.into())),
    }
}

pub fn v_int(i: i64) -> sb_proto::Value {
    sb_proto::Value {
        kind: Some(sb_proto::value::Kind::IntValue(i)),
    }
}

/// Starts a mock plugin **without configuring it**.
///
/// Kept apart for the `doctor` tests, which need exactly that: a live plugin
/// nobody has told yet what to work on.
pub async fn start(name: &str) -> PluginClient {
    PluginClient::start(name, &mock_path()).await.unwrap()
}

/// Tells the mock which directory to work on, without seed or size.
pub async fn configure(client: &PluginClient, dir: &Path) {
    let mut cfg = HashMap::new();
    cfg.insert("dir".into(), v_str(dir.to_string_lossy()));
    client.configure(cfg).await.unwrap();
}

/// Starts an engine and a storage already configured over the same directory.
pub async fn prepare(dir: &Path, seed: i64, size: i64) -> (PluginClient, PluginClient) {
    let engine = start("mock-engine").await;
    let storage = start("mock-storage").await;

    let mut engine_cfg = HashMap::new();
    engine_cfg.insert("dir".into(), v_str(dir.to_string_lossy()));
    engine_cfg.insert("seed".into(), v_int(seed));
    engine_cfg.insert("size".into(), v_int(size));
    engine.configure(engine_cfg).await.unwrap();

    configure(&storage, dir).await;

    (engine, storage)
}

/// Kills the plugin outright and **waits until it really is dead**.
///
/// It simulates what in production is a plugin that crashes mid-job: the handle
/// still exists and the channel is still open, but there is nobody on the other
/// side any more. Without the wait the test would be a race —`kill` returns
/// before the process ends—, so the control socket is polled: while somebody is
/// listening, connecting works; as soon as the process dies, the kernel refuses
/// the connection and there is no room for doubt.
///
/// The handle's `shutdown` is still needed afterwards: it is what reaps the child
/// and removes its directory.
pub async fn kill(client: &PluginClient) {
    let pid = i32::try_from(client.process().pid()).unwrap();
    let target = rustix::process::Pid::from_raw(pid).unwrap();
    rustix::process::kill_process_group(target, rustix::process::Signal::KILL).unwrap();

    let socket = client.process().control_socket().to_path_buf();
    for _ in 0..500 {
        if tokio::net::UnixStream::connect(&socket).await.is_err() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!(
        "the plugin \"{}\" kept accepting connections",
        client.name()
    );
}

pub fn request<'a>(
    engine: &'a PluginClient,
    storage: &'a PluginClient,
    key: &str,
    id: &Identity,
) -> BackupRequest<'a> {
    BackupRequest {
        target: "test".into(),
        engine,
        storage,
        artifact_key: key.into(),
        recipient: id.to_recipient(),
        level: CompressionLevel::default(),
        engine_version: "0.1.0".into(),
        server_version: "mock".into(),
        created_at: "2026-08-21T10:00:00Z".into(),
    }
}

/// Name of the file where the mock engine leaves what it receives via `Restore`.
///
/// The constant lives in the plugin's binary, which a test cannot import.
pub const RESTORED_FILE: &str = "restore.bin";

/// What the mock engine produces for a given seed and size.
///
/// It is the reference against which the restored data is compared: if the full
/// cycle does not reproduce this byte for byte, the project is useless.
pub fn engine_data(seed: u64, size: usize) -> Vec<u8> {
    sb_plugin_mock::deterministic_data(seed, size).collect()
}
