// The `clippy.toml` exception for `unwrap` covers `#[test]` bodies, but this
// whole file is test code: the process start-up and the put/get helpers are
// too, and there an `unwrap` is exactly what is wanted -- for the test to blow
// up where it failed, with its line number.
#![allow(clippy::unwrap_used)]

//! The mock plugin, started as a real process.
//!
//! Nothing is simulated here: the binary is launched, the bootstrap envelope is
//! handed to it over stdin, its announcement is read from stdout and it is
//! talked to over mTLS on a Unix socket, exactly as the core will do. A mock
//! that only worked when called in-process would be useless for testing the
//! core.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use sb_plugin_mock::deterministic_data;
use sb_plugin_sdk::sb_proto::notifier_client::NotifierClient;
use sb_plugin_sdk::sb_proto::plugin_client::PluginClient;
use sb_plugin_sdk::sb_proto::source_client::SourceClient;
use sb_plugin_sdk::sb_proto::storage_client::StorageClient;
use sb_plugin_sdk::sb_proto::value::Kind;
use sb_plugin_sdk::sb_proto::{
    ConfigureRequest, DeleteRequest, DumpRequest, GetRequest, InfoRequest, ListRequest,
    NotifyRequest, PreflightRequest, PutRequest, RestoreRequest, Value,
};
use sb_plugin_sdk::tonic::transport::Channel;
use sb_plugin_sdk::tonic::{Code, Status};
use sb_transport::{Bootstrap, DataChannel, EphemeralPki, Ready, connect_control};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// A really started plugin, with its control channel already open.
///
/// It takes care of killing **and reaping** the process when dropped: a plugin
/// that is never `wait`ed on becomes a zombie, and a test that left zombies
/// behind would set a bad example for the core, which has the same obligation.
struct LivePlugin {
    child: Child,
    channel: Channel,
    ready: Ready,
    /// Keeps the control socket's directory alive for the duration of the test.
    _sockets: TempDir,
}

impl LivePlugin {
    async fn start() -> Self {
        let sockets = tempfile::tempdir().unwrap();
        let socket = sockets.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();
        let envelope = Bootstrap::new(vec![1], socket.display().to_string(), pki.server_bundle());

        let mut child = Command::new(env!("CARGO_BIN_EXE_sb-plugin-mock"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let mut input = child.stdin.take().unwrap();
        writeln!(input, "{}", envelope.to_line().unwrap()).unwrap();
        input.flush().unwrap();
        drop(input);

        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        let ready = Ready::from_line(&line).unwrap();

        let channel = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();

        Self {
            child,
            channel,
            ready,
            _sockets: sockets,
        }
    }

    fn plugin(&self) -> PluginClient<Channel> {
        PluginClient::new(self.channel.clone())
    }
    fn source(&self) -> SourceClient<Channel> {
        SourceClient::new(self.channel.clone())
    }
    fn storage(&self) -> StorageClient<Channel> {
        StorageClient::new(self.channel.clone())
    }
    fn notifier(&self) -> NotifierClient<Channel> {
        NotifierClient::new(self.channel.clone())
    }

    async fn configure(&self, dir: &Path, seed: i64, size: i64) {
        let config = HashMap::from([
            (
                "dir".to_string(),
                Value {
                    kind: Some(Kind::StringValue(dir.display().to_string())),
                },
            ),
            (
                "seed".to_string(),
                Value {
                    kind: Some(Kind::IntValue(seed)),
                },
            ),
            (
                "size".to_string(),
                Value {
                    kind: Some(Kind::IntValue(size)),
                },
            ),
        ]);
        self.plugin()
            .configure(ConfigureRequest { config })
            .await
            .unwrap();
    }
}

impl Drop for LivePlugin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Creates a data channel and returns its path as the `.proto` expects it.
fn data_channel(dir: &Path, name: &str) -> (DataChannel, String) {
    let channel = DataChannel::create(dir, name).unwrap();
    let path = channel.path().display().to_string();
    (channel, path)
}

/// Stores `content` under `key` and returns the error if the target rejects it.
async fn put(
    live: &LivePlugin,
    sockets: &Path,
    name: &str,
    key: &str,
    content: Vec<u8>,
) -> Result<(), Status> {
    let (channel, path) = data_channel(sockets, name);
    let mut stream = live
        .storage()
        .put(PutRequest {
            key: key.to_string(),
            data_socket: path,
        })
        .await?
        .into_inner();

    let writer = tokio::spawn(async move {
        let mut s = channel.accept().await.unwrap();
        s.write_all(&content).await.unwrap();
        s.shutdown().await.unwrap();
    });
    while stream.message().await?.is_some() {}
    writer.await.unwrap();
    Ok(())
}

/// Retrieves what was stored under `key`.
async fn get(live: &LivePlugin, sockets: &Path, name: &str, key: &str) -> Result<Vec<u8>, Status> {
    let (channel, path) = data_channel(sockets, name);
    let mut stream = live
        .storage()
        .get(GetRequest {
            key: key.to_string(),
            data_socket: path,
        })
        .await?
        .into_inner();

    let reader = tokio::spawn(async move {
        let mut s = channel.accept().await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        buf
    });
    while stream.message().await?.is_some() {}
    Ok(reader.await.unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn it_starts_announces_itself_and_declares_its_four_capabilities() {
    let live = LivePlugin::start().await;
    assert_eq!(live.ready.protocol_version, 1);
    assert_eq!(
        live.ready.capabilities,
        vec!["source", "storage", "notifier", "drill"]
    );
    assert!(live.ready.pid > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn info_identifies_itself_as_mock_over_the_mtls_channel() {
    let live = LivePlugin::start().await;
    let info = live
        .plugin()
        .info(InfoRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(info.name, "mock");
    assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(info.protocol_version, 1);
    // 1 = source, 2 = storage, 3 = notifier, 4 = drill.
    assert_eq!(info.capabilities, vec![1, 2, 3, 4]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_notification_is_appended_to_the_notifications_file_as_one_json_line() {
    let live = LivePlugin::start().await;
    let dir = tempfile::tempdir().unwrap();
    live.configure(dir.path(), 1, 1).await;

    for (command, ok) in [("backup", true), ("verify", false)] {
        live.notifier()
            .notify(NotifyRequest {
                command: command.into(),
                ok,
                report_json: format!(r#"{{"ok":{ok}}}"#),
            })
            .await
            .unwrap();
    }

    let text = std::fs::read_to_string(dir.path().join("notifications.jsonl")).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "one line per notification: {text}");
    assert_eq!(
        lines[0],
        r#"{"command":"backup","ok":true,"report":{"ok":true}}"#
    );
    assert_eq!(
        lines[1],
        r#"{"command":"verify","ok":false,"report":{"ok":false}}"#
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_notification_before_configure_fails_with_failed_precondition() {
    let live = LivePlugin::start().await;
    let e = live
        .notifier()
        .notify(NotifyRequest::default())
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition, "{}", e.message());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_schema_publishes_dir_seed_and_size_with_no_secrets() {
    let live = LivePlugin::start().await;
    let schema = live
        .plugin()
        .schema(sb_plugin_sdk::sb_proto::SchemaRequest {})
        .await
        .unwrap()
        .into_inner();
    let names: Vec<&str> = schema.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["dir", "seed", "size"]);
    assert!(schema.fields.iter().all(|f| !f.secret));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_data_rpc_before_configure_fails_with_failed_precondition() {
    let live = LivePlugin::start().await;

    let e = live
        .source()
        .dump(DumpRequest {
            data_socket: "/tmp/does-not-matter.sock".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition, "{}", e.message());

    let e = live
        .storage()
        .list(ListRequest {
            prefix: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition, "{}", e.message());
}

#[tokio::test(flavor = "multi_thread")]
async fn preflight_without_configuration_reports_instead_of_blowing_up() {
    // `doctor` needs a report explaining what is missing, not an error that
    // interrupts it: that is why Preflight is the exception to the rule above.
    let live = LivePlugin::start().await;
    let pf = live
        .plugin()
        .preflight(PreflightRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(!pf.ok);
    assert!(!pf.checks[0].remediation.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn configured_preflight_creates_the_directory() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("does/not/exist/yet");
    let live = LivePlugin::start().await;
    live.configure(&dir, 42, 10).await;

    let pf = live
        .plugin()
        .preflight(PreflightRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(pf.ok, "{:?}", pf.checks);
    assert_eq!(pf.source_version, "mock");
    assert!(dir.is_dir());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_dump_delivers_exactly_the_bytes_the_library_regenerates() {
    const SEED: u64 = 1234;
    // A size that is a multiple of neither the mebibyte nor the internal chunk:
    // that way the last chunk is partial and it is checked that nothing is lost
    // or repeated.
    const SIZE: usize = 3 * 1024 * 1024 + 7;

    let dir = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let live = LivePlugin::start().await;
    live.configure(
        dir.path(),
        i64::try_from(SEED).unwrap(),
        i64::try_from(SIZE).unwrap(),
    )
    .await;

    let (channel, path) = data_channel(sockets.path(), "dump");
    let mut stream = live
        .source()
        .dump(DumpRequest { data_socket: path })
        .await
        .unwrap()
        .into_inner();

    let reader = tokio::spawn(async move {
        let mut s = channel.accept().await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        buf
    });

    let mut updates = Vec::new();
    while let Some(p) = stream.message().await.unwrap() {
        updates.push(p);
    }
    let received = reader.await.unwrap();

    let expected: Vec<u8> = deterministic_data(SEED, SIZE).collect();
    assert_eq!(received.len(), SIZE);
    assert_eq!(received, expected, "the dump is not reproducible");

    // One progress update per mebibyte crossed plus the final one.
    assert!(
        updates.len() >= 4,
        "expected progress per mebibyte, got {}",
        updates.len()
    );
    assert_eq!(updates.last().unwrap().bytes, u64::try_from(SIZE).unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_restore_writes_what_it_receives_into_the_directory() {
    let dir = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let live = LivePlugin::start().await;
    live.configure(dir.path(), 5, 0).await;

    let content: Vec<u8> = deterministic_data(5, 4096).collect();
    let copy = content.clone();

    let (channel, path) = data_channel(sockets.path(), "restore");
    let mut stream = live
        .source()
        .restore(RestoreRequest { data_socket: path })
        .await
        .unwrap()
        .into_inner();

    let writer = tokio::spawn(async move {
        let mut s = channel.accept().await.unwrap();
        s.write_all(&copy).await.unwrap();
        s.shutdown().await.unwrap();
    });
    while stream.message().await.unwrap().is_some() {}
    writer.await.unwrap();

    assert_eq!(
        std::fs::read(dir.path().join("restore.bin")).unwrap(),
        content
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn put_followed_by_get_returns_the_same_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let live = LivePlugin::start().await;
    live.configure(dir.path(), 42, 0).await;

    let content: Vec<u8> = deterministic_data(77, 200_000).collect();
    put(&live, sockets.path(), "put", "backup.age", content.clone())
        .await
        .unwrap();

    let retrieved = get(&live, sockets.path(), "get", "backup.age")
        .await
        .unwrap();
    assert_eq!(retrieved, content);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_with_slashes_creates_the_directories_and_list_finds_it() {
    let dir = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let live = LivePlugin::start().await;
    live.configure(dir.path(), 42, 0).await;

    let key = "production/2026/08/21/x.age";
    put(&live, sockets.path(), "put", key, b"artifact".to_vec())
        .await
        .unwrap();
    assert!(dir.path().join(key).is_file());

    let listing = live
        .storage()
        .list(ListRequest {
            prefix: "production/".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listing.artifacts.len(), 1);
    assert_eq!(listing.artifacts[0].key, key);
    assert_eq!(listing.artifacts[0].size, 8);
    // `modified_at` is RFC-3339 UTC by contract -- `2026-08-21T09:30:00Z` --,
    // not the epoch. The core compares dates of artifacts coming from different
    // storage targets, and two incomparable formats would make that comparison
    // lie silently.
    let date = &listing.artifacts[0].modified_at;
    assert_eq!(date.len(), 20, "`{date}` is not an RFC-3339 UTC");
    assert!(date.ends_with('Z'), "`{date}` does not end in Z");
    assert!(
        !date.chars().all(|c| c.is_ascii_digit()),
        "`{date}` is still the epoch in seconds"
    );

    // A prefix that does not match returns nothing.
    let empty = live
        .storage()
        .list(ListRequest {
            prefix: "staging/".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(empty.artifacts.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_that_escapes_the_directory_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let live = LivePlugin::start().await;
    live.configure(dir.path(), 42, 0).await;

    for key in ["../outside.age", "a/../../outside.age", "/etc/passwd"] {
        let e = put(&live, sockets.path(), "escape", key, b"x".to_vec())
            .await
            .unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument, "key {key}");
    }
    // And it left nothing outside the storage target's directory.
    assert!(!dir.path().parent().unwrap().join("outside.age").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn get_of_something_nonexistent_is_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let live = LivePlugin::start().await;
    live.configure(dir.path(), 42, 0).await;

    let e = get(&live, sockets.path(), "get", "does-not-exist.age")
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::NotFound);
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_something_nonexistent_is_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let live = LivePlugin::start().await;
    live.configure(dir.path(), 42, 0).await;

    // Idempotence: retrying a retention pass cannot fail for having succeeded.
    live.storage()
        .delete(DeleteRequest {
            key: "never-existed.age".into(),
        })
        .await
        .unwrap();

    put(&live, sockets.path(), "put", "ephemeral.age", b"x".to_vec())
        .await
        .unwrap();
    for _ in 0..2 {
        live.storage()
            .delete(DeleteRequest {
                key: "ephemeral.age".into(),
            })
            .await
            .unwrap();
    }
    assert!(!dir.path().join("ephemeral.age").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn abort_incomplete_has_nothing_to_abort() {
    let dir = tempfile::tempdir().unwrap();
    let live = LivePlugin::start().await;
    live.configure(dir.path(), 42, 0).await;

    let r = live
        .storage()
        .abort_incomplete(sb_plugin_sdk::sb_proto::AbortIncompleteRequest {
            prefix: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(r.aborted, 0);
}
