// The `clippy.toml` exception for `unwrap`/`expect` covers the bodies of
// `#[test]` functions, but this whole file is test code: the helpers that spawn
// processes, read announcements and reap children are test code too, and there
// an `unwrap` is exactly what is wanted — for the test to blow up where it
// failed.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The failures that come from talking to plugins that are **separate
//! processes**.
//!
//! A backend compiled into the binary cannot refuse to start, nor speak a
//! different version of the protocol, nor die halfway through a dump. A process
//! can. This is the family of failures the plugin architecture brings with it,
//! and what is checked here is not merely that they fail: it is that they
//! **fail fast and with a bounded error instead of hanging**.
//!
//! That is why every wait is wrapped in a `tokio::time::timeout`. A protocol
//! failure that manifests as a hang is a backup that never finishes at three in
//! the morning and that nobody hears about until a restore is needed. A backup
//! that fails with a clear error is infinitely preferable, and that preference
//! is tested, not assumed.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::LazyLock;
use std::time::Duration;

use sb_proto::plugin_client::PluginClient;
use sb_proto::source_client::SourceClient;
use sb_proto::value::Kind;
use sb_proto::{ConfigureRequest, DumpRequest, InfoRequest, Value};
use sb_transport::{
    Bootstrap, DataChannel, EphemeralPki, HANDSHAKE_VERSION, Ready, connect_control,
};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, Command};
use tonic::transport::Channel;

/// Deadline for what **must finish**. Deliberately generous: what is checked is
/// that it finishes, not how fast it does so.
const DEADLINE: Duration = Duration::from_secs(10);

/// Deadline for what **must fail**. Shorter: an error that takes its time is
/// already half a hang, and the core cannot afford to wait on a dead plugin.
const FAILURE_DEADLINE: Duration = Duration::from_secs(3);

/// Deadline for the waits that **must expire** without anything happening.
/// Short: the test pays this time in full on every run.
const EXPIRY_DEADLINE: Duration = Duration::from_millis(300);

/// Size of the dump that gets cut in half. Large enough that it does not fit
/// entirely in the socket buffer and the plugin is still writing when we kill
/// it.
const LARGE_DUMP: i64 = 256 * 1024 * 1024;

/// Path to the mock plugin's binary.
///
/// cargo only defines `CARGO_BIN_EXE_*` for binaries of the **same** package,
/// and the mock lives in another one. It is located next to the test executable
/// — cargo puts both under the same `target/<profile>/` — and, if it has not
/// been built yet, it is built once so that this file can be run in isolation
/// with `cargo test -p sb-transport --test failures`.
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
        assert!(status.success(), "the mock plugin could not be built");
    }
    assert!(
        binary.is_file(),
        "the mock plugin binary was not found at {}",
        binary.display()
    );
    binary
});

/// Spawns a process with all three pipes under control.
///
/// `kill_on_drop` is the safety net: if a test panics before reaping its child,
/// the child does not outlive the test.
fn spawn_process<S: AsRef<OsStr>>(program: S, args: &[&str]) -> Child {
    Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

/// Kills **and reaps** the process. Both things: a child that is never `wait`ed
/// on becomes a zombie, and the core is under exactly the same obligation.
///
/// `start_kill` failing because the process had already died is not a problem:
/// what matters is the `wait` that comes after.
async fn kill_and_reap(child: &mut Child) {
    let _ = child.start_kill();
    let _ = tokio::time::timeout(DEADLINE, child.wait()).await;
}

/// Waits for the process to finish, with a deadline.
///
/// If it does not finish, it is killed, reaped and the test fails: a plugin
/// that stays alive waiting for something that will never come is exactly the
/// hang these tests exist to prevent.
async fn wait_for_exit(child: &mut Child, reason: &str) -> ExitStatus {
    let Ok(status) = tokio::time::timeout(DEADLINE, child.wait()).await else {
        kill_and_reap(child).await;
        panic!("{reason}: the plugin must terminate, not hang");
    };
    status.unwrap()
}

/// Spawns the mock and feeds `line` into its stdin verbatim, without validating
/// it.
///
/// That is the core's role when something goes wrong: the plugin cannot assume
/// that whatever arrives on stdin makes sense.
async fn mock_with_envelope(line: &str) -> Child {
    let mut child = spawn_process(&*MOCK, &[]);
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(line.as_bytes()).await.unwrap();
    stdin.write_all(b"\n").await.unwrap();
    stdin.flush().await.unwrap();
    drop(stdin);
    child
}

/// A correctly started mock, with its control channel open.
///
/// The `TempDir` travels with it because it holds the control socket: if it
/// were dropped first, the channel would have nowhere left to live.
async fn start_mock() -> (Child, Channel, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let pki = EphemeralPki::generate().unwrap();
    let envelope = Bootstrap::new(vec![1], socket.display().to_string(), pki.server_bundle());

    let mut child = mock_with_envelope(&envelope.to_line().unwrap()).await;
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(DEADLINE, stdout.read_line(&mut line))
        .await
        .expect("reading the announcement of a healthy plugin must not hang")
        .unwrap();
    Ready::from_line(&line).unwrap();

    let channel = tokio::time::timeout(
        DEADLINE,
        connect_control(&socket, pki.client_config().unwrap()),
    )
    .await
    .expect("connecting to the control channel must not hang")
    .unwrap();

    (child, channel, dir)
}

/// Configures the mock to dump `size` bytes into `dir`.
async fn configure(channel: &Channel, dir: &std::path::Path, size: i64) {
    let config = HashMap::from([
        (
            "dir".to_string(),
            Value {
                kind: Some(Kind::StringValue(dir.display().to_string())),
            },
        ),
        (
            "size".to_string(),
            Value {
                kind: Some(Kind::IntValue(size)),
            },
        ),
    ]);
    tokio::time::timeout(
        DEADLINE,
        PluginClient::new(channel.clone()).configure(ConfigureRequest { config }),
    )
    .await
    .expect("configuring a live plugin must not hang")
    .unwrap();
}

// ---------------------------------------------------------------------------
// Binaries that are not plugins
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_binary_that_is_not_a_plugin_gives_eof_and_does_not_hang() {
    // `/bin/true` exits immediately without writing anything. That is what
    // happens when somebody points the configuration at some random system
    // binary: the core has to see an EOF, not sit waiting for an announcement.
    let mut child = spawn_process("/bin/true", &[]);
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();

    let read = tokio::time::timeout(FAILURE_DEADLINE, stdout.read_line(&mut line))
        .await
        .expect("reading the announcement of an already-dead binary must not hang")
        .unwrap();

    assert_eq!(read, 0, "a binary that writes nothing must give EOF");
    assert!(
        Ready::from_line(&line).is_err(),
        "an empty line cannot pass for a valid announcement"
    );
    kill_and_reap(&mut child).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_binary_that_never_answers_times_out() {
    // `/bin/sleep 300` is a plugin lost in thought. With no deadline the core
    // would wait five minutes; with one it fails in three hundred milliseconds
    // and the operator finds out.
    let mut child = spawn_process("/bin/sleep", &["300"]);
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();

    let result = tokio::time::timeout(EXPIRY_DEADLINE, stdout.read_line(&mut line)).await;

    assert!(
        result.is_err(),
        "waiting for the announcement of a mute binary must time out, not wait for it to finish"
    );
    kill_and_reap(&mut child).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_binary_that_writes_junk_to_stdout_is_rejected() {
    // Worse than writing nothing: writing something. If the announcement were
    // accepted without validation, the core would carry on believing it is
    // talking to a plugin.
    let mut child = spawn_process("/bin/echo", &["i am not a plugin"]);
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();

    let read = tokio::time::timeout(FAILURE_DEADLINE, stdout.read_line(&mut line))
        .await
        .expect("reading a line that is already written must not hang")
        .unwrap();

    assert!(read > 0, "echo does write something");
    assert!(
        Ready::from_line(&line).is_err(),
        "a made-up announcement cannot turn into a Ready: {line:?}"
    );
    kill_and_reap(&mut child).await;
}

// ---------------------------------------------------------------------------
// Startup envelopes the plugin has to reject
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_with_no_protocol_version_in_common_gives_up() {
    // A core from the future asks for version 99; the mock only speaks 1. What
    // must not happen is the plugin staying alive serving nobody: the core
    // would consider it started and wait for its announcement forever.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let pki = EphemeralPki::generate().unwrap();
    let envelope = Bootstrap::new(vec![99], socket.display().to_string(), pki.server_bundle());

    let mut child = mock_with_envelope(&envelope.to_line().unwrap()).await;
    let status = wait_for_exit(&mut child, "no protocol version in common").await;

    assert!(
        !status.success(),
        "giving up for lack of a common version must be a failure, it exited with {status}"
    );
    assert!(
        !socket.exists(),
        "a plugin that negotiated no version must never have got as far as listening"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_envelope_with_the_marker_changed_is_rejected() {
    // The marker is what tells the core apart from any other process that
    // starts writing to the plugin's stdin.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let pki = EphemeralPki::generate().unwrap();
    let mut envelope = Bootstrap::new(vec![1], socket.display().to_string(), pki.server_bundle());
    envelope.magic = "SOMETHING-ELSE".into();

    let mut child = mock_with_envelope(&envelope.to_line().unwrap()).await;
    let status = wait_for_exit(&mut child, "wrong marker").await;

    assert!(
        !status.success(),
        "an envelope without the right marker must end in failure, it exited with {status}"
    );
    assert!(
        !socket.exists(),
        "it must never have got as far as listening"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_envelope_from_a_future_version_is_rejected_at_startup() {
    // This is the property that makes extending the protocol in the future fail
    // early and clearly — the old plugin refuses to start — instead of late and
    // strangely, with a mandatory field nobody read.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let pki = EphemeralPki::generate().unwrap();
    let mut envelope = Bootstrap::new(vec![1], socket.display().to_string(), pki.server_bundle());
    envelope.handshake_version = HANDSHAKE_VERSION + 1;

    let mut child = mock_with_envelope(&envelope.to_line().unwrap()).await;
    let status = wait_for_exit(&mut child, "envelope from a future version").await;

    assert!(
        !status.success(),
        "an envelope of a version the plugin does not understand must end in failure, it exited with {status}"
    );
    assert!(
        !socket.exists(),
        "it must never have got as far as listening"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_envelope_that_is_not_json_terminates_the_plugin() {
    let mut child = mock_with_envelope("this is not json").await;
    let status = wait_for_exit(&mut child, "envelope that is not JSON").await;

    assert!(
        !status.success(),
        "junk on stdin must end in failure, it exited with {status}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stdin_closed_with_no_envelope_terminates_the_plugin() {
    // The plugin cannot sit waiting for an envelope that is never coming: if it
    // did, the core would have to kill it on a timeout at every failed startup
    // instead of collecting an immediate error.
    let mut child = spawn_process(&*MOCK, &[]);
    drop(child.stdin.take().unwrap());

    let status = wait_for_exit(&mut child, "stdin closed with no envelope").await;

    assert!(
        !status.success(),
        "starting up with no envelope must end in failure, it exited with {status}"
    );
}

// ---------------------------------------------------------------------------
// The control channel once the plugin is gone
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn connecting_to_a_control_channel_that_does_not_exist_fails_fast() {
    // A plugin that died before binding its socket: connecting must give an
    // error, not retry silently until somebody gets tired.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("does-not-exist.sock");
    let pki = EphemeralPki::generate().unwrap();

    let result = tokio::time::timeout(
        FAILURE_DEADLINE,
        connect_control(&socket, pki.client_config().unwrap()),
    )
    .await
    .expect("connecting to a socket that does not exist must not hang");

    assert!(
        result.is_err(),
        "connecting to a socket that does not exist must give an error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn connecting_with_credentials_from_another_pki_fails_instead_of_hanging() {
    // The server does not take the channel down when a TLS handshake fails: it
    // logs it and keeps accepting, so that nobody can render the plugin useless
    // with one junk connection. The price of that decision is that the impostor
    // gets no explained close, so we have to check that it still sees an error
    // rather than sitting there waiting.
    let (mut child, _channel, dir) = start_mock().await;
    let socket = dir.path().join("control.sock");
    let intruder = EphemeralPki::generate().unwrap();

    let result = tokio::time::timeout(
        FAILURE_DEADLINE,
        connect_control(&socket, intruder.client_config().unwrap()),
    )
    .await
    .expect("a rejected TLS handshake must not hang the connecting side");

    assert!(
        result.is_err(),
        "credentials from another PKI cannot open the control channel"
    );
    kill_and_reap(&mut child).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn talking_to_a_dead_plugin_gives_an_error_and_not_a_hang() {
    let (mut child, channel, _dir) = start_mock().await;

    // It is killed **and reaped** before we talk: what is being tested is a
    // call to a process that no longer exists, not to one that is dying.
    child.start_kill().unwrap();
    let status = tokio::time::timeout(DEADLINE, child.wait())
        .await
        .expect("reaping a just-killed process must not hang")
        .unwrap();
    assert!(
        !status.success(),
        "a killed process does not exit successfully, it exited with {status}"
    );

    let result = tokio::time::timeout(
        FAILURE_DEADLINE,
        PluginClient::new(channel).info(InfoRequest {}),
    )
    .await
    .expect("an RPC against a dead plugin must fail, not hang");

    assert!(result.is_err(), "talking to a dead plugin cannot return Ok");
}

// ---------------------------------------------------------------------------
// The data channel once the plugin is gone
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_that_dies_mid_dump_does_not_leave_the_core_waiting() {
    // The most expensive case of all: the backup is already moving bytes when
    // the plugin disappears. If reading the channel never ended, the core would
    // be left with a half-written file and no idea about it.
    let (mut child, channel, dir) = start_mock().await;
    configure(&channel, dir.path(), LARGE_DUMP).await;

    let data = DataChannel::create(dir.path(), "dump").unwrap();
    let path = data.path().display().to_string();

    let mut progress = tokio::time::timeout(
        DEADLINE,
        SourceClient::new(channel.clone()).dump(DumpRequest { data_socket: path }),
    )
    .await
    .expect("asking a live plugin for the dump must not hang")
    .unwrap()
    .into_inner();

    let mut stream = tokio::time::timeout(DEADLINE, data.accept())
        .await
        .expect("the plugin must connect to the data channel")
        .unwrap();

    // First we check that bytes really are flowing: killing the plugin before
    // the first byte would be testing something else.
    let mut buffer = vec![0_u8; 64 * 1024];
    let read = tokio::time::timeout(DEADLINE, stream.read(&mut buffer))
        .await
        .expect("the first chunk of the dump must arrive")
        .unwrap();
    assert!(read > 0, "the dump must have started flowing");

    // And now, mid-stream, the plugin disappears.
    child.start_kill().unwrap();
    tokio::time::timeout(DEADLINE, child.wait())
        .await
        .expect("reaping the dead plugin must not hang")
        .unwrap();

    // The read has to end: with an error or with end of stream, but it has to
    // end. Whatever was left in the socket buffer is drained.
    let mut total = read;
    loop {
        let step = tokio::time::timeout(FAILURE_DEADLINE, stream.read(&mut buffer))
            .await
            .expect("reading the data channel of a dead plugin must not hang");
        match step {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
    assert!(
        i64::try_from(total).unwrap() < LARGE_DUMP,
        "the dump was cut in half: it cannot have arrived whole"
    );

    // Nor may the RPC's progress stream stay open forever.
    let next = tokio::time::timeout(FAILURE_DEADLINE, progress.message())
        .await
        .expect("the progress stream of a dead plugin must not hang");
    assert!(
        next.is_err() || matches!(next, Ok(None)),
        "the progress of an interrupted dump cannot keep advancing"
    );

    kill_and_reap(&mut child).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_data_channel_nobody_connects_to_times_out() {
    // A plugin that accepts the RPC and never opens the socket. With no
    // deadline on the caller's side the backup would hang forever: that is why
    // `accept` does not impose one of its own and documents that setting one is
    // the caller's duty.
    let dir = tempfile::tempdir().unwrap();
    let data = DataChannel::create(dir.path(), "nobody").unwrap();

    let result = tokio::time::timeout(EXPIRY_DEADLINE, data.accept()).await;

    assert!(
        result.is_err(),
        "an accept with nobody on the other side must time out"
    );
}
