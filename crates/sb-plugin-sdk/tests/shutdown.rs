//! `Shutdown` has to end the process, not just answer.
//!
//! The core calls `Shutdown` expecting an orderly close: first the RPC
//! response, then the death of the process. If the process stayed alive, the
//! core would end up killing it; if it died before answering, the core would see
//! a transport error on a correct shutdown. This test demands both things at
//! once and **does not use `kill`**: if the plugin does not die on its own, it
//! fails.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sb_proto::plugin_client::PluginClient;
use sb_transport::{Bootstrap, EphemeralPki, Ready, connect_control};

/// How long the plugin is given to terminate after answering the `Shutdown`.
/// Deliberately generous: what is being checked is that it terminates **on its
/// own**, not how fast it does so.
const PATIENCE: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_answers_and_then_the_process_ends_on_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let pki = EphemeralPki::generate().unwrap();
    let boot = Bootstrap::new(vec![1], socket.display().to_string(), pki.server_bundle());

    let mut child = Command::new(env!("CARGO_BIN_EXE_sb-plugin-smoke"))
        .stderr(Stdio::null())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    writeln!(input, "{}", boot.to_line().unwrap()).unwrap();
    input.flush().unwrap();

    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    Ready::from_line(&line).unwrap();

    let channel = connect_control(&socket, pki.client_config().unwrap())
        .await
        .unwrap();
    let mut client = PluginClient::new(channel);

    // First: the response arrives. A shutdown that cut the connection before
    // answering would look to the core like a plugin failure.
    client
        .shutdown(sb_proto::ShutdownRequest {})
        .await
        .expect("the Shutdown must answer before the process dies");

    // Then: the process ends by itself. No `kill`, no signals.
    let deadline = Instant::now() + PATIENCE;
    let status = loop {
        match child.try_wait().unwrap() {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                // It is reaped anyway: a test that left the process alive would
                // leave a zombie behind the failure.
                child.kill().unwrap();
                child.wait().unwrap();
                panic!(
                    "the plugin was still alive {} s after answering the Shutdown",
                    PATIENCE.as_secs()
                );
            }
            None => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };

    assert!(
        status.success(),
        "an orderly shutdown must end successfully, it ended with {status}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_shutdown_answers_before_the_process_dies() {
    // This is what tells an orderly shutdown apart from killing the process: the
    // core must receive the RPC response, not a transport error.
    //
    // It reinforces the test above by looking at the *error* when there is one:
    // a transport `Unavailable`/`Unknown` would be exactly the spurious failure
    // that the GOAWAY shutdown exists to avoid, and it is named here so that a
    // regression is not mistaken for a plugin failure.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let pki = EphemeralPki::generate().unwrap();
    let boot = Bootstrap::new(vec![1], socket.display().to_string(), pki.server_bundle());

    let mut child = Command::new(env!("CARGO_BIN_EXE_sb-plugin-smoke"))
        .stderr(Stdio::null())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    writeln!(input, "{}", boot.to_line().unwrap()).unwrap();
    input.flush().unwrap();

    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    Ready::from_line(&line).unwrap();

    let channel = connect_control(&socket, pki.client_config().unwrap())
        .await
        .unwrap();
    let mut client = PluginClient::new(channel);

    // The process is still alive when the shutdown is requested: what is being
    // checked is that the response comes out anyway, not that the plugin was
    // already dead.
    assert!(
        child.try_wait().unwrap().is_none(),
        "the plugin must still be alive before asking it to close"
    );

    let response = client.shutdown(sb_proto::ShutdownRequest {}).await;
    if let Err(status) = &response {
        panic!(
            "the Shutdown must return Ok, not a transport error: {:?} {}",
            status.code(),
            status.message()
        );
    }

    // And only then does the process shut itself down, successfully.
    let deadline = Instant::now() + PATIENCE;
    let status = loop {
        match child.try_wait().unwrap() {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!(
                    "the plugin was still alive {} s after answering the Shutdown",
                    PATIENCE.as_secs()
                );
            }
            None => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };

    assert!(
        status.success(),
        "an orderly shutdown must end successfully, it ended with {status}"
    );
}
