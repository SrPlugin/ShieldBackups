use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use sb_proto::plugin_client::PluginClient;
use sb_transport::{Bootstrap, EphemeralPki, Ready, connect_control};

#[tokio::test(flavor = "multi_thread")]
async fn the_plugin_starts_announces_itself_and_answers() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let pki = EphemeralPki::generate().unwrap();
    let boot = Bootstrap::new(vec![1], socket.display().to_string(), pki.server_bundle());

    let mut child = Command::new(env!("CARGO_BIN_EXE_sb-plugin-smoke"))
        .env("RUST_LOG", "debug")
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
    let ready = Ready::from_line(&line).unwrap();
    assert_eq!(ready.protocol_version, 1);
    assert!(ready.capabilities.is_empty());

    let channel = connect_control(&socket, pki.client_config().unwrap())
        .await
        .unwrap();
    let info = PluginClient::new(channel)
        .info(sb_proto::InfoRequest {})
        .await
        .unwrap();
    assert_eq!(info.into_inner().name, "minimal");

    // Kill and **reap**: a process nobody waits on becomes a zombie. The core
    // has the same obligation with every plugin it starts, so the test practises
    // what it preaches.
    child.kill().unwrap();
    child.wait().unwrap();
}
