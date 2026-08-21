use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use sb_proto::plugin_client::PluginClient;
use sb_transport::{Bootstrap, EphemeralPki, Ready, connect_control};

#[tokio::test(flavor = "multi_thread")]
async fn el_plugin_arranca_se_anuncia_y_responde() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let pki = EphemeralPki::generate().unwrap();
    let boot = Bootstrap::nuevo(vec![1], socket.display().to_string(), pki.server_bundle());

    let mut hijo = Command::new(env!("CARGO_BIN_EXE_sb-plugin-smoke"))
        .env("RUST_LOG", "debug")
        .stderr(Stdio::null())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ent = hijo.stdin.take().unwrap();
    writeln!(ent, "{}", boot.to_line().unwrap()).unwrap();
    ent.flush().unwrap();

    let mut sal = BufReader::new(hijo.stdout.take().unwrap());
    let mut linea = String::new();
    sal.read_line(&mut linea).unwrap();
    let ready = Ready::from_line(&linea).unwrap();
    assert_eq!(ready.protocol_version, 1);
    assert!(ready.capabilities.is_empty());

    let canal = connect_control(&socket, pki.client_config().unwrap())
        .await
        .unwrap();
    let info = PluginClient::new(canal)
        .info(sb_proto::InfoRequest {})
        .await
        .unwrap();
    assert_eq!(info.into_inner().name, "minimo");

    // Matar y **recoger**: un proceso al que no se le hace wait queda zombie.
    // El núcleo tiene la misma obligación con cada plugin que arranca, así que
    // el test predica con el ejemplo.
    hijo.kill().unwrap();
    hijo.wait().unwrap();
}
