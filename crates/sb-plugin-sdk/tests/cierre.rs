//! `Shutdown` tiene que terminar el proceso, no solo responder.
//!
//! El núcleo llama a `Shutdown` esperando un cierre ordenado: primero la
//! respuesta del RPC, después la muerte del proceso. Si el proceso siguiera
//! vivo, el núcleo acabaría matándolo; si muriera antes de responder, el núcleo
//! vería un error de transporte en un cierre correcto. Este test exige las dos
//! cosas a la vez y **no usa `kill`**: si el plugin no se muere solo, falla.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sb_proto::plugin_client::PluginClient;
use sb_transport::{Bootstrap, EphemeralPki, Ready, connect_control};

/// Cuánto se le concede al plugin para terminar tras responder al `Shutdown`.
/// Generoso a propósito: lo que se comprueba es que termina **solo**, no lo
/// rápido que lo hace.
const PACIENCIA: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_responde_y_despues_el_proceso_termina_solo() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let pki = EphemeralPki::generate().unwrap();
    let boot = Bootstrap::nuevo(vec![1], socket.display().to_string(), pki.server_bundle());

    let mut hijo = Command::new(env!("CARGO_BIN_EXE_sb-plugin-smoke"))
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
    Ready::from_line(&linea).unwrap();

    let canal = connect_control(&socket, pki.client_config().unwrap())
        .await
        .unwrap();
    let mut cliente = PluginClient::new(canal);

    // Primero: la respuesta llega. Un cierre que corta la conexión antes de
    // responder le parecería al núcleo un fallo del plugin.
    cliente
        .shutdown(sb_proto::ShutdownRequest {})
        .await
        .expect("el Shutdown debe responder antes de que el proceso muera");

    // Después: el proceso termina por su cuenta. Ni `kill` ni señales.
    let limite = Instant::now() + PACIENCIA;
    let estado = loop {
        match hijo.try_wait().unwrap() {
            Some(estado) => break estado,
            None if Instant::now() >= limite => {
                // Se recoge igualmente: un test que dejara el proceso vivo
                // dejaría un zombie detrás del fallo.
                hijo.kill().unwrap();
                hijo.wait().unwrap();
                panic!(
                    "el plugin seguía vivo {} s después de responder al Shutdown",
                    PACIENCIA.as_secs()
                );
            }
            None => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };

    assert!(
        estado.success(),
        "el cierre ordenado debe terminar con éxito, terminó con {estado}"
    );
}
