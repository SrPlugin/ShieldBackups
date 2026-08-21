// Igual que en `sb-transport/tests/fallos.rs`: esto es todo código de prueba,
// y ahí un `unwrap` es lo que se quiere —que el test explote justo donde
// falló—.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Este módulo se compila dentro de **cada** binario de test que lo declara, y
// ninguno de ellos usa todos sus ayudantes. Sin esto, añadir un ayudante para
// un test rompería la compilación del otro con un aviso de código muerto.
#![allow(dead_code)]

//! Lo que comparten los tests de integración del núcleo: localizar el binario
//! del plugin mock y dejar un motor y un destino configurados sobre el mismo
//! directorio.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use sb_core::ops::backup::BackupRequest;
use sb_core::plugin::PluginClient;
use sb_crypto::{CompressionLevel, Identity};

/// Ruta del binario del plugin mock.
///
/// `CARGO_BIN_EXE_*` solo lo define cargo para los binarios del **propio**
/// paquete, y el mock vive en otro. Se localiza junto al ejecutable del test
/// —cargo deja ambos bajo el mismo `target/<perfil>/`— y, si todavía no está
/// construido, se construye una sola vez para que estos ficheros se puedan
/// ejecutar aislados con `cargo test -p sb-core --test <nombre>`.
pub fn ruta_mock() -> PathBuf {
    static MOCK: LazyLock<PathBuf> = LazyLock::new(|| {
        let mut dir = std::env::current_exe().unwrap();
        dir.pop();
        if dir.ends_with("deps") {
            dir.pop();
        }
        let binario = dir.join("sb-plugin-mock");
        if !binario.is_file() {
            let release = dir.file_name() == Some(OsStr::new("release"));
            let mut cargo = std::process::Command::new(env!("CARGO"));
            cargo.args(["build", "-p", "sb-plugin-mock"]);
            if release {
                cargo.arg("--release");
            }
            let estado = cargo.status().unwrap();
            assert!(estado.success(), "no se pudo construir el plugin mock");
        }
        assert!(
            binario.is_file(),
            "no se encontró el binario del plugin mock en {}",
            binario.display()
        );
        binario
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

/// Arranca un plugin mock **sin configurarlo**.
///
/// Aparte para los tests de `doctor`, que necesitan justo eso: un plugin vivo
/// al que todavía nadie ha dicho sobre qué trabajar.
pub async fn arrancar(nombre: &str) -> PluginClient {
    PluginClient::start(nombre, &ruta_mock()).await.unwrap()
}

/// Le dice al mock sobre qué directorio trabajar, sin semilla ni tamaño.
pub async fn configurar(cliente: &PluginClient, dir: &Path) {
    let mut cfg = HashMap::new();
    cfg.insert("dir".into(), v_str(dir.to_string_lossy()));
    cliente.configure(cfg).await.unwrap();
}

/// Arranca motor y destino ya configurados sobre el mismo directorio.
pub async fn preparar(dir: &Path, seed: i64, size: i64) -> (PluginClient, PluginClient) {
    let motor = arrancar("mock-engine").await;
    let destino = arrancar("mock-storage").await;

    let mut cfg_m = HashMap::new();
    cfg_m.insert("dir".into(), v_str(dir.to_string_lossy()));
    cfg_m.insert("seed".into(), v_int(seed));
    cfg_m.insert("size".into(), v_int(size));
    motor.configure(cfg_m).await.unwrap();

    configurar(&destino, dir).await;

    (motor, destino)
}

/// Mata al plugin por las bravas y **espera a que de verdad esté muerto**.
///
/// Simula lo que en producción es un plugin que se cae a media faena: el
/// handle sigue existiendo y el canal sigue abierto, pero al otro lado ya no
/// hay nadie. Sin la espera el test sería una carrera —`kill` vuelve antes de
/// que el proceso termine—, así que se sondea el socket de control: mientras
/// alguien escuche, conectarse funciona; en cuanto el proceso muere, el núcleo
/// rechaza la conexión y no hay duda posible.
///
/// El `shutdown` del handle sigue haciendo falta después: es quien recoge al
/// hijo y borra su directorio.
pub async fn matar(cliente: &PluginClient) {
    let pid = i32::try_from(cliente.proceso().pid()).unwrap();
    let objetivo = rustix::process::Pid::from_raw(pid).unwrap();
    rustix::process::kill_process_group(objetivo, rustix::process::Signal::KILL).unwrap();

    let socket = cliente.proceso().control_socket().to_path_buf();
    for _ in 0..500 {
        if tokio::net::UnixStream::connect(&socket).await.is_err() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!(
        "el plugin «{}» siguió aceptando conexiones",
        cliente.nombre()
    );
}

pub fn peticion<'a>(
    motor: &'a PluginClient,
    destino: &'a PluginClient,
    clave: &str,
    id: &Identity,
) -> BackupRequest<'a> {
    BackupRequest {
        target: "prueba".into(),
        engine: motor,
        storage: destino,
        artifact_key: clave.into(),
        recipient: id.to_recipient(),
        level: CompressionLevel::default(),
        engine_version: "0.1.0".into(),
        server_version: "mock".into(),
        created_at: "2026-08-21T10:00:00Z".into(),
    }
}

/// Nombre del fichero donde el motor mock deja lo que recibe por `Restore`.
///
/// La constante vive en el binario del plugin, que un test no puede importar.
pub const FICHERO_RESTAURADO: &str = "restore.bin";

/// Lo que el motor mock produce para una semilla y un tamaño dados.
///
/// Es la referencia contra la que se compara lo restaurado: si el ciclo
/// completo no reproduce esto byte a byte, el proyecto no sirve para nada.
pub fn datos_del_motor(seed: u64, size: usize) -> Vec<u8> {
    sb_plugin_mock::datos_deterministas(seed, size).collect()
}
