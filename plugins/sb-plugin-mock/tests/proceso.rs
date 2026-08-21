// La excepción de `clippy.toml` para `unwrap` cubre los cuerpos de `#[test]`,
// pero este fichero es todo código de prueba: el arranque del proceso y los
// ayudantes de put/get también lo son, y ahí un `unwrap` es exactamente lo que
// se quiere —que el test explote donde falló, con su línea.
#![allow(clippy::unwrap_used)]

//! El plugin mock, arrancado como proceso de verdad.
//!
//! Nada se simula aquí: se lanza el binario, se le pasa el sobre por stdin, se
//! lee su anuncio por stdout y se habla con él por mTLS sobre socket Unix,
//! exactamente como hará el núcleo. Un mock que solo funcionara llamado en
//! proceso no serviría para probar el núcleo.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use sb_plugin_mock::datos_deterministas;
use sb_plugin_sdk::sb_proto::engine_client::EngineClient;
use sb_plugin_sdk::sb_proto::plugin_client::PluginClient;
use sb_plugin_sdk::sb_proto::storage_client::StorageClient;
use sb_plugin_sdk::sb_proto::value::Kind;
use sb_plugin_sdk::sb_proto::{
    ConfigureRequest, DeleteRequest, DumpRequest, GetRequest, InfoRequest, ListRequest,
    PreflightRequest, PutRequest, RestoreRequest, Value,
};
use sb_plugin_sdk::tonic::transport::Channel;
use sb_plugin_sdk::tonic::{Code, Status};
use sb_transport::{Bootstrap, DataChannel, EphemeralPki, Ready, connect_control};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Un plugin arrancado de verdad, con su canal de control ya abierto.
///
/// Se encarga de matar **y recoger** el proceso al destruirse: un plugin al que
/// no se le hace `wait` queda zombie, y un test que dejara zombies detrás sería
/// un mal ejemplo para el núcleo, que tiene la misma obligación.
struct PluginVivo {
    hijo: Child,
    canal: Channel,
    ready: Ready,
    /// Mantiene vivo el directorio del socket de control mientras dure el test.
    _sockets: TempDir,
}

impl PluginVivo {
    async fn arrancar() -> Self {
        let sockets = tempfile::tempdir().unwrap();
        let socket = sockets.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();
        let sobre = Bootstrap::nuevo(vec![1], socket.display().to_string(), pki.server_bundle());

        let mut hijo = Command::new(env!("CARGO_BIN_EXE_sb-plugin-mock"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let mut entrada = hijo.stdin.take().unwrap();
        writeln!(entrada, "{}", sobre.to_line().unwrap()).unwrap();
        entrada.flush().unwrap();
        drop(entrada);

        let mut salida = BufReader::new(hijo.stdout.take().unwrap());
        let mut linea = String::new();
        salida.read_line(&mut linea).unwrap();
        let ready = Ready::from_line(&linea).unwrap();

        let canal = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();

        Self {
            hijo,
            canal,
            ready,
            _sockets: sockets,
        }
    }

    fn plugin(&self) -> PluginClient<Channel> {
        PluginClient::new(self.canal.clone())
    }
    fn motor(&self) -> EngineClient<Channel> {
        EngineClient::new(self.canal.clone())
    }
    fn destino(&self) -> StorageClient<Channel> {
        StorageClient::new(self.canal.clone())
    }

    async fn configurar(&self, dir: &Path, seed: i64, size: i64) {
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

impl Drop for PluginVivo {
    fn drop(&mut self) {
        let _ = self.hijo.kill();
        let _ = self.hijo.wait();
    }
}

/// Crea un canal de datos y devuelve su ruta como la espera el `.proto`.
fn canal_de_datos(dir: &Path, nombre: &str) -> (DataChannel, String) {
    let canal = DataChannel::create(dir, nombre).unwrap();
    let ruta = canal.path().display().to_string();
    (canal, ruta)
}

/// Guarda `contenido` bajo `clave` y devuelve el error si el destino lo rechaza.
async fn poner(
    vivo: &PluginVivo,
    sockets: &Path,
    nombre: &str,
    clave: &str,
    contenido: Vec<u8>,
) -> Result<(), Status> {
    let (canal, ruta) = canal_de_datos(sockets, nombre);
    let mut flujo = vivo
        .destino()
        .put(PutRequest {
            key: clave.to_string(),
            data_socket: ruta,
        })
        .await?
        .into_inner();

    let escritura = tokio::spawn(async move {
        let mut s = canal.accept().await.unwrap();
        s.write_all(&contenido).await.unwrap();
        s.shutdown().await.unwrap();
    });
    while flujo.message().await?.is_some() {}
    escritura.await.unwrap();
    Ok(())
}

/// Recupera lo guardado bajo `clave`.
async fn obtener(
    vivo: &PluginVivo,
    sockets: &Path,
    nombre: &str,
    clave: &str,
) -> Result<Vec<u8>, Status> {
    let (canal, ruta) = canal_de_datos(sockets, nombre);
    let mut flujo = vivo
        .destino()
        .get(GetRequest {
            key: clave.to_string(),
            data_socket: ruta,
        })
        .await?
        .into_inner();

    let lectura = tokio::spawn(async move {
        let mut s = canal.accept().await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        buf
    });
    while flujo.message().await?.is_some() {}
    Ok(lectura.await.unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn arranca_se_anuncia_y_declara_ambas_capacidades() {
    let vivo = PluginVivo::arrancar().await;
    assert_eq!(vivo.ready.protocol_version, 1);
    assert_eq!(vivo.ready.capabilities, vec!["engine", "storage"]);
    assert!(vivo.ready.pid > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn info_se_identifica_como_mock_por_el_canal_mtls() {
    let vivo = PluginVivo::arrancar().await;
    let info = vivo
        .plugin()
        .info(InfoRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(info.name, "mock");
    assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(info.protocol_version, 1);
    // 1 = engine, 2 = storage.
    assert_eq!(info.capabilities, vec![1, 2]);
}

#[tokio::test(flavor = "multi_thread")]
async fn el_esquema_publica_dir_seed_y_size_sin_secretos() {
    let vivo = PluginVivo::arrancar().await;
    let esquema = vivo
        .plugin()
        .schema(sb_plugin_sdk::sb_proto::SchemaRequest {})
        .await
        .unwrap()
        .into_inner();
    let nombres: Vec<&str> = esquema.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(nombres, vec!["dir", "seed", "size"]);
    assert!(esquema.fields.iter().all(|f| !f.secret));
}

#[tokio::test(flavor = "multi_thread")]
async fn un_rpc_de_datos_antes_de_configure_falla_con_failed_precondition() {
    let vivo = PluginVivo::arrancar().await;

    let e = vivo
        .motor()
        .dump(DumpRequest {
            data_socket: "/tmp/da-igual.sock".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition, "{}", e.message());

    let e = vivo
        .destino()
        .list(ListRequest {
            prefix: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition, "{}", e.message());
}

#[tokio::test(flavor = "multi_thread")]
async fn el_preflight_sin_configurar_informa_en_vez_de_reventar() {
    // `doctor` necesita un informe que explique qué falta, no un error que lo
    // interrumpa: por eso Preflight es la excepción a la regla anterior.
    let vivo = PluginVivo::arrancar().await;
    let pf = vivo
        .plugin()
        .preflight(PreflightRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(!pf.ok);
    assert!(!pf.checks[0].remediation.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn el_preflight_configurado_crea_el_directorio() {
    let raiz = tempfile::tempdir().unwrap();
    let dir = raiz.path().join("aun/no/existe");
    let vivo = PluginVivo::arrancar().await;
    vivo.configurar(&dir, 42, 10).await;

    let pf = vivo
        .plugin()
        .preflight(PreflightRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(pf.ok, "{:?}", pf.checks);
    assert_eq!(pf.server_version, "mock");
    assert!(dir.is_dir());
}

#[tokio::test(flavor = "multi_thread")]
async fn el_volcado_entrega_exactamente_los_bytes_que_regenera_la_libreria() {
    const SEMILLA: u64 = 1234;
    // Un tamaño que no es múltiplo del mebibyte ni del trozo interno: así el
    // último trozo es parcial y se comprueba que no se pierde ni se repite.
    const TAMANO: usize = 3 * 1024 * 1024 + 7;

    let dir = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let vivo = PluginVivo::arrancar().await;
    vivo.configurar(
        dir.path(),
        i64::try_from(SEMILLA).unwrap(),
        i64::try_from(TAMANO).unwrap(),
    )
    .await;

    let (canal, ruta) = canal_de_datos(sockets.path(), "dump");
    let mut flujo = vivo
        .motor()
        .dump(DumpRequest { data_socket: ruta })
        .await
        .unwrap()
        .into_inner();

    let lectura = tokio::spawn(async move {
        let mut s = canal.accept().await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        buf
    });

    let mut progresos = Vec::new();
    while let Some(p) = flujo.message().await.unwrap() {
        progresos.push(p);
    }
    let recibidos = lectura.await.unwrap();

    let esperados: Vec<u8> = datos_deterministas(SEMILLA, TAMANO).collect();
    assert_eq!(recibidos.len(), TAMANO);
    assert_eq!(recibidos, esperados, "el volcado no es reproducible");

    // Un progreso por mebibyte cruzado más el final.
    assert!(
        progresos.len() >= 4,
        "se esperaba progreso por mebibyte, llegaron {}",
        progresos.len()
    );
    assert_eq!(
        progresos.last().unwrap().bytes,
        u64::try_from(TAMANO).unwrap()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn la_restauracion_escribe_lo_recibido_en_el_directorio() {
    let dir = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let vivo = PluginVivo::arrancar().await;
    vivo.configurar(dir.path(), 5, 0).await;

    let contenido: Vec<u8> = datos_deterministas(5, 4096).collect();
    let copia = contenido.clone();

    let (canal, ruta) = canal_de_datos(sockets.path(), "restore");
    let mut flujo = vivo
        .motor()
        .restore(RestoreRequest { data_socket: ruta })
        .await
        .unwrap()
        .into_inner();

    let escritura = tokio::spawn(async move {
        let mut s = canal.accept().await.unwrap();
        s.write_all(&copia).await.unwrap();
        s.shutdown().await.unwrap();
    });
    while flujo.message().await.unwrap().is_some() {}
    escritura.await.unwrap();

    assert_eq!(
        std::fs::read(dir.path().join("restore.bin")).unwrap(),
        contenido
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn put_seguido_de_get_devuelve_los_mismos_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let vivo = PluginVivo::arrancar().await;
    vivo.configurar(dir.path(), 42, 0).await;

    let contenido: Vec<u8> = datos_deterministas(77, 200_000).collect();
    poner(
        &vivo,
        sockets.path(),
        "put",
        "backup.age",
        contenido.clone(),
    )
    .await
    .unwrap();

    let recuperado = obtener(&vivo, sockets.path(), "get", "backup.age")
        .await
        .unwrap();
    assert_eq!(recuperado, contenido);
}

#[tokio::test(flavor = "multi_thread")]
async fn una_clave_con_barras_crea_los_directorios_y_list_la_encuentra() {
    let dir = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let vivo = PluginVivo::arrancar().await;
    vivo.configurar(dir.path(), 42, 0).await;

    let clave = "produccion/2026/08/21/x.age";
    poner(&vivo, sockets.path(), "put", clave, b"artefacto".to_vec())
        .await
        .unwrap();
    assert!(dir.path().join(clave).is_file());

    let listado = vivo
        .destino()
        .list(ListRequest {
            prefix: "produccion/".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listado.artifacts.len(), 1);
    assert_eq!(listado.artifacts[0].key, clave);
    assert_eq!(listado.artifacts[0].size, 9);

    // Un prefijo que no casa no devuelve nada.
    let vacio = vivo
        .destino()
        .list(ListRequest {
            prefix: "staging/".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(vacio.artifacts.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn una_clave_que_escapa_del_directorio_se_rechaza() {
    let dir = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let vivo = PluginVivo::arrancar().await;
    vivo.configurar(dir.path(), 42, 0).await;

    for clave in ["../fuera.age", "a/../../fuera.age", "/etc/passwd"] {
        let e = poner(&vivo, sockets.path(), "escape", clave, b"x".to_vec())
            .await
            .unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument, "clave {clave}");
    }
    // Y no dejó nada fuera del directorio del destino.
    assert!(!dir.path().parent().unwrap().join("fuera.age").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn get_de_algo_inexistente_es_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let vivo = PluginVivo::arrancar().await;
    vivo.configurar(dir.path(), 42, 0).await;

    let e = obtener(&vivo, sockets.path(), "get", "no-existe.age")
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::NotFound);
}

#[tokio::test(flavor = "multi_thread")]
async fn borrar_algo_inexistente_no_es_un_error() {
    let dir = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let vivo = PluginVivo::arrancar().await;
    vivo.configurar(dir.path(), 42, 0).await;

    // Idempotencia: reintentar una retención no puede fallar por haber acertado.
    vivo.destino()
        .delete(DeleteRequest {
            key: "jamas-existio.age".into(),
        })
        .await
        .unwrap();

    poner(&vivo, sockets.path(), "put", "efimero.age", b"x".to_vec())
        .await
        .unwrap();
    for _ in 0..2 {
        vivo.destino()
            .delete(DeleteRequest {
                key: "efimero.age".into(),
            })
            .await
            .unwrap();
    }
    assert!(!dir.path().join("efimero.age").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn abort_incomplete_no_tiene_nada_que_abortar() {
    let dir = tempfile::tempdir().unwrap();
    let vivo = PluginVivo::arrancar().await;
    vivo.configurar(dir.path(), 42, 0).await;

    let r = vivo
        .destino()
        .abort_incomplete(sb_plugin_sdk::sb_proto::AbortIncompleteRequest {
            prefix: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(r.aborted, 0);
}
