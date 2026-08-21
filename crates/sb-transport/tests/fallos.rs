// La excepción de `clippy.toml` para `unwrap`/`expect` cubre los cuerpos de
// `#[test]`, pero este fichero es todo código de prueba: los ayudantes que
// lanzan procesos, leen anuncios y recogen hijos también lo son, y ahí un
// `unwrap` es exactamente lo que se quiere —que el test explote donde falló—.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Los fallos que introduce hablar con plugins que son **procesos separados**.
//!
//! Un backend compilado dentro del binario no puede negarse a arrancar, ni
//! hablar otra versión del protocolo, ni morirse a mitad de un volcado. Un
//! proceso sí. Esta es la familia de fallos que la arquitectura de plugins
//! trae consigo, y lo que se comprueba aquí no es solo que fallen: es que
//! **fallen rápido y con un error acotado en vez de colgarse**.
//!
//! Por eso cada espera va envuelta en un `tokio::time::timeout`. Un fallo del
//! protocolo que se manifieste como un cuelgue es un backup que no termina a
//! las tres de la mañana y del que nadie se entera hasta que hace falta
//! restaurar. Un backup que falla con un error claro es infinitamente
//! preferible, y esa preferencia se prueba, no se supone.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::LazyLock;
use std::time::Duration;

use sb_proto::engine_client::EngineClient;
use sb_proto::plugin_client::PluginClient;
use sb_proto::value::Kind;
use sb_proto::{ConfigureRequest, DumpRequest, InfoRequest, Value};
use sb_transport::{
    Bootstrap, DataChannel, EphemeralPki, HANDSHAKE_VERSION, Ready, connect_control,
};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, Command};
use tonic::transport::Channel;

/// Límite para lo que **debe terminar**. Generoso a propósito: lo que se
/// comprueba es que termina, no lo rápido que lo hace.
const LIMITE: Duration = Duration::from_secs(10);

/// Límite para lo que **debe fallar**. Más corto: un error que tarda ya es
/// medio cuelgue, y el núcleo no puede permitirse esperar a un plugin muerto.
const LIMITE_FALLO: Duration = Duration::from_secs(3);

/// Límite para las esperas que **deben vencer** sin que pase nada. Corto: el
/// test paga este tiempo íntegro cada vez que se ejecuta.
const LIMITE_VENCE: Duration = Duration::from_millis(300);

/// Tamaño del volcado que se corta a mitad. Lo bastante grande para que no
/// quepa entero en el búfer del socket y el plugin siga escribiendo cuando lo
/// matemos.
const VOLCADO_LARGO: i64 = 256 * 1024 * 1024;

/// Ruta del binario del plugin mock.
///
/// `CARGO_BIN_EXE_*` solo lo define cargo para los binarios del **propio**
/// paquete, y el mock vive en otro. Se localiza junto al ejecutable del test
/// —cargo deja ambos bajo el mismo `target/<perfil>/`— y, si todavía no está
/// construido, se construye una sola vez para que este fichero se pueda
/// ejecutar aislado con `cargo test -p sb-transport --test fallos`.
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

/// Lanza un proceso con las tres tuberías bajo control.
///
/// `kill_on_drop` es la red de seguridad: si un test entra en pánico antes de
/// recoger a su hijo, el hijo no sobrevive al test.
fn lanzar<S: AsRef<OsStr>>(programa: S, args: &[&str]) -> Child {
    Command::new(programa)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

/// Mata **y recoge** el proceso. Las dos cosas: un hijo al que no se le hace
/// `wait` queda zombie, y el núcleo tiene exactamente la misma obligación.
///
/// Que `start_kill` falle porque el proceso ya había muerto no es un problema:
/// lo que importa es el `wait` que viene después.
async fn terminar(hijo: &mut Child) {
    let _ = hijo.start_kill();
    let _ = tokio::time::timeout(LIMITE, hijo.wait()).await;
}

/// Espera a que el proceso termine, con límite.
///
/// Si no termina, lo mata, lo recoge y falla: un plugin que se queda vivo
/// esperando algo que nunca va a llegar es justo el cuelgue que estos tests
/// existen para impedir.
async fn esperar_salida(hijo: &mut Child, motivo: &str) -> ExitStatus {
    let Ok(estado) = tokio::time::timeout(LIMITE, hijo.wait()).await else {
        terminar(hijo).await;
        panic!("{motivo}: el plugin debe terminar, no colgarse");
    };
    estado.unwrap()
}

/// Lanza el mock y le mete `linea` por stdin tal cual, sin validarla.
///
/// Es el papel del núcleo cuando algo va mal: el plugin no puede fiarse de que
/// lo que llega por stdin tenga sentido.
async fn mock_con_sobre(linea: &str) -> Child {
    let mut hijo = lanzar(&*MOCK, &[]);
    let mut entrada = hijo.stdin.take().unwrap();
    entrada.write_all(linea.as_bytes()).await.unwrap();
    entrada.write_all(b"\n").await.unwrap();
    entrada.flush().await.unwrap();
    drop(entrada);
    hijo
}

/// Un mock arrancado correctamente, con su canal de control abierto.
///
/// El `TempDir` viaja con él porque contiene el socket de control: si se
/// destruyera antes, el canal se quedaría sin sitio donde vivir.
async fn arrancar_mock() -> (Child, Channel, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let pki = EphemeralPki::generate().unwrap();
    let sobre = Bootstrap::nuevo(vec![1], socket.display().to_string(), pki.server_bundle());

    let mut hijo = mock_con_sobre(&sobre.to_line().unwrap()).await;
    let mut salida = BufReader::new(hijo.stdout.take().unwrap());
    let mut linea = String::new();
    tokio::time::timeout(LIMITE, salida.read_line(&mut linea))
        .await
        .expect("leer el anuncio de un plugin sano no debe colgarse")
        .unwrap();
    Ready::from_line(&linea).unwrap();

    let canal = tokio::time::timeout(
        LIMITE,
        connect_control(&socket, pki.client_config().unwrap()),
    )
    .await
    .expect("conectar al canal de control no debe colgarse")
    .unwrap();

    (hijo, canal, dir)
}

/// Configura el mock para que vuelque `size` bytes en `dir`.
async fn configurar(canal: &Channel, dir: &std::path::Path, size: i64) {
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
        LIMITE,
        PluginClient::new(canal.clone()).configure(ConfigureRequest { config }),
    )
    .await
    .expect("configurar un plugin vivo no debe colgarse")
    .unwrap();
}

// ---------------------------------------------------------------------------
// Binarios que no son plugins
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn un_binario_que_no_es_un_plugin_da_fin_de_fichero_y_no_cuelga() {
    // `/bin/true` termina de inmediato sin escribir nada. Es lo que pasa cuando
    // alguien apunta la configuración a un binario cualquiera del sistema: el
    // núcleo tiene que ver un EOF, no quedarse esperando un anuncio.
    let mut hijo = lanzar("/bin/true", &[]);
    let mut salida = BufReader::new(hijo.stdout.take().unwrap());
    let mut linea = String::new();

    let leidos = tokio::time::timeout(LIMITE_FALLO, salida.read_line(&mut linea))
        .await
        .expect("leer el anuncio de un binario que ya murió no debe colgarse")
        .unwrap();

    assert_eq!(leidos, 0, "un binario que no escribe nada debe dar EOF");
    assert!(
        Ready::from_line(&linea).is_err(),
        "una línea vacía no puede pasar por un anuncio válido"
    );
    terminar(&mut hijo).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn un_binario_que_nunca_responde_vence_por_tiempo() {
    // `/bin/sleep 300` es un plugin que se queda pensando. Sin límite, el
    // núcleo esperaría cinco minutos; con él, falla en trescientos
    // milisegundos y el operador se entera.
    let mut hijo = lanzar("/bin/sleep", &["300"]);
    let mut salida = BufReader::new(hijo.stdout.take().unwrap());
    let mut linea = String::new();

    let resultado = tokio::time::timeout(LIMITE_VENCE, salida.read_line(&mut linea)).await;

    assert!(
        resultado.is_err(),
        "esperar el anuncio de un binario mudo debe vencer por tiempo, no esperar a que termine"
    );
    terminar(&mut hijo).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn un_binario_que_escribe_basura_en_stdout_se_rechaza() {
    // Peor que no escribir nada: escribir algo. Si el anuncio se aceptara sin
    // validar, el núcleo seguiría adelante creyendo que habla con un plugin.
    let mut hijo = lanzar("/bin/echo", &["no soy un plugin"]);
    let mut salida = BufReader::new(hijo.stdout.take().unwrap());
    let mut linea = String::new();

    let leidos = tokio::time::timeout(LIMITE_FALLO, salida.read_line(&mut linea))
        .await
        .expect("leer una línea que ya está escrita no debe colgarse")
        .unwrap();

    assert!(leidos > 0, "echo sí escribe algo");
    assert!(
        Ready::from_line(&linea).is_err(),
        "un anuncio inventado no puede convertirse en un Ready: {linea:?}"
    );
    terminar(&mut hijo).await;
}

// ---------------------------------------------------------------------------
// Sobres de arranque que el plugin tiene que rechazar
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn un_plugin_sin_version_de_protocolo_en_comun_se_rinde() {
    // El núcleo del futuro pide la versión 99; el mock solo habla la 1. Lo que
    // no puede pasar es que el plugin se quede vivo sin servir a nadie: el
    // núcleo lo daría por arrancado y esperaría su anuncio para siempre.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let pki = EphemeralPki::generate().unwrap();
    let sobre = Bootstrap::nuevo(vec![99], socket.display().to_string(), pki.server_bundle());

    let mut hijo = mock_con_sobre(&sobre.to_line().unwrap()).await;
    let estado = esperar_salida(&mut hijo, "sin versión de protocolo en común").await;

    assert!(
        !estado.success(),
        "rendirse por falta de versión común debe ser un fallo, terminó con {estado}"
    );
    assert!(
        !socket.exists(),
        "un plugin que no negoció versión no debe haber llegado a escuchar"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn un_sobre_con_el_marcador_cambiado_se_rechaza() {
    // El marcador es lo que distingue al núcleo de cualquier otro proceso que
    // se ponga a escribir en el stdin del plugin.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let pki = EphemeralPki::generate().unwrap();
    let mut sobre = Bootstrap::nuevo(vec![1], socket.display().to_string(), pki.server_bundle());
    sobre.magic = "OTRA-COSA".into();

    let mut hijo = mock_con_sobre(&sobre.to_line().unwrap()).await;
    let estado = esperar_salida(&mut hijo, "marcador incorrecto").await;

    assert!(
        !estado.success(),
        "un sobre sin el marcador correcto debe terminar en fallo, terminó con {estado}"
    );
    assert!(!socket.exists(), "no debe haber llegado a escuchar");
}

#[tokio::test(flavor = "multi_thread")]
async fn un_sobre_de_version_futura_se_rechaza_al_arrancar() {
    // Esta es la propiedad que hace que ampliar el protocolo en el futuro
    // falle pronto y claro —el plugin viejo se niega a arrancar— en vez de
    // tarde y raro, con un campo obligatorio que nadie leyó.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let pki = EphemeralPki::generate().unwrap();
    let mut sobre = Bootstrap::nuevo(vec![1], socket.display().to_string(), pki.server_bundle());
    sobre.handshake_version = HANDSHAKE_VERSION + 1;

    let mut hijo = mock_con_sobre(&sobre.to_line().unwrap()).await;
    let estado = esperar_salida(&mut hijo, "sobre de versión futura").await;

    assert!(
        !estado.success(),
        "un sobre de una versión que el plugin no entiende debe terminar en fallo, terminó con {estado}"
    );
    assert!(!socket.exists(), "no debe haber llegado a escuchar");
}

#[tokio::test(flavor = "multi_thread")]
async fn un_sobre_que_no_es_json_termina_el_plugin() {
    let mut hijo = mock_con_sobre("esto no es json").await;
    let estado = esperar_salida(&mut hijo, "sobre que no es JSON").await;

    assert!(
        !estado.success(),
        "basura por stdin debe terminar en fallo, terminó con {estado}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn el_stdin_cerrado_sin_sobre_termina_el_plugin() {
    // El plugin no puede quedarse esperando un sobre que ya no va a llegar: si
    // lo hiciera, el núcleo tendría que matarlo por timeout en cada arranque
    // fallido en vez de recoger un error inmediato.
    let mut hijo = lanzar(&*MOCK, &[]);
    drop(hijo.stdin.take().unwrap());

    let estado = esperar_salida(&mut hijo, "stdin cerrado sin sobre").await;

    assert!(
        !estado.success(),
        "arrancar sin sobre debe terminar en fallo, terminó con {estado}"
    );
}

// ---------------------------------------------------------------------------
// El canal de control cuando el plugin ya no está
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn conectar_a_un_canal_de_control_que_no_existe_falla_rapido() {
    // Un plugin que murió antes de enlazar su socket: conectar debe dar error,
    // no reintentar en silencio hasta que alguien se canse.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("no-existe.sock");
    let pki = EphemeralPki::generate().unwrap();

    let resultado = tokio::time::timeout(
        LIMITE_FALLO,
        connect_control(&socket, pki.client_config().unwrap()),
    )
    .await
    .expect("conectar a un socket inexistente no debe colgarse");

    assert!(
        resultado.is_err(),
        "conectar a un socket que no existe debe dar error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn conectar_con_credenciales_de_otra_pki_falla_en_vez_de_colgarse() {
    // El servidor no tumba el canal cuando un handshake TLS falla: lo registra
    // y sigue aceptando, para que nadie pueda dejar el plugin inservible con
    // una conexión basura. El precio de esa decisión es que el impostor no
    // recibe un cierre explicado, así que hay que comprobar que aun así ve un
    // error y no se queda esperando.
    let (mut hijo, _canal, dir) = arrancar_mock().await;
    let socket = dir.path().join("control.sock");
    let intrusa = EphemeralPki::generate().unwrap();

    let resultado = tokio::time::timeout(
        LIMITE_FALLO,
        connect_control(&socket, intrusa.client_config().unwrap()),
    )
    .await
    .expect("un handshake TLS rechazado no debe colgar al que conecta");

    assert!(
        resultado.is_err(),
        "unas credenciales de otra PKI no pueden abrir el canal de control"
    );
    terminar(&mut hijo).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hablar_con_un_plugin_muerto_da_error_y_no_cuelgue() {
    let (mut hijo, canal, _dir) = arrancar_mock().await;

    // Se mata **y se recoge** antes de hablar: lo que se prueba es la llamada
    // a un proceso que ya no existe, no a uno que se está muriendo.
    hijo.start_kill().unwrap();
    let estado = tokio::time::timeout(LIMITE, hijo.wait())
        .await
        .expect("recoger un proceso al que se acaba de matar no debe colgarse")
        .unwrap();
    assert!(
        !estado.success(),
        "un proceso matado no termina con éxito, terminó con {estado}"
    );

    let resultado =
        tokio::time::timeout(LIMITE_FALLO, PluginClient::new(canal).info(InfoRequest {}))
            .await
            .expect("un RPC contra un plugin muerto debe fallar, no colgarse");

    assert!(
        resultado.is_err(),
        "hablar con un plugin muerto no puede devolver Ok"
    );
}

// ---------------------------------------------------------------------------
// El canal de datos cuando el plugin ya no está
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn un_plugin_que_muere_a_mitad_del_volcado_no_deja_al_nucleo_esperando() {
    // El caso más caro de todos: el backup ya está moviendo bytes cuando el
    // plugin desaparece. Si la lectura del canal no terminara, el núcleo se
    // quedaría con un fichero a medias y sin saberlo.
    let (mut hijo, canal, dir) = arrancar_mock().await;
    configurar(&canal, dir.path(), VOLCADO_LARGO).await;

    let datos = DataChannel::create(dir.path(), "dump").unwrap();
    let ruta = datos.path().display().to_string();

    let mut progreso = tokio::time::timeout(
        LIMITE,
        EngineClient::new(canal.clone()).dump(DumpRequest { data_socket: ruta }),
    )
    .await
    .expect("pedir el volcado a un plugin vivo no debe colgarse")
    .unwrap()
    .into_inner();

    let mut flujo = tokio::time::timeout(LIMITE, datos.accept())
        .await
        .expect("el plugin debe conectarse al canal de datos")
        .unwrap();

    // Primero se comprueba que los bytes ya están fluyendo de verdad: matar el
    // plugin antes del primer byte probaría otra cosa.
    let mut buffer = vec![0_u8; 64 * 1024];
    let leidos = tokio::time::timeout(LIMITE, flujo.read(&mut buffer))
        .await
        .expect("el primer trozo del volcado debe llegar")
        .unwrap();
    assert!(leidos > 0, "el volcado debe haber empezado a fluir");

    // Y ahora, a mitad del flujo, el plugin desaparece.
    hijo.start_kill().unwrap();
    tokio::time::timeout(LIMITE, hijo.wait())
        .await
        .expect("recoger al plugin muerto no debe colgarse")
        .unwrap();

    // La lectura tiene que terminar: con error o con fin de flujo, pero
    // terminar. Se drena lo que quedara en el búfer del socket.
    let mut total = leidos;
    loop {
        let paso = tokio::time::timeout(LIMITE_FALLO, flujo.read(&mut buffer))
            .await
            .expect("leer del canal de datos de un plugin muerto no debe colgarse");
        match paso {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
    assert!(
        i64::try_from(total).unwrap() < VOLCADO_LARGO,
        "el volcado se cortó a mitad: no puede haber llegado entero"
    );

    // El flujo de progreso del RPC tampoco puede quedarse abierto para siempre.
    let siguiente = tokio::time::timeout(LIMITE_FALLO, progreso.message())
        .await
        .expect("el flujo de progreso de un plugin muerto no debe colgarse");
    assert!(
        siguiente.is_err() || matches!(siguiente, Ok(None)),
        "el progreso de un volcado interrumpido no puede seguir avanzando"
    );

    terminar(&mut hijo).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn un_canal_de_datos_al_que_nadie_se_conecta_vence_por_tiempo() {
    // Un plugin que acepta el RPC y nunca abre el socket. Sin límite por parte
    // de quien llama, el backup se colgaría para siempre: por eso `accept` no
    // impone el suyo y documenta que es obligación del que llama ponerlo.
    let dir = tempfile::tempdir().unwrap();
    let datos = DataChannel::create(dir.path(), "nadie").unwrap();

    let resultado = tokio::time::timeout(LIMITE_VENCE, datos.accept()).await;

    assert!(
        resultado.is_err(),
        "un accept sin nadie al otro lado debe vencer por tiempo"
    );
}
