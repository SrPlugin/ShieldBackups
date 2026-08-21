// Igual que en el resto de los tests del workspace: aquí un `unwrap` es lo que
// se quiere, que el test explote justo donde falló.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Los tests de la superficie de la CLI: los que no necesitan un plugin vivo.
//!
//! Son los rápidos, y cubren lo que un script que llame a `shieldbk` necesita
//! poder dar por hecho: que hay seis comandos, que los códigos de salida
//! distinguen los tipos de error, y que en `--format json` la salida estándar
//! es JSON **pase lo que pase**.

mod comun;

use comun::{Banco, alterar, json_de};

/// Un error de configuración. Un script tiene que poder reaccionar distinto a
/// «la config está mal» que a «el backup falló».
const CODIGO_CONFIG: i32 = 2;

#[test]
fn el_help_muestra_los_seis_comandos() {
    let salida = Banco::nuevo().cmd().arg("--help").output().unwrap();
    assert!(salida.status.success());
    let texto = String::from_utf8_lossy(&salida.stdout).to_string();
    for comando in ["backup", "restore", "verify", "doctor", "plugin", "storage"] {
        assert!(
            texto.contains(comando),
            "el help no menciona «{comando}»:\n{texto}"
        );
    }
}

#[test]
fn la_version_funciona() {
    let salida = Banco::nuevo().cmd().arg("--version").output().unwrap();
    assert!(salida.status.success());
    let texto = String::from_utf8_lossy(&salida.stdout).to_string();
    assert!(
        texto.contains(env!("CARGO_PKG_VERSION")),
        "«--version» debe decir la versión: {texto}"
    );
}

#[test]
fn una_config_inexistente_da_codigo_2_y_nombra_la_ruta() {
    let banco = Banco::nuevo();
    let inexistente = banco.ruta("no/existe/config.toml");
    let salida = banco
        .cmd()
        .args(["--config", &inexistente.to_string_lossy(), "doctor"])
        .output()
        .unwrap();

    assert_eq!(salida.status.code(), Some(CODIGO_CONFIG));
    let texto = String::from_utf8_lossy(&salida.stderr).to_string();
    assert!(
        texto.contains(&inexistente.to_string_lossy().to_string()),
        "el error debe nombrar la ruta que buscó: {texto}"
    );
}

#[test]
fn un_toml_invalido_da_codigo_2_y_dice_que_es_toml() {
    let banco = Banco::nuevo();
    let config = banco.config("esto no es toml [[[");
    let salida = banco
        .cmd()
        .args(["--config", &config.to_string_lossy(), "doctor"])
        .output()
        .unwrap();

    assert_eq!(salida.status.code(), Some(CODIGO_CONFIG));
    let texto = String::from_utf8_lossy(&salida.stderr).to_lowercase();
    assert!(
        texto.contains("toml"),
        "el error debe decir que el problema es el TOML: {texto}"
    );
}

#[test]
fn una_config_sin_targets_da_codigo_2_y_lo_dice() {
    let banco = Banco::nuevo();
    let config = banco.config("[defaults]\ncompression_level = 6\n");
    let salida = banco
        .cmd()
        .args(["--config", &config.to_string_lossy(), "doctor"])
        .output()
        .unwrap();

    assert_eq!(salida.status.code(), Some(CODIGO_CONFIG));
    let texto = String::from_utf8_lossy(&salida.stderr).to_lowercase();
    assert!(
        texto.contains("target"),
        "el error debe decir que faltan targets: {texto}"
    );
}

#[test]
fn en_json_stdout_es_json_parseable_aunque_el_comando_falle() {
    // Es lo que hace la herramienta usable desde un script: `shieldbk --format
    // json backup | jq` tiene que funcionar también el día que el backup falle.
    let banco = Banco::nuevo();
    let inexistente = banco.ruta("no/existe/config.toml");
    let salida = banco
        .cmd()
        .args([
            "--config",
            &inexistente.to_string_lossy(),
            "--format",
            "json",
            "doctor",
        ])
        .output()
        .unwrap();

    assert_eq!(salida.status.code(), Some(CODIGO_CONFIG));
    let json = json_de(&salida.stdout);
    assert_eq!(json["ok"], serde_json::Value::Bool(false));
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("config"),
        "el JSON debe llevar el mensaje: {json}"
    );
}

#[test]
fn en_json_ningun_log_se_cuela_en_stdout() {
    // La salida estándar pertenece al resultado y nada más puede escribir ahí.
    // `-vv` sube la traza a `debug`, que es cuando de verdad hay volumen de
    // registros que colar.
    let banco = Banco::nuevo();
    let config = banco.config_mock("age1qqqqqqqqqq");
    let salida = banco
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "json",
            "-vv",
            "doctor",
            "no-existe",
        ])
        .output()
        .unwrap();

    assert_ne!(salida.status.code(), Some(0));
    let json = json_de(&salida.stdout);
    assert_eq!(json["ok"], serde_json::Value::Bool(false));
    assert!(
        !salida.stderr.is_empty(),
        "con -vv tiene que haber registros, y tienen que estar en stderr"
    );
}

#[test]
fn plugin_lock_registra_los_binarios_del_directorio_y_escribe_el_lockfile() {
    let banco = Banco::nuevo();
    let config = banco.config_mock("age1qqqqqqqqqq");
    std::fs::write(banco.dir_plugins().join("sb-plugin-uno"), b"binario uno").unwrap();
    std::fs::write(banco.dir_plugins().join("sb-plugin-dos"), b"binario dos").unwrap();
    // Un fichero que no es un plugin no debe acabar registrado.
    std::fs::write(banco.dir_plugins().join("LEEME.txt"), b"no soy un plugin").unwrap();

    let salida = banco
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
        .output()
        .unwrap();

    assert!(
        salida.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&salida.stderr)
    );
    let lock = std::fs::read_to_string(banco.lockfile()).unwrap();
    assert!(
        lock.contains("uno"),
        "el lockfile debe registrar uno: {lock}"
    );
    assert!(
        lock.contains("dos"),
        "el lockfile debe registrar dos: {lock}"
    );
    assert!(
        !lock.contains("LEEME"),
        "un fichero que no es un plugin no se registra: {lock}"
    );
}

#[test]
fn plugin_verify_pasa_tras_lock_y_falla_si_el_binario_cambia() {
    let banco = Banco::nuevo();
    let config = banco.config_mock("age1qqqqqqqqqq");
    let binario = banco.dir_plugins().join("sb-plugin-uno");
    std::fs::write(&binario, b"binario uno").unwrap();

    let lock = banco
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
        .output()
        .unwrap();
    assert!(lock.status.success());

    let bien = banco
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "verify"])
        .output()
        .unwrap();
    assert!(
        bien.status.success(),
        "recién registrado debe verificar: {}",
        String::from_utf8_lossy(&bien.stderr)
    );

    alterar(&binario);

    let mal = banco
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "verify"])
        .output()
        .unwrap();
    assert_eq!(
        mal.status.code(),
        Some(3),
        "un binario alterado es un error de plugin"
    );
    let texto = String::from_utf8_lossy(&mal.stderr).to_string();
    assert!(
        texto.contains("uno"),
        "el error debe nombrar el plugin alterado: {texto}"
    );
}

#[test]
fn un_target_inexistente_da_un_error_que_lo_nombra() {
    let banco = Banco::nuevo();
    let config = banco.config_mock("age1qqqqqqqqqq");
    let salida = banco
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "doctor",
            "el-que-no-esta",
        ])
        .output()
        .unwrap();

    assert_eq!(salida.status.code(), Some(CODIGO_CONFIG));
    let texto = String::from_utf8_lossy(&salida.stderr).to_string();
    assert!(
        texto.contains("el-que-no-esta"),
        "el error debe nombrar el target que se pidió: {texto}"
    );
    assert!(
        texto.contains("produccion"),
        "y ayudar diciendo cuáles hay: {texto}"
    );
}

#[test]
fn la_tilde_de_las_rutas_de_la_configuracion_se_expande() {
    // La configuración se escribe a mano y sus rutas se escriben como las
    // escribiría una persona. Ninguna shell las expande al leerlas de un TOML,
    // y sin esta expansión `shieldbk` crearía un directorio llamado
    // literalmente «~» dentro del directorio de trabajo: no fallaría, haría lo
    // correcto en el sitio equivocado.
    let banco = Banco::nuevo();
    let config = banco.config(
        r#"
[plugins]
dir = "~/plugins"
lockfile = "~/plugins.lock"

[[target]]
name = "produccion"
engine = "mock"
storage = "mock"
recipient = "age1qqqqqqqqqq"
"#,
    );
    std::fs::write(banco.dir_plugins().join("sb-plugin-uno"), b"uno").unwrap();

    let salida = banco
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
        .output()
        .unwrap();

    assert!(
        salida.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&salida.stderr)
    );
    assert!(
        banco.lockfile().is_file(),
        "el lockfile tenía que acabar en «{}», que es donde apunta ~",
        banco.lockfile().display()
    );
    assert!(
        !banco.ruta("~").exists(),
        "no puede haberse creado un directorio llamado literalmente «~»"
    );
}
