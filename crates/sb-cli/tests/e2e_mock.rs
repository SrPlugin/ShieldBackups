// Igual que en el resto de los tests del workspace: aquí un `unwrap` es lo que
// se quiere, que el test explote justo donde falló.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! El ciclo real de la CLI contra `sb-plugin-mock`.
//!
//! `cli.rs` comprueba la superficie; esto comprueba que la superficie está
//! conectada a algo. Se ejecuta el binario de verdad, arrancando plugins de
//! verdad, y se mira el directorio del destino para ver si el artefacto está
//! donde la CLI dice que lo dejó.
//!
//! Dos de estos tests no son del ciclo feliz y son los que más importan: el
//! que comprueba que **sin `plugin lock` no se ejecuta nada** y el que
//! comprueba que **un binario alterado después del `lock` tampoco**. Un plugin
//! recibe las credenciales de la base de datos y del almacenamiento; que esa
//! puerta esté cerrada es la propiedad de seguridad que sostiene la
//! arquitectura entera.

mod comun;

use comun::{Banco, alterar, json_de};

use sb_crypto::Identity;

/// Una identidad nueva y su fichero de clave, como los escribiría `age-keygen`.
fn identidad(banco: &Banco) -> (Identity, std::path::PathBuf) {
    let id = Identity::generate();
    let ruta = banco.ruta("clave.age");
    std::fs::write(
        &ruta,
        format!(
            "# created: 2026-08-21T00:00:00Z\n# public key: {}\n{}\n",
            id.to_recipient(),
            id.to_secret_string().expose()
        ),
    )
    .unwrap();
    (id, ruta)
}

/// Deja el banco listo: mock instalado, registrado y una config que lo usa.
fn preparado() -> (Banco, std::path::PathBuf, Identity, std::path::PathBuf) {
    let banco = Banco::nuevo();
    banco.instalar_mock();
    let (id, clave) = identidad(&banco);
    let config = banco.config_mock(&id.to_recipient().to_string());

    let lock = banco
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
        .output()
        .unwrap();
    assert!(
        lock.status.success(),
        "plugin lock falló: {}",
        String::from_utf8_lossy(&lock.stderr)
    );

    (banco, config, id, clave)
}

#[test]
fn el_ciclo_lock_doctor_backup_verify_funciona_de_principio_a_fin() {
    let (banco, config, _id, _clave) = preparado();
    let config = config.to_string_lossy().into_owned();

    let doctor = banco
        .cmd()
        .args(["--config", &config, "doctor"])
        .output()
        .unwrap();
    assert!(
        doctor.status.success(),
        "doctor falló:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&doctor.stdout),
        String::from_utf8_lossy(&doctor.stderr)
    );

    let backup = banco
        .cmd()
        .args(["--config", &config, "backup"])
        .output()
        .unwrap();
    assert!(
        backup.status.success(),
        "backup falló:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&backup.stdout),
        String::from_utf8_lossy(&backup.stderr)
    );

    // El artefacto tiene que estar de verdad en el destino, no solo dicho.
    let artefactos: Vec<_> = walk(&banco.dir_datos())
        .into_iter()
        .filter(|r| !r.ends_with(".manifest.json"))
        .collect();
    assert_eq!(
        artefactos.len(),
        1,
        "se esperaba un artefacto: {artefactos:?}"
    );

    let verify = banco
        .cmd()
        .args(["--config", &config, "verify", "produccion"])
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "verify falló:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    let texto = String::from_utf8_lossy(&verify.stdout).to_string();
    assert!(
        texto.contains("1/1"),
        "verify sin artefacto debe comprobar todos los del target: {texto}"
    );
}

#[test]
fn sin_plugin_lock_previo_el_backup_se_niega_y_dice_como_registrarlo() {
    // La puerta que sostiene la arquitectura: shieldbk no ejecuta binarios que
    // no ha verificado, porque a un plugin se le entregan las credenciales de
    // la base de datos.
    let banco = Banco::nuevo();
    banco.instalar_mock();
    let (id, _clave) = identidad(&banco);
    let config = banco.config_mock(&id.to_recipient().to_string());

    let salida = banco
        .cmd()
        .args(["--config", &config.to_string_lossy(), "backup"])
        .output()
        .unwrap();

    assert_eq!(
        salida.status.code(),
        Some(3),
        "un plugin sin registrar es un error de plugin"
    );
    let texto = String::from_utf8_lossy(&salida.stderr).to_string();
    assert!(
        texto.contains("plugin lock"),
        "el mensaje debe decir cómo registrarlo: {texto}"
    );
    assert!(
        texto.contains("mock"),
        "y qué plugin es el que no está registrado: {texto}"
    );

    // Y sobre todo: no puede haber quedado nada en el destino.
    assert!(
        walk(&banco.dir_datos()).is_empty(),
        "un backup que se negó a ejecutarse no puede haber escrito nada"
    );
}

#[test]
fn si_el_binario_cambia_despues_del_lock_el_backup_se_niega_y_lo_explica() {
    let (banco, config, _id, _clave) = preparado();
    alterar(&banco.dir_plugins().join("sb-plugin-mock"));

    let salida = banco
        .cmd()
        .args(["--config", &config.to_string_lossy(), "backup"])
        .output()
        .unwrap();

    assert_eq!(salida.status.code(), Some(3));
    let texto = String::from_utf8_lossy(&salida.stderr).to_string();
    assert!(
        texto.contains("ha cambiado"),
        "el mensaje debe explicar que el binario cambió: {texto}"
    );
    assert!(
        texto.contains("sha256"),
        "y enseñar los dos hashes para poder comprobarlo: {texto}"
    );
    assert!(walk(&banco.dir_datos()).is_empty());
}

#[test]
fn restore_reproduce_los_datos_que_el_motor_habia_volcado() {
    // Es lo único que justifica el proyecto: un backup que no restaura no es
    // un backup.
    let (banco, config, _id, clave) = preparado();
    let config = config.to_string_lossy().into_owned();

    let backup = banco
        .cmd()
        .args(["--config", &config, "--format", "json", "backup"])
        .output()
        .unwrap();
    assert!(backup.status.success());
    let json = json_de(&backup.stdout);
    let artefacto = json["targets"][0]["artifact_key"].as_str().unwrap();

    let restore = banco
        .cmd()
        .args([
            "--config",
            &config,
            "restore",
            "produccion",
            artefacto,
            "--identity",
            &clave.to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(
        restore.status.success(),
        "restore falló:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&restore.stdout),
        String::from_utf8_lossy(&restore.stderr)
    );

    // El motor mock deja en `restore.bin` lo que recibe, y su volcado es
    // determinista: se puede regenerar aquí y comparar byte a byte.
    let restaurado = std::fs::read(banco.dir_datos().join("restore.bin")).unwrap();
    let esperado: Vec<u8> = sb_plugin_mock::datos_deterministas(7, 65536).collect();
    assert_eq!(
        restaurado, esperado,
        "el ciclo completo por la CLI no reprodujo los datos originales"
    );
}

#[test]
fn doctor_detecta_un_recipient_invalido_en_la_configuracion() {
    // Una errata en la clave pública no da ningún error hasta que alguien
    // intenta restaurar, y entonces ya no hay nada que hacer. `doctor` la
    // convierte en un fallo inmediato.
    let banco = Banco::nuevo();
    banco.instalar_mock();
    let config = banco.config_mock("age1esto-no-es-una-clave-publica");
    let lock = banco
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
        .output()
        .unwrap();
    assert!(lock.status.success());

    let salida = banco
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "json",
            "doctor",
        ])
        .output()
        .unwrap();

    assert_eq!(
        salida.status.code(),
        Some(4),
        "un diagnóstico con fallos es un error de operación"
    );
    let json = json_de(&salida.stdout);
    assert_eq!(json["ok"], serde_json::Value::Bool(false));

    let checks = json["targets"][0]["checks"].as_array().unwrap();
    let recipiente = checks
        .iter()
        .find(|c| c["nombre"] == "recipient")
        .expect("doctor tiene que comprobar el recipient");
    assert_eq!(recipiente["ok"], serde_json::Value::Bool(false));
    assert_eq!(
        recipiente["origen"], "config",
        "el problema está en el fichero, no en un plugin"
    );
    assert!(
        !recipiente["remedio"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "un check que falla sin remedio no sirve de nada"
    );
}

#[test]
fn el_backup_en_json_da_la_clave_del_artefacto() {
    let (banco, config, _id, _clave) = preparado();

    let salida = banco
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "json",
            "-vv",
            "backup",
        ])
        .output()
        .unwrap();
    assert!(salida.status.success());

    // Con `-vv` hay registros de sobra; ninguno puede haberse colado aquí.
    let json = json_de(&salida.stdout);
    assert_eq!(json["ok"], serde_json::Value::Bool(true));
    let clave = json["targets"][0]["artifact_key"].as_str().unwrap();
    assert!(
        clave.starts_with("produccion/"),
        "la clave sale de la plantilla del target: {clave}"
    );
    assert!(clave.ends_with(".dump.zst.age"), "{clave}");
    assert!(
        banco.dir_datos().join(clave).is_file(),
        "el artefacto que dice el JSON tiene que existir: {clave}"
    );
    assert!(
        !salida.stderr.is_empty(),
        "con -vv hay registros, en stderr"
    );
}

#[test]
fn storage_gc_habla_con_el_destino_y_cuenta_lo_que_abortó() {
    let (banco, config, _id, _clave) = preparado();
    let salida = banco
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "json",
            "storage",
            "gc",
            "produccion",
        ])
        .output()
        .unwrap();

    assert!(
        salida.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&salida.stderr)
    );
    let json = json_de(&salida.stdout);
    assert_eq!(json["target"], "produccion");
    // El destino mock escribe cada artefacto de una vez: no hay multipart que
    // abortar y por eso son cero. Lo que se comprueba es que la llamada llegó.
    assert_eq!(json["abortadas"], 0);
    assert_eq!(json["prefijo"], "produccion/");
}

#[test]
fn plugin_docs_ensena_el_esquema_del_plugin_y_ningun_valor() {
    let (banco, config, _id, _clave) = preparado();
    let salida = banco
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "plugin",
            "docs",
            "mock",
        ])
        .output()
        .unwrap();

    assert!(
        salida.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&salida.stderr)
    );
    let texto = String::from_utf8_lossy(&salida.stdout).to_string();
    for esperado in ["CAMPO", "TIPO", "REQ", "SECRETO", "dir", "seed", "size"] {
        assert!(texto.contains(esperado), "falta «{esperado}»:\n{texto}");
    }
    assert!(
        !texto.contains(&banco.dir_datos().to_string_lossy().to_string()),
        "docs describe el esquema, nunca lo que hay configurado:\n{texto}"
    );
}

#[test]
fn plugin_list_ensena_el_estado_de_cada_binario() {
    let banco = Banco::nuevo();
    banco.instalar_mock();
    let config = banco.config_mock("age1qqqqqqqqqq");

    let antes = banco
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "json",
            "plugin",
            "list",
        ])
        .output()
        .unwrap();
    assert!(
        antes.status.success(),
        "listar no falla por no estar el lock"
    );
    let json = json_de(&antes.stdout);
    assert_eq!(json["plugins"][0]["nombre"], "mock");
    assert_eq!(json["plugins"][0]["usable"], serde_json::Value::Bool(false));

    banco
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
        .output()
        .unwrap();

    let despues = banco
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "json",
            "plugin",
            "list",
        ])
        .output()
        .unwrap();
    let json = json_de(&despues.stdout);
    assert_eq!(json["plugins"][0]["usable"], serde_json::Value::Bool(true));
}

/// Las rutas relativas de todo lo que hay bajo `raiz`, en orden estable.
fn walk(raiz: &std::path::Path) -> Vec<String> {
    let mut encontrados = Vec::new();
    let mut pendientes = vec![raiz.to_path_buf()];
    while let Some(dir) = pendientes.pop() {
        let Ok(entradas) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entrada in entradas.flatten() {
            let ruta = entrada.path();
            if ruta.is_dir() {
                pendientes.push(ruta);
            } else if let Ok(relativa) = ruta.strip_prefix(raiz) {
                encontrados.push(relativa.to_string_lossy().into_owned());
            }
        }
    }
    encontrados.sort();
    encontrados
}
