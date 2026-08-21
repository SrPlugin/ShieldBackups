// Igual que en `backup_mock.rs`: este fichero es todo código de prueba y ahí un
// `unwrap` es lo que se quiere —que el test explote justo donde falló—.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! El ciclo completo: backup → verify → restore, contra `sb-plugin-mock`.
//!
//! `backup_mock.rs` comprueba que el artefacto llega al destino. Eso no basta:
//! **un backup que no restaura no es un backup**. Lo que se prueba aquí es lo
//! único que justifica el proyecto entero —que los bytes que salieron del motor
//! vuelven a entrar en él, idénticos, después de cruzar cuatro veces el límite
//! de proceso y tres capas de pipeline— y la propiedad que hace que eso se
//! pueda comprobar sin arriesgar nada: que `verify` no necesita la clave
//! privada.

mod comun;

use comun::{FICHERO_RESTAURADO, datos_del_motor, peticion, preparar};

use sb_core::ops::backup::ejecutar_backup;
use sb_core::ops::restore::{RestoreRequest, ejecutar_restore};
use sb_core::ops::verify::ejecutar_verify;
use sb_crypto::{CompressionLevel, Digest, Identity};

/// Lo que el motor recibió por `Restore`.
fn restaurado(dir: &std::path::Path) -> Vec<u8> {
    std::fs::read(dir.join(FICHERO_RESTAURADO)).unwrap()
}

#[tokio::test]
async fn el_ciclo_completo_reproduce_los_datos_originales_byte_a_byte() {
    // ESTE es el test que justifica el proyecto. Todo lo demás es soporte.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (seed, size) = (7_u64, 2 * 1024 * 1024_usize);
    let (motor, destino) = preparar(dir.path(), 7, 2 * 1024 * 1024).await;

    let backup = ejecutar_backup(peticion(&motor, &destino, "ciclo/artefacto.age", &id))
        .await
        .unwrap();

    // 1. Verificar antes de restaurar: es el orden en que lo haría una persona
    //    que acaba de perder la base de datos.
    let v = ejecutar_verify(&destino, "ciclo/artefacto.age")
        .await
        .unwrap();
    assert!(v.ok, "el artefacto recién subido debe verificar");
    assert_eq!(v.digest_obtenido, backup.summary.ciphertext_sha256.to_hex());
    assert_eq!(v.bytes, backup.summary.ciphertext_bytes);

    // 2. Restaurar contra el motor.
    let escritos = ejecutar_restore(RestoreRequest {
        engine: &motor,
        storage: &destino,
        artifact_key: "ciclo/artefacto.age".into(),
        identity: &id,
        expected_ciphertext_sha256: Some(backup.summary.ciphertext_sha256),
    })
    .await
    .unwrap();

    assert_eq!(escritos, u64::try_from(size).unwrap());
    assert_eq!(
        restaurado(dir.path()),
        datos_del_motor(seed, size),
        "el ciclo completo no reprodujo los datos originales"
    );

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn verify_no_necesita_la_clave_privada() {
    // La razón de que el pipeline hashee el texto cifrado y no el plano: una
    // máquina puede comprobar que sus backups siguen íntegros sin tener con qué
    // leerlos. `ejecutar_verify` ni siquiera recibe una `Identity`, así que
    // esto lo garantiza el tipo; el test lo deja escrito.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (motor, destino) = preparar(dir.path(), 13, 512 * 1024).await;

    let backup = ejecutar_backup(peticion(&motor, &destino, "sinclave.age", &id))
        .await
        .unwrap();

    // La identidad se destruye antes de verificar: aquí ya no hay con qué
    // descifrar nada.
    drop(id);

    let v = ejecutar_verify(&destino, "sinclave.age").await.unwrap();
    assert!(v.ok);
    assert_eq!(v.digest_esperado, backup.summary.ciphertext_sha256.to_hex());
    assert_eq!(v.digest_obtenido, v.digest_esperado);

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn verify_detecta_un_artefacto_corrupto() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (motor, destino) = preparar(dir.path(), 21, 256 * 1024).await;

    let backup = ejecutar_backup(peticion(&motor, &destino, "corrupto.age", &id))
        .await
        .unwrap();

    // Un solo bit, en medio del artefacto y sin tocar el manifiesto: es
    // exactamente lo que hace un disco que se está muriendo.
    let ruta = dir.path().join("corrupto.age");
    let mut bytes = std::fs::read(&ruta).unwrap();
    let medio = bytes.len() / 2;
    bytes[medio] ^= 0x01;
    std::fs::write(&ruta, &bytes).unwrap();

    let v = ejecutar_verify(&destino, "corrupto.age").await.unwrap();
    assert!(!v.ok, "un artefacto con un bit cambiado no puede dar ok");
    assert_eq!(v.digest_esperado, backup.summary.ciphertext_sha256.to_hex());
    assert_ne!(v.digest_obtenido, v.digest_esperado);
    assert_eq!(
        v.bytes, backup.summary.ciphertext_bytes,
        "el tamaño no cambió: lo que lo delata es el digest"
    );

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn verify_detecta_un_artefacto_truncado() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (motor, destino) = preparar(dir.path(), 22, 256 * 1024).await;

    let backup = ejecutar_backup(peticion(&motor, &destino, "truncado.age", &id))
        .await
        .unwrap();

    let ruta = dir.path().join("truncado.age");
    let bytes = std::fs::read(&ruta).unwrap();
    std::fs::write(&ruta, &bytes[..bytes.len() / 2]).unwrap();

    let v = ejecutar_verify(&destino, "truncado.age").await.unwrap();
    assert!(!v.ok);
    assert!(
        v.bytes < backup.summary.ciphertext_bytes,
        "aquí lo delatan los dos: el tamaño y el digest"
    );
    assert_ne!(v.digest_obtenido, v.digest_esperado);

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn verify_sin_manifiesto_falla_diciendo_que_clave_buscaba() {
    // Sin manifiesto no hay contra qué comparar. El mensaje tiene que decir la
    // clave exacta que se buscó: quien lo lea a las tres de la mañana necesita
    // saber si el manifiesto se perdió o si nunca se llamó así.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (motor, destino) = preparar(dir.path(), 4, 64 * 1024).await;

    ejecutar_backup(peticion(&motor, &destino, "huerfano.age", &id))
        .await
        .unwrap();
    std::fs::remove_file(dir.path().join("huerfano.age.manifest.json")).unwrap();

    let texto = ejecutar_verify(&destino, "huerfano.age")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        texto.contains("huerfano.age.manifest.json"),
        "el error debe nombrar la clave que buscó: {texto}"
    );
    assert!(
        texto.contains("manifiesto"),
        "y decir qué es lo que falta: {texto}"
    );

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn restore_comprueba_el_digest_esperado() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (seed, size) = (31_u64, 128 * 1024_usize);
    let (motor, destino) = preparar(dir.path(), 31, 128 * 1024).await;

    let backup = ejecutar_backup(peticion(&motor, &destino, "digest.age", &id))
        .await
        .unwrap();

    // Con el digest bueno: restaura.
    ejecutar_restore(RestoreRequest {
        engine: &motor,
        storage: &destino,
        artifact_key: "digest.age".into(),
        identity: &id,
        expected_ciphertext_sha256: Some(backup.summary.ciphertext_sha256),
    })
    .await
    .unwrap();
    assert_eq!(restaurado(dir.path()), datos_del_motor(seed, size));

    // Con un digest que no es el suyo: falla, aunque el artefacto esté
    // perfectamente descifrable. Es la comprobación de que el destino sirvió
    // el artefacto que el manifiesto dice, y no otro.
    let falso =
        Digest::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
    let error = ejecutar_restore(RestoreRequest {
        engine: &motor,
        storage: &destino,
        artifact_key: "digest.age".into(),
        identity: &id,
        expected_ciphertext_sha256: Some(falso),
    })
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("digest"),
        "el error debe explicar que el digest no cuadra: {error}"
    );

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn restore_con_una_identidad_ajena_falla_sin_dejar_datos_utilizables() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let intrusa = Identity::generate();
    let (motor, destino) = preparar(dir.path(), 41, 512 * 1024).await;

    ejecutar_backup(peticion(&motor, &destino, "ajeno.age", &id))
        .await
        .unwrap();

    let error = ejecutar_restore(RestoreRequest {
        engine: &motor,
        storage: &destino,
        artifact_key: "ajeno.age".into(),
        identity: &intrusa,
        expected_ciphertext_sha256: None,
    })
    .await
    .unwrap_err();
    assert!(!error.to_string().is_empty());

    // age falla al leer la cabecera, antes de entregar un solo bloque: el
    // motor no llega a recibir nada. Lo que no puede pasar bajo ningún
    // concepto es que quede ahí un fichero con datos de verdad.
    let ruta = dir.path().join(FICHERO_RESTAURADO);
    let dejado = if ruta.exists() {
        std::fs::read(&ruta).unwrap()
    } else {
        Vec::new()
    };
    assert!(
        dejado.is_empty(),
        "una identidad ajena dejó {} bytes de plaintext en el motor",
        dejado.len()
    );

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn el_ciclo_completo_funciona_con_un_tamano_no_redondo_y_varios_niveles() {
    // Un tamaño que no es múltiplo de nada fuerza el último bloque parcial en
    // las tres capas a la vez, que es donde vive el fallo de un cierre mal
    // ordenado.
    let size = 1024 * 1024 + 13_usize;
    let seed = 77_u64;

    for nivel in [1_i32, 3, 19] {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate();
        let (motor, destino) = preparar(dir.path(), 77, 1024 * 1024 + 13).await;

        let backup = ejecutar_backup(sb_core::ops::backup::BackupRequest {
            level: CompressionLevel::new(nivel).unwrap(),
            ..peticion(&motor, &destino, "raro.age", &id)
        })
        .await
        .unwrap();
        assert_eq!(backup.summary.plaintext_bytes, u64::try_from(size).unwrap());

        assert!(
            ejecutar_verify(&destino, "raro.age").await.unwrap().ok,
            "verify falló con nivel {nivel}"
        );

        let escritos = ejecutar_restore(RestoreRequest {
            engine: &motor,
            storage: &destino,
            artifact_key: "raro.age".into(),
            identity: &id,
            expected_ciphertext_sha256: Some(backup.summary.ciphertext_sha256),
        })
        .await
        .unwrap();

        assert_eq!(escritos, u64::try_from(size).unwrap(), "nivel {nivel}");
        assert_eq!(
            restaurado(dir.path()),
            datos_del_motor(seed, size),
            "el ciclo no reprodujo los datos con nivel {nivel}"
        );

        motor.shutdown().await.unwrap();
        destino.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn el_ciclo_completo_de_una_fuente_vacia() {
    // Cero bytes es el caso que revela un cierre de capa omitido: el artefacto
    // tiene forma correcta y no restaura.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (motor, destino) = preparar(dir.path(), 1, 0).await;

    let backup = ejecutar_backup(peticion(&motor, &destino, "vacio.age", &id))
        .await
        .unwrap();
    assert_eq!(backup.summary.plaintext_bytes, 0);

    let v = ejecutar_verify(&destino, "vacio.age").await.unwrap();
    assert!(v.ok);
    assert_eq!(v.bytes, backup.summary.ciphertext_bytes);
    assert!(v.bytes > 0, "cabecera age y frame zstd");

    let escritos = ejecutar_restore(RestoreRequest {
        engine: &motor,
        storage: &destino,
        artifact_key: "vacio.age".into(),
        identity: &id,
        expected_ciphertext_sha256: Some(backup.summary.ciphertext_sha256),
    })
    .await
    .unwrap();

    assert_eq!(escritos, 0);
    assert!(restaurado(dir.path()).is_empty());

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn el_manifiesto_se_puede_leer_sin_descargar_el_artefacto() {
    // `restore` necesita el digest que el manifiesto promete **antes** de
    // mover un byte, igual que `verify`. Que la lectura del manifiesto sea una
    // operación propia es lo que evita que cada una tenga su propia idea de
    // cómo se llama y de qué contiene.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (motor, destino) = preparar(dir.path(), 5, 32 * 1024).await;

    let backup = ejecutar_backup(peticion(&motor, &destino, "manifiesto.age", &id))
        .await
        .unwrap();

    let m = sb_core::ops::verify::leer_manifiesto(&destino, "manifiesto.age")
        .await
        .unwrap();
    assert_eq!(m.artifact_key, "manifiesto.age");
    assert_eq!(m.target, "prueba");
    assert_eq!(
        m.ciphertext_sha256,
        backup.summary.ciphertext_sha256.to_hex()
    );
    assert_eq!(m.ciphertext_bytes, backup.summary.ciphertext_bytes);

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}
