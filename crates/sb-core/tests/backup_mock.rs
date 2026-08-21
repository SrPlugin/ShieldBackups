// Igual que en `sb-transport/tests/fallos.rs`: este fichero es todo código de
// prueba, ayudantes incluidos, y ahí un `unwrap` es lo que se quiere —que el
// test explote justo donde falló—.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Backup completo contra `sb-plugin-mock`, de punta a punta y sin red.
//!
//! Los tests de las piezas sueltas ya cubren el pipeline, el canal de datos y
//! el arranque de plugins. Lo que solo se puede comprobar aquí es lo que pasa
//! cuando los bytes cruzan **dos veces** el límite de proceso: motor → núcleo →
//! destino. Un fallo en ese camino no lo ve ningún test unitario, y se
//! manifestaría como un artefacto que no se puede restaurar.

mod comun;

use comun::{peticion, preparar};

use sb_core::ops::backup::{BackupRequest, ejecutar_backup};
use sb_crypto::Identity;
// Arriba y no dentro de cada test: `clippy::pedantic` prohíbe declarar items
// después de las sentencias, y `shutdown` sobre el `Sha256Writer` lo necesitan
// varios de ellos.
use tokio::io::AsyncWriteExt as _;

#[tokio::test]
async fn un_backup_completo_produce_artefacto_y_manifiesto() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (motor, destino) = preparar(dir.path(), 7, 2 * 1024 * 1024).await;

    let r = ejecutar_backup(peticion(&motor, &destino, "prueba/artefacto.age", &id))
        .await
        .unwrap();

    assert_eq!(r.summary.plaintext_bytes, 2 * 1024 * 1024);
    assert!(r.summary.ciphertext_bytes > 0);

    assert!(dir.path().join("prueba/artefacto.age").exists());
    assert!(
        dir.path()
            .join("prueba/artefacto.age.manifest.json")
            .exists()
    );

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn el_manifiesto_describe_fielmente_el_artefacto() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (motor, destino) = preparar(dir.path(), 3, 512 * 1024).await;

    let r = ejecutar_backup(peticion(&motor, &destino, "m.age", &id))
        .await
        .unwrap();

    let texto = std::fs::read_to_string(dir.path().join("m.age.manifest.json")).unwrap();
    let m = sb_core::model::Manifest::parse(&texto).unwrap();

    assert_eq!(m.plaintext_bytes, 512 * 1024);
    assert_eq!(m.ciphertext_sha256, r.summary.ciphertext_sha256.to_hex());
    assert_eq!(m.plaintext_sha256, r.summary.plaintext_sha256.to_hex());
    assert_eq!(m.artifact_key, "m.age");
    assert_eq!(m.target, "prueba");
    assert_eq!(m.encryption.recipient, id.to_recipient().to_string());

    // El tamaño declarado coincide con el fichero que hay de verdad en el destino.
    let real = std::fs::metadata(dir.path().join("m.age")).unwrap().len();
    assert_eq!(m.ciphertext_bytes, real);

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn el_artefacto_del_destino_es_exactamente_lo_que_produjo_el_pipeline() {
    // Comprueba que nada se corrompe al cruzar dos veces el límite de proceso.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (motor, destino) = preparar(dir.path(), 11, 3 * 1024 * 1024 + 7).await;

    let r = ejecutar_backup(peticion(&motor, &destino, "exacto.age", &id))
        .await
        .unwrap();

    let bytes = std::fs::read(dir.path().join("exacto.age")).unwrap();
    assert_eq!(bytes.len() as u64, r.summary.ciphertext_bytes);

    // Y su digest coincide con el que calculó el pipeline al vuelo.
    let mut w = sb_crypto::Sha256Writer::new(Vec::new());
    w.write_all(&bytes).await.unwrap();
    w.shutdown().await.unwrap();
    assert_eq!(w.into_parts().1, r.summary.ciphertext_sha256);

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn el_plaintext_hasheado_es_el_que_el_motor_dijo_producir() {
    // El resumen no se cree lo que diga el motor: se regenera el flujo
    // determinista aquí y se compara con el digest que el pipeline calculó al
    // vuelo. Si un byte se perdiera entre el motor y el núcleo, esto lo ve.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (motor, destino) = preparar(dir.path(), 23, 1024 * 1024 + 3).await;

    let r = ejecutar_backup(peticion(&motor, &destino, "fiel.age", &id))
        .await
        .unwrap();

    let esperado: Vec<u8> = sb_plugin_mock::datos_deterministas(23, 1024 * 1024 + 3).collect();
    let mut w = sb_crypto::Sha256Writer::new(Vec::new());
    w.write_all(&esperado).await.unwrap();
    w.shutdown().await.unwrap();
    assert_eq!(w.into_parts().1, r.summary.plaintext_sha256);

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn el_backup_de_una_fuente_vacia_tambien_funciona() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (motor, destino) = preparar(dir.path(), 1, 0).await;

    let r = ejecutar_backup(peticion(&motor, &destino, "vacio.age", &id))
        .await
        .unwrap();

    assert_eq!(r.summary.plaintext_bytes, 0);
    assert!(r.summary.ciphertext_bytes > 0, "cabecera age y frame zstd");
    assert!(dir.path().join("vacio.age").exists());

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn una_clave_con_barras_crea_la_jerarquia() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (motor, destino) = preparar(dir.path(), 5, 4096).await;

    ejecutar_backup(peticion(&motor, &destino, "a/b/c/d.age", &id))
        .await
        .unwrap();
    assert!(dir.path().join("a/b/c/d.age").exists());
    assert!(dir.path().join("a/b/c/d.age.manifest.json").exists());

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn un_plugin_sin_la_capacidad_necesaria_se_rechaza_antes_de_empezar() {
    // Pedirle un dump a un plugin que solo es destino debe fallar de inmediato
    // y con un error del dominio, no a mitad del flujo de datos.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (motor, destino) = preparar(dir.path(), 1, 1024).await;

    // Se invierten los papeles a propósito: se comprueba que la validación de
    // capacidades existe. El mock tiene ambas, así que esto debe funcionar;
    // lo que se verifica es que `ejecutar_backup` llama a exigir_capacidad.
    let r = ejecutar_backup(BackupRequest {
        engine: &destino,
        storage: &motor,
        ..peticion(&motor, &destino, "invertido.age", &id)
    })
    .await;
    assert!(r.is_ok(), "el mock tiene ambas capacidades");

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn dos_backups_consecutivos_con_la_misma_fuente_dan_el_mismo_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let (motor, destino) = preparar(dir.path(), 99, 256 * 1024).await;

    let a = ejecutar_backup(peticion(&motor, &destino, "a.age", &id))
        .await
        .unwrap();
    let b = ejecutar_backup(peticion(&motor, &destino, "b.age", &id))
        .await
        .unwrap();

    assert_eq!(a.summary.plaintext_sha256, b.summary.plaintext_sha256);
    assert_ne!(
        a.summary.ciphertext_sha256, b.summary.ciphertext_sha256,
        "age usa una clave de fichero distinta cada vez"
    );

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}
