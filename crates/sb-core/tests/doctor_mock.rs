// Igual que en `backup_mock.rs`: este fichero es todo código de prueba, y ahí
// un `unwrap` es lo que se quiere —que el test explote justo donde falló—.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `doctor` contra `sb-plugin-mock`, con dos plugins de verdad.
//!
//! Lo que solo se ve aquí es la propiedad que distingue a `doctor` del resto de
//! operaciones: **no aborta**. Un plugin sin configurar, o directamente muerto,
//! tiene que aparecer como un hallazgo del informe y no impedir que el otro
//! plugin se compruebe. Ningún test unitario puede enseñar eso, porque hace
//! falta un proceso al que matar.

mod comun;

use comun::{arrancar, configurar, matar, preparar};

use sb_core::ops::doctor::ejecutar_doctor;

#[tokio::test]
async fn con_los_dos_plugins_configurados_el_informe_esta_limpio() {
    let dir = tempfile::tempdir().unwrap();
    let (motor, destino) = preparar(dir.path(), 7, 1024).await;

    let informe = ejecutar_doctor("prueba", &motor, &destino).await;

    assert!(informe.ok(), "fallos inesperados: {:?}", informe.fallos());
    assert_eq!(informe.target, "prueba");
    assert!(
        informe.checks.iter().any(|c| c.origen == "engine"),
        "el informe no trae comprobaciones del motor: {:?}",
        informe.checks
    );
    assert!(
        informe.checks.iter().any(|c| c.origen == "storage"),
        "el informe no trae comprobaciones del destino: {:?}",
        informe.checks
    );

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn un_plugin_sin_configurar_sale_como_fallo_pero_el_informe_se_genera() {
    let dir = tempfile::tempdir().unwrap();
    let motor = arrancar("mock-engine").await;
    configurar(&motor, dir.path()).await;
    // El destino se queda sin `Configure` a propósito.
    let destino = arrancar("mock-storage").await;

    let informe = ejecutar_doctor("prueba", &motor, &destino).await;

    assert!(!informe.ok());
    let fallos = informe.fallos();
    assert_eq!(fallos.len(), 1, "fallos: {fallos:?}");
    assert_eq!(fallos[0].origen, "storage");
    assert!(
        !fallos[0].remedio.is_empty(),
        "un fallo sin remedio no le sirve a nadie: {:?}",
        fallos[0]
    );
    // El motor sí se comprobó, y salió bien.
    assert!(
        informe.checks.iter().any(|c| c.origen == "engine" && c.ok),
        "el motor no llegó a comprobarse: {:?}",
        informe.checks
    );

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn la_version_de_la_fuente_que_reporta_el_motor_llega_al_informe() {
    let dir = tempfile::tempdir().unwrap();
    let (motor, destino) = preparar(dir.path(), 7, 1024).await;

    let informe = ejecutar_doctor("prueba", &motor, &destino).await;

    // Es la que el mock declara en su `PreflightResponse`; el manifiesto de un
    // backup la necesitará para saber contra qué versión se hizo el volcado.
    assert_eq!(informe.server_version(), Some("mock"));

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}

#[tokio::test]
async fn un_plugin_muerto_es_un_fallo_del_informe_y_el_otro_igual_se_comprueba() {
    let dir = tempfile::tempdir().unwrap();
    let (motor, destino) = preparar(dir.path(), 7, 1024).await;
    matar(&motor).await;

    // Nada de `unwrap`: `ejecutar_doctor` no devuelve `Result` justamente
    // porque esto no es un error de la operación.
    let informe = ejecutar_doctor("prueba", &motor, &destino).await;

    assert!(!informe.ok());
    let fallos = informe.fallos();
    assert!(
        fallos.iter().any(|c| c.origen == "engine"),
        "el motor muerto no figura como fallo: {fallos:?}"
    );
    assert!(
        fallos.iter().all(|c| !c.remedio.is_empty()),
        "un fallo sin remedio no le sirve a nadie: {fallos:?}"
    );
    // Lo que de verdad se está comprobando: el destino se comprobó igualmente.
    assert!(
        informe.checks.iter().any(|c| c.origen == "storage" && c.ok),
        "el destino no llegó a comprobarse: {:?}",
        informe.checks
    );

    motor.shutdown().await.unwrap();
    destino.shutdown().await.unwrap();
}
