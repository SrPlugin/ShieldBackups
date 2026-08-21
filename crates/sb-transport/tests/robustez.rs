//! Robustez del handshake frente a la salida de un binario externo.
//!
//! El handshake es la primera superficie que ve el núcleo de un plugin: un
//! proceso hijo que puede estar roto, ser de otra versión o ser directamente
//! hostil. Un pánico aquí es un fallo del núcleo provocado por lo que otro
//! escribió en su stdout, así que la propiedad que se comprueba no es «parsea
//! bien» sino «no entra en pánico con nada».

use proptest::prelude::*;
use sb_transport::{Bootstrap, Ready};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Ninguna entrada, por absurda que sea, puede provocar un pánico.
    #[test]
    fn el_parser_de_ready_nunca_entra_en_panico(entrada in ".*") {
        let _ = Ready::from_line(&entrada);
    }

    #[test]
    fn el_parser_de_bootstrap_nunca_entra_en_panico(entrada in ".*") {
        let _ = Bootstrap::from_line(&entrada);
    }

    /// Bytes arbitrarios, incluidos los que no son UTF-8 válido.
    #[test]
    fn bytes_arbitrarios_no_provocan_panico(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let texto = String::from_utf8_lossy(&bytes);
        let _ = Ready::from_line(&texto);
        let _ = Bootstrap::from_line(&texto);
    }

    /// JSON estructuralmente válido con valores extremos.
    #[test]
    fn json_con_valores_extremos_no_provoca_panico(
        version in any::<u32>(),
        pid in any::<u32>(),
        n_caps in 0_usize..200,
    ) {
        let caps: Vec<String> = (0..n_caps).map(|i| format!("cap{i}")).collect();
        let json = format!(
            r#"{{"magic":"SHIELDBK_PLUGIN","protocol_version":{version},"capabilities":{},"pid":{pid}}}"#,
            serde_json::to_string(&caps).unwrap()
        );
        let _ = Ready::from_line(&json);
    }

    /// Un plugin puede anunciar cualquier lista de versiones, incluidas listas
    /// enormes o vacías. Negociar no puede entrar en pánico ni siquiera cuando
    /// no hay nada en común.
    #[test]
    fn la_negociacion_de_version_nunca_entra_en_panico(
        del_nucleo in prop::collection::vec(any::<u32>(), 0..64),
        del_plugin in prop::collection::vec(any::<u32>(), 0..64),
    ) {
        let json = format!(
            r#"{{"magic":"SHIELDBK_PLUGIN","handshake_version":1,"core_protocol_versions":{},"control_socket":"/tmp/x.sock","tls":{{"ca_cert_pem":"","server_cert_pem":"","server_key_pem":""}}}}"#,
            serde_json::to_string(&del_nucleo).unwrap()
        );
        let b = Bootstrap::from_line(&json).unwrap();
        let elegida = b.negotiate(&del_plugin);
        // Si hay versión elegida, tiene que estar en las dos listas: negociar
        // no puede inventarse una que ninguno de los dos lados soporta.
        if let Ok(v) = elegida {
            prop_assert!(del_nucleo.contains(&v));
            prop_assert!(del_plugin.contains(&v));
        }
    }

    /// El sobre que el núcleo escribe siempre se puede volver a leer, sea cual
    /// sea el contenido de los campos que vienen de fuera.
    #[test]
    fn el_bootstrap_sobrevive_a_su_propia_ida_y_vuelta(
        socket in ".*",
        ca in ".*",
        cert in ".*",
        key in ".*",
    ) {
        let b = Bootstrap::nuevo(
            vec![1],
            socket.clone(),
            sb_transport::ServerBundle {
                ca_cert_pem: ca,
                server_cert_pem: cert,
                server_key_pem: key,
            },
        );
        let linea = b.to_line().unwrap();
        prop_assert!(!linea.contains('\n'), "el sobre tiene que caber en una línea");
        prop_assert_eq!(Bootstrap::from_line(&linea).unwrap().control_socket, socket);
    }
}

#[test]
fn una_linea_enorme_no_agota_la_memoria() {
    // Un plugin roto podría escribir gigabytes en stdout.
    let enorme = "x".repeat(10 * 1024 * 1024);
    assert!(Ready::from_line(&enorme).is_err());
}

#[test]
fn un_json_profundamente_anidado_no_desborda_la_pila() {
    // El desbordamiento de pila NO es un pánico capturable: aborta el proceso.
    let profundo = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
    assert!(Ready::from_line(&profundo).is_err());
}

#[test]
fn el_magic_correcto_con_el_resto_ausente_se_rechaza() {
    assert!(Ready::from_line(r#"{"magic":"SHIELDBK_PLUGIN"}"#).is_err());
}

#[test]
fn un_bootstrap_profundamente_anidado_no_desborda_la_pila() {
    let profundo = format!(
        "{}{}",
        "{\"a\":".repeat(10_000),
        "1".to_owned() + &"}".repeat(10_000)
    );
    assert!(Bootstrap::from_line(&profundo).is_err());
}
