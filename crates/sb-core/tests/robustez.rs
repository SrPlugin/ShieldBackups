//! Robustez de los parsers del núcleo frente a entradas arbitrarias.
//!
//! Todo lo que se prueba aquí procesa datos que el núcleo no ha escrito: el
//! lockfile del disco, el manifiesto que baja del destino, la plantilla y el
//! nombre de target que salen de la configuración del usuario, y los digests y
//! claves públicas que viajan dentro del manifiesto. Ninguno puede provocar un
//! pánico, y en el caso de [`sb_core::naming::render`] tampoco puede colarse
//! una clave insegura.

use std::fmt::Write as _;

use proptest::prelude::*;
use sb_core::lockfile::Lockfile;
use sb_core::model::Manifest;
use sb_core::naming::{MAX_CLAVE_BYTES, NamingContext, render};
use sb_crypto::{Digest, Recipient};

/// Comprueba las invariantes que hacen segura una clave de artefacto.
///
/// Es exactamente lo que el destino da por hecho: que la clave no sale del
/// directorio de backups, que no inyecta nada en las cabeceras de la petición
/// y que el object storage la va a aceptar.
fn clave_segura(clave: &str) -> Result<(), String> {
    if clave.is_empty() {
        return Err("la clave está vacía".to_owned());
    }
    if clave.starts_with('/') {
        return Err(format!("«{clave}» es absoluta"));
    }
    if clave.contains('\\') {
        return Err(format!("«{clave}» contiene una barra invertida"));
    }
    if let Some(c) = clave
        .chars()
        .find(|c| matches!(*c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}'))
    {
        return Err(format!(
            "«{clave}» contiene el carácter de control U+{:04X}",
            c as u32
        ));
    }
    if clave.len() > MAX_CLAVE_BYTES {
        return Err(format!("«{clave}» ocupa {} bytes", clave.len()));
    }
    for segmento in clave.split('/') {
        if matches!(segmento, ".." | "." | "") {
            return Err(format!("«{clave}» tiene un segmento «{segmento}»"));
        }
    }
    Ok(())
}

/// Contexto con todos los campos arbitrarios: el nombre del target, el motor y
/// el destino salen de la configuración del usuario, así que son entrada
/// externa tanto como la plantilla.
fn contexto_arbitrario() -> impl Strategy<Value = NamingContext> {
    (".*", ".*", ".*", ".*", ".*", ".*", ".*").prop_map(
        |(target, engine, storage, timestamp, year, month, day)| NamingContext {
            target,
            engine,
            storage,
            timestamp,
            year,
            month,
            day,
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    // ---------- lockfile ----------

    /// Ninguna entrada, por absurda que sea, puede provocar un pánico.
    #[test]
    fn el_parser_del_lockfile_nunca_entra_en_panico(entrada in ".*") {
        let _ = Lockfile::from_toml(&entrada);
    }

    /// Bytes arbitrarios, incluidos los que no son UTF-8 válido.
    #[test]
    fn bytes_arbitrarios_no_rompen_el_lockfile(
        bytes in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let texto = String::from_utf8_lossy(&bytes);
        let _ = Lockfile::from_toml(&texto);
    }

    /// TOML con la forma correcta y valores extremos: versiones enormes,
    /// nombres de plugin y hashes arbitrarios.
    #[test]
    fn un_lockfile_valido_con_valores_extremos_no_provoca_panico(
        version in any::<u64>(),
        nombre in "[a-z-]{1,16}",
        sha in ".*",
    ) {
        let texto = format!(
            "version = {version}\n\n[plugins.{nombre}]\nsha256 = {}\n",
            toml_str(&sha)
        );
        let _ = Lockfile::from_toml(&texto);
    }

    // ---------- manifiesto ----------

    #[test]
    fn el_parser_del_manifiesto_nunca_entra_en_panico(entrada in ".*") {
        let _ = Manifest::parse(&entrada);
    }

    #[test]
    fn bytes_arbitrarios_no_rompen_el_manifiesto(
        bytes in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let texto = String::from_utf8_lossy(&bytes);
        let _ = Manifest::parse(&texto);
    }

    /// JSON con la forma exacta del manifiesto y valores extremos: tamaños al
    /// borde de `u64`, versiones futuras y cadenas larguísimas.
    #[test]
    fn un_manifiesto_valido_con_valores_extremos_no_provoca_panico(
        version in any::<u32>(),
        plaintext in any::<u64>(),
        ciphertext in any::<u64>(),
        nivel in any::<i32>(),
        largo in 0_usize..8192,
        texto_libre in ".*",
    ) {
        let cadena = "á".repeat(largo);
        let json = serde_json::json!({
            "version": version,
            "target": cadena,
            "engine": {
                "plugin": texto_libre,
                "plugin_version": cadena,
                "server_version": cadena,
            },
            "created_at": texto_libre,
            "artifact_key": cadena,
            "plaintext_bytes": plaintext,
            "ciphertext_bytes": ciphertext,
            "plaintext_sha256": cadena,
            "ciphertext_sha256": texto_libre,
            "compression": { "algorithm": texto_libre, "level": nivel },
            "encryption": { "algorithm": texto_libre, "recipient": texto_libre },
        })
        .to_string();
        // Si se acepta, derivar la clave del manifiesto tampoco puede romper.
        if let Ok(m) = Manifest::parse(&json) {
            let _ = m.manifest_key();
        }
    }

    /// Arrays profundos —pero dentro del límite de recursión de serde_json—
    /// en el sitio donde el manifiesto espera un objeto.
    #[test]
    fn un_manifiesto_con_arrays_profundos_no_provoca_panico(profundidad in 0_usize..120) {
        let json = format!("{}1{}", "[".repeat(profundidad), "]".repeat(profundidad));
        prop_assert!(Manifest::parse(&json).is_err());
    }

    // ---------- naming ----------

    /// La plantilla la escribe el usuario: puede ser cualquier cosa.
    #[test]
    fn el_render_nunca_entra_en_panico_con_plantillas_arbitrarias(plantilla in ".*") {
        let ctx = NamingContext::new("t", "e", "s", 0);
        let _ = render(&plantilla, &ctx);
    }

    /// Plantillas sesgadas hacia las llaves, que es donde está la lógica de
    /// troceado: `.*` casi nunca genera un `{` seguido de un `}`.
    #[test]
    fn el_render_aguanta_plantillas_llenas_de_llaves(
        plantilla in "[{}a-z/.\\\\{}0-9]{0,64}",
    ) {
        let ctx = NamingContext::new("t", "e", "s", 0);
        let _ = render(&plantilla, &ctx);
    }

    /// El contexto también es entrada externa: el nombre del target sale de la
    /// configuración del usuario.
    #[test]
    fn el_render_nunca_entra_en_panico_con_contextos_arbitrarios(
        plantilla in ".*",
        ctx in contexto_arbitrario(),
    ) {
        let _ = render(&plantilla, &ctx);
    }

    /// **La propiedad que de verdad importa**: si `render` devuelve `Ok`, la
    /// clave cumple las invariantes de seguridad. No basta con que no entre en
    /// pánico; hace falta que la validación no se pueda saltar con ninguna
    /// combinación de plantilla y contexto.
    #[test]
    fn una_clave_aceptada_siempre_es_segura(
        plantilla in ".*",
        ctx in contexto_arbitrario(),
    ) {
        if let Ok(clave) = render(&plantilla, &ctx)
            && let Err(motivo) = clave_segura(&clave)
        {
            prop_assert!(false, "render aceptó una clave insegura: {motivo}");
        }
    }

    /// La misma propiedad, con plantillas y contextos sesgados hacia los
    /// caracteres peligrosos: barras, puntos, llaves, control y bytes nulos.
    /// Con `.*` la probabilidad de generar `{target}` es prácticamente nula.
    #[test]
    fn una_clave_aceptada_es_segura_tambien_con_entradas_hostiles(
        plantilla in prop::collection::vec(
            prop_oneof![
                Just("{target}".to_owned()),
                Just("{engine}".to_owned()),
                Just("{storage}".to_owned()),
                Just("{timestamp}".to_owned()),
                Just("{yyyy}".to_owned()),
                Just("/".to_owned()),
                Just("..".to_owned()),
                Just(".".to_owned()),
                Just("\\".to_owned()),
                Just("\0".to_owned()),
                Just("\n".to_owned()),
                Just("a".to_owned()),
            ],
            0..24,
        ).prop_map(|partes| partes.concat()),
        target in prop_oneof![
            Just("..".to_owned()),
            Just("/".to_owned()),
            Just(".".to_owned()),
            Just(String::new()),
            Just("a/../..".to_owned()),
            Just("x\r\nX-Inyectada: si".to_owned()),
            Just("ñ".repeat(600)),
            Just("a".repeat(2000)),
            "[a-z./\\\\]{0,8}",
        ],
    ) {
        let mut ctx = NamingContext::new(&target, "e", "s", 0);
        ctx.storage = target.clone();
        if let Ok(clave) = render(&plantilla, &ctx)
            && let Err(motivo) = clave_segura(&clave)
        {
            prop_assert!(false, "render aceptó una clave insegura: {motivo}");
        }
    }

    /// El constructor del contexto recibe la marca de tiempo del reloj del
    /// sistema: un reloj roto no puede tumbar un backup.
    #[test]
    fn el_contexto_se_construye_con_cualquier_marca_de_tiempo(
        epoch in any::<i64>(),
        target in ".*",
    ) {
        let ctx = NamingContext::new(&target, "e", "s", epoch);
        prop_assert!(!ctx.timestamp.is_empty());
    }

    // ---------- cripto ----------

    /// `Digest::from_hex` recibe cadenas que vienen del manifiesto, es decir
    /// del destino remoto.
    #[test]
    fn el_parser_de_digest_nunca_entra_en_panico(entrada in ".*") {
        let _ = Digest::from_hex(&entrada);
    }

    /// Cadenas de exactamente 64 **bytes** compuestas de caracteres
    /// multibyte: la comprobación de longitud es en bytes y el troceado en
    /// pares también, así que un carácter de dos o tres bytes cae justo entre
    /// medias.
    #[test]
    fn un_digest_de_64_bytes_no_ascii_no_entra_en_panico(
        relleno in prop::collection::vec(
            prop_oneof![Just('a'), Just('ñ'), Just('€'), Just('𝄞'), Just('f'), Just('0')],
            0..64,
        ),
    ) {
        let mut s: String = relleno.into_iter().collect();
        while s.len() > 64 {
            s.pop();
        }
        while s.len() < 64 {
            s.push('0');
        }
        prop_assert_eq!(s.len(), 64);
        let _ = Digest::from_hex(&s);
    }

    /// Un digest hexadecimal bien formado siempre da la vuelta completa.
    #[test]
    fn un_digest_hexadecimal_valido_da_la_vuelta(bytes in prop::array::uniform32(any::<u8>())) {
        let hex = bytes.iter().fold(String::with_capacity(64), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        });
        let d = Digest::from_hex(&hex).unwrap();
        prop_assert_eq!(d.to_hex(), hex);
    }

    /// La clave pública age viene de la configuración y del manifiesto.
    #[test]
    fn el_parser_de_recipient_nunca_entra_en_panico(entrada in ".*") {
        let _ = Recipient::parse(&entrada);
    }

    /// Sesgado hacia lo que *parece* una clave age: el prefijo correcto con un
    /// cuerpo bech32 arbitrario ejercita el decodificador de verdad.
    #[test]
    fn un_recipient_con_pinta_de_age_no_entra_en_panico(cuerpo in "[a-z0-9]{0,80}") {
        let _ = Recipient::parse(&format!("age1{cuerpo}"));
    }
}

/// Escribe `s` como cadena literal de TOML.
///
/// No usa `unwrap`: en un helper libre de un fichero de `tests/` está
/// prohibido por la configuración de clippy del workspace.
fn toml_str(s: &str) -> String {
    toml::to_string(&toml::Value::String(s.to_owned()))
        .map_or_else(|_| "\"\"".to_owned(), |t| t.trim().to_owned())
}

#[test]
fn un_lockfile_enorme_no_agota_la_memoria() {
    let enorme = "x".repeat(10 * 1024 * 1024);
    assert!(Lockfile::from_toml(&enorme).is_err());
}

#[test]
fn un_manifiesto_enorme_no_agota_la_memoria() {
    let enorme = "x".repeat(10 * 1024 * 1024);
    assert!(Manifest::parse(&enorme).is_err());
}

#[test]
fn un_manifiesto_profundamente_anidado_no_desborda_la_pila() {
    // El desbordamiento de pila NO es un pánico capturable: aborta el proceso.
    let profundo = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
    assert!(Manifest::parse(&profundo).is_err());
}

#[test]
fn un_lockfile_profundamente_anidado_no_desborda_la_pila() {
    let profundo = format!("a = {}1{}", "[".repeat(10_000), "]".repeat(10_000));
    assert!(Lockfile::from_toml(&profundo).is_err());
}

#[test]
fn una_plantilla_enorme_no_agota_la_memoria() {
    // La clave resultante pasaría del límite de S3 mucho antes de importar.
    let enorme = "x".repeat(10 * 1024 * 1024);
    let ctx = NamingContext::new("t", "e", "s", 0);
    assert!(render(&enorme, &ctx).is_err());
}

#[test]
fn muchas_llaves_sin_cerrar_no_provocan_un_bucle_infinito() {
    // Una llave sin cerrar es texto literal: el bucle de `render` tiene que
    // seguir avanzando o no terminaría nunca.
    let ctx = NamingContext::new("t", "e", "s", 0);
    let plantilla = "{".repeat(100_000);
    assert!(
        render(&plantilla, &ctx).is_err(),
        "supera el límite de bytes"
    );
    assert_eq!(render("{{{{", &ctx).unwrap(), "{{{{");
}

#[test]
fn un_digest_de_64_bytes_con_caracteres_multibyte_no_entra_en_panico() {
    // 21 signos de euro (3 bytes cada uno) más una «a»: exactamente 64 bytes,
    // pero el troceado en pares cae en mitad de un carácter.
    let s = format!("{}a", "€".repeat(21));
    assert_eq!(s.len(), 64, "la trampa es que mide 64 bytes");
    assert!(Digest::from_hex(&s).is_err());
}
