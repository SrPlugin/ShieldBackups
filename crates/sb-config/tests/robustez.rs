//! Robustez del parser de configuración frente a texto arbitrario.
//!
//! El TOML de configuración lo escribe una persona, pero también puede llegar
//! de un repositorio compartido o de una plantilla generada. Que sea inválido
//! es normal; que tumbe el proceso no lo es.

use proptest::prelude::*;
use sb_config::Config;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Ninguna entrada, por absurda que sea, puede provocar un pánico.
    #[test]
    fn el_parser_de_configuracion_nunca_entra_en_panico(entrada in ".*") {
        let _ = Config::parse(&entrada);
    }

    /// Bytes arbitrarios, incluidos los que no son UTF-8 válido.
    #[test]
    fn bytes_arbitrarios_no_provocan_panico(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let texto = String::from_utf8_lossy(&bytes);
        let _ = Config::parse(&texto);
    }

    /// TOML estructuralmente válido pero con valores extremos en los campos
    /// que el parser sí interpreta.
    #[test]
    fn un_toml_valido_con_valores_extremos_no_provoca_panico(
        nivel in any::<i64>(),
        nombre in ".*",
        plantilla in ".*",
    ) {
        let texto = format!(
            "[defaults]\ncompression_level = {nivel}\n\n[[target]]\nname = {}\nengine = \"e\"\n\
             storage = \"s\"\nrecipient = \"age1x\"\nartifact_template = {}\n",
            toml_str(&nombre),
            toml_str(&plantilla),
        );
        let _ = Config::parse(&texto);
    }

    /// Muchos targets, con nombres que pueden repetirse: el camino que detecta
    /// duplicados también es entrada externa.
    #[test]
    fn muchos_targets_con_nombres_arbitrarios_no_provocan_panico(
        nombres in prop::collection::vec("[a-z]{0,3}", 0..64),
    ) {
        use std::fmt::Write as _;
        let mut texto = String::new();
        for n in &nombres {
            let _ = write!(
                texto,
                "[[target]]\nname = {}\nengine = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\n\n",
                toml_str(n)
            );
        }
        let _ = Config::parse(&texto);
    }

    /// Las tablas opacas de plugin admiten cualquier forma: el núcleo no las
    /// interpreta, así que tiene que tragarse lo que sea sin romperse.
    #[test]
    fn tablas_opacas_arbitrarias_no_provocan_panico(
        clave in "[a-z_]{1,8}",
        valor in ".*",
    ) {
        let texto = format!(
            "[[target]]\nname = \"t\"\nengine = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\n\
             [target.engine_config]\n{clave} = {}\n",
            toml_str(&valor)
        );
        let _ = Config::parse(&texto);
    }
}

/// Escribe `s` como cadena literal de TOML.
///
/// No usa `unwrap`: en un helper libre de un fichero de `tests/` está
/// prohibido, y aquí además sería innecesario —serializar una `String` a TOML
/// no puede fallar, pero decirlo con un `unwrap_or` cuesta lo mismo que
/// afirmarlo—.
fn toml_str(s: &str) -> String {
    toml::to_string(&toml::Value::String(s.to_owned()))
        .map_or_else(|_| "\"\"".to_owned(), |t| t.trim().to_owned())
}

#[test]
fn un_fichero_enorme_no_agota_la_memoria() {
    // Un TOML de diez megas de basura tiene que fallar, no tumbar el proceso.
    let enorme = "x".repeat(10 * 1024 * 1024);
    assert!(Config::parse(&enorme).is_err());
}

#[test]
fn un_toml_profundamente_anidado_no_desborda_la_pila() {
    // El desbordamiento de pila NO es un pánico capturable: aborta el proceso.
    let profundo = format!("a = {}1{}", "[".repeat(10_000), "]".repeat(10_000));
    assert!(Config::parse(&profundo).is_err());
}

#[test]
fn una_configuracion_vacia_se_rechaza_sin_panico() {
    assert!(Config::parse("").is_err());
}
