use serde::{Deserialize, Serialize};

/// Versión del formato de manifiesto. Se incrementa solo ante cambios que un
/// lector antiguo no pueda interpretar con seguridad.
pub const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("el manifiesto no es JSON válido: {0}")]
    JsonInvalido(#[from] serde_json::Error),
    #[error(
        "manifiesto de versión {encontrada}, esta versión de shieldbk soporta hasta la {soportada}"
    )]
    VersionNoSoportada { encontrada: u32, soportada: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineInfo {
    pub plugin: String,
    pub plugin_version: String,
    pub server_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionInfo {
    pub algorithm: String,
    pub level: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionInfo {
    pub algorithm: String,
    /// Clave **pública** age. No es un secreto: saber a quién va dirigido un
    /// artefacto no ayuda a descifrarlo.
    pub recipient: String,
}

/// Descripción completa de un artefacto, guardada junto a él.
///
/// `verify` y `restore` leen esto en vez de deducir nada del nombre del
/// archivo: un nombre puede cambiar, un manifiesto es autoritativo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub target: String,
    pub engine: EngineInfo,
    pub created_at: String,
    pub artifact_key: String,
    pub plaintext_bytes: u64,
    pub ciphertext_bytes: u64,
    pub plaintext_sha256: String,
    pub ciphertext_sha256: String,
    pub compression: CompressionInfo,
    pub encryption: EncryptionInfo,
}

impl Manifest {
    /// Clave del manifiesto en el destino, derivada de la del artefacto.
    #[must_use]
    pub fn manifest_key(&self) -> String {
        format!("{}.manifest.json", self.artifact_key)
    }

    /// # Errors
    /// Devuelve error si el JSON es inválido o si el manifiesto viene de una
    /// versión de shieldbk más nueva que esta.
    pub fn parse(json: &str) -> Result<Self, ManifestError> {
        let m: Self = serde_json::from_str(json)?;
        if m.version > MANIFEST_VERSION {
            return Err(ManifestError::VersionNoSoportada {
                encontrada: m.version,
                soportada: MANIFEST_VERSION,
            });
        }
        Ok(m)
    }

    /// # Errors
    /// Devuelve error si la serialización falla.
    pub fn to_json(&self) -> Result<String, ManifestError> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifiesto_de_ejemplo() -> Manifest {
        Manifest {
            version: MANIFEST_VERSION,
            target: "produccion".into(),
            engine: EngineInfo {
                plugin: "postgres".into(),
                plugin_version: "0.1.0".into(),
                server_version: "16.2".into(),
            },
            created_at: "2026-08-21T10:00:00Z".into(),
            artifact_key: "produccion/2026/08/21/produccion-20260821T100000Z-postgres.dump.zst.age"
                .into(),
            plaintext_bytes: 1_234,
            ciphertext_bytes: 567,
            plaintext_sha256: "a".repeat(64),
            ciphertext_sha256: "b".repeat(64),
            compression: CompressionInfo {
                algorithm: "zstd".into(),
                level: 3,
            },
            encryption: EncryptionInfo {
                algorithm: "age".into(),
                recipient: "age1qqq".into(),
            },
        }
    }

    #[test]
    fn ida_y_vuelta_por_json() {
        let m = manifiesto_de_ejemplo();
        let json = m.to_json().unwrap();
        let vuelta = Manifest::parse(&json).unwrap();
        assert_eq!(m, vuelta);
    }

    #[test]
    fn la_clave_del_manifiesto_deriva_de_la_del_artefacto() {
        let m = manifiesto_de_ejemplo();
        assert_eq!(
            m.manifest_key(),
            "produccion/2026/08/21/produccion-20260821T100000Z-postgres.dump.zst.age.manifest.json"
        );
    }

    #[test]
    fn se_rechaza_un_manifiesto_de_version_futura() {
        // Un shieldbk antiguo no puede interpretar con seguridad un manifiesto
        // escrito por uno más nuevo: mejor negarse que restaurar mal.
        let mut m = manifiesto_de_ejemplo();
        m.version = MANIFEST_VERSION + 1;
        let json = serde_json::to_string(&m).unwrap();
        let err = Manifest::parse(&json).unwrap_err();
        assert!(matches!(err, ManifestError::VersionNoSoportada { .. }));
    }

    #[test]
    fn el_error_de_version_dice_ambas_versiones() {
        let mut m = manifiesto_de_ejemplo();
        m.version = 99;
        let texto = Manifest::parse(&serde_json::to_string(&m).unwrap())
            .unwrap_err()
            .to_string();
        assert!(texto.contains("99"), "debe decir qué versión encontró");
        assert!(
            texto.contains(&MANIFEST_VERSION.to_string()),
            "y cuál soporta"
        );
    }

    #[test]
    fn se_acepta_un_manifiesto_de_la_version_actual() {
        let json = serde_json::to_string(&manifiesto_de_ejemplo()).unwrap();
        assert!(Manifest::parse(&json).is_ok());
    }

    #[test]
    fn un_json_corrupto_da_un_error_claro() {
        assert!(matches!(
            Manifest::parse("{ esto no es json").unwrap_err(),
            ManifestError::JsonInvalido(_)
        ));
    }

    #[test]
    fn falta_un_campo_obligatorio() {
        // Un manifiesto al que le falta el digest no sirve para verificar nada.
        let json = r#"{"version":1,"target":"t"}"#;
        assert!(matches!(
            Manifest::parse(json).unwrap_err(),
            ManifestError::JsonInvalido(_)
        ));
    }

    #[test]
    fn el_json_generado_es_legible_por_una_persona() {
        // El manifiesto se lee a mano cuando algo va mal a las tres de la
        // mañana. Debe estar indentado, no en una sola línea.
        let json = manifiesto_de_ejemplo().to_json().unwrap();
        assert!(json.contains('\n'), "debe ir indentado");
        assert!(
            json.contains("\"ciphertext_sha256\""),
            "los nombres de campo son los del struct"
        );
    }
}
