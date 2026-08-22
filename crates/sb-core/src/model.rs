use serde::{Deserialize, Serialize};

/// Version of the manifest format. It is bumped only on changes that an older
/// reader could not safely interpret.
pub const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("the manifest is not valid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("manifest of version {found}, this version of shieldbk supports up to {supported}")]
    UnsupportedVersion { found: u32, supported: u32 },
}

/// Which source produced the artifact, and at which versions.
///
/// The field names are the ones written into every artifact's manifest. They
/// were `engine` / `server_version` until 0.1.0 and were renamed **without a
/// `serde(alias)` fallback**: no artifact of the old shape exists anywhere, so
/// accepting a name that was never written durably would be permanent dead
/// weight, and [`MANIFEST_VERSION`] stays at 1 for the same reason — bumping it
/// would advertise a migration nobody has to make.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceInfo {
    /// Name of the source plugin that produced the dump.
    pub plugin: String,
    /// Version of that plugin binary.
    pub plugin_version: String,
    /// Version of whatever the plugin sits in front of —the database server, the
    /// container runtime— as reported in its preflight. Empty when the source
    /// has no such notion.
    pub source_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionInfo {
    pub algorithm: String,
    pub level: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionInfo {
    pub algorithm: String,
    /// The age **public** key. It is not a secret: knowing who an artifact is
    /// addressed to does not help decrypt it.
    pub recipient: String,
}

/// Full description of an artifact, stored next to it.
///
/// `verify` and `restore` read this instead of inferring anything from the file
/// name: a name can change, a manifest is authoritative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub target: String,
    pub source: SourceInfo,
    pub created_at: String,
    pub artifact_key: String,
    pub plaintext_bytes: u64,
    pub ciphertext_bytes: u64,
    pub plaintext_sha256: String,
    pub ciphertext_sha256: String,
    pub compression: CompressionInfo,
    pub encryption: EncryptionInfo,
}

/// Key of the manifest that accompanies the artifact stored under
/// `artifact_key`.
///
/// It is a free function and not just a method because `verify` needs this key
/// **before** it has the manifest: the first thing it does is download it. If
/// the rule lived only inside [`Manifest`], the operation would have to repeat
/// the `format!` and the day the suffix changed there would be two truths.
#[must_use]
pub fn manifest_key_for(artifact_key: &str) -> String {
    format!("{artifact_key}.manifest.json")
}

impl Manifest {
    /// Key of the manifest in the storage, derived from the artifact's own.
    #[must_use]
    pub fn manifest_key(&self) -> String {
        manifest_key_for(&self.artifact_key)
    }

    /// # Errors
    /// Returns an error if the JSON is invalid or if the manifest comes from a
    /// newer version of shieldbk than this one.
    pub fn parse(json: &str) -> Result<Self, ManifestError> {
        let m: Self = serde_json::from_str(json)?;
        if m.version > MANIFEST_VERSION {
            return Err(ManifestError::UnsupportedVersion {
                found: m.version,
                supported: MANIFEST_VERSION,
            });
        }
        Ok(m)
    }

    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, ManifestError> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> Manifest {
        Manifest {
            version: MANIFEST_VERSION,
            target: "production".into(),
            source: SourceInfo {
                plugin: "postgres".into(),
                plugin_version: "0.1.0".into(),
                source_version: "16.2".into(),
            },
            created_at: "2026-08-21T10:00:00Z".into(),
            artifact_key: "production/2026/08/21/production-20260821T100000Z-postgres.dump.zst.age"
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
    fn round_trip_through_json() {
        let m = sample_manifest();
        let json = m.to_json().unwrap();
        let back = Manifest::parse(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn the_manifest_key_derives_from_the_artifact_key() {
        let m = sample_manifest();
        assert_eq!(
            m.manifest_key(),
            "production/2026/08/21/production-20260821T100000Z-postgres.dump.zst.age.manifest.json"
        );
    }

    #[test]
    fn a_manifest_from_a_future_version_is_rejected() {
        // An old shieldbk cannot safely interpret a manifest written by a newer
        // one: better to refuse than to restore badly.
        let mut m = sample_manifest();
        m.version = MANIFEST_VERSION + 1;
        let json = serde_json::to_string(&m).unwrap();
        let err = Manifest::parse(&json).unwrap_err();
        assert!(matches!(err, ManifestError::UnsupportedVersion { .. }));
    }

    #[test]
    fn the_version_error_says_both_versions() {
        let mut m = sample_manifest();
        m.version = 99;
        let text = Manifest::parse(&serde_json::to_string(&m).unwrap())
            .unwrap_err()
            .to_string();
        assert!(text.contains("99"), "it must say which version it found");
        assert!(
            text.contains(&MANIFEST_VERSION.to_string()),
            "and which one it supports"
        );
    }

    #[test]
    fn a_manifest_of_the_current_version_is_accepted() {
        let json = serde_json::to_string(&sample_manifest()).unwrap();
        assert!(Manifest::parse(&json).is_ok());
    }

    #[test]
    fn a_corrupt_json_gives_a_clear_error() {
        assert!(matches!(
            Manifest::parse("{ this is not json").unwrap_err(),
            ManifestError::InvalidJson(_)
        ));
    }

    #[test]
    fn a_mandatory_field_is_missing() {
        // A manifest missing the digest is useless for verifying anything.
        let json = r#"{"version":1,"target":"t"}"#;
        assert!(matches!(
            Manifest::parse(json).unwrap_err(),
            ManifestError::InvalidJson(_)
        ));
    }

    #[test]
    fn the_generated_json_is_readable_by_a_human() {
        // The manifest is read by hand when something goes wrong at three in the
        // morning. It must be indented, not on a single line.
        let json = sample_manifest().to_json().unwrap();
        assert!(json.contains('\n'), "it must be indented");
        assert!(
            json.contains("\"ciphertext_sha256\""),
            "the field names are the struct's own"
        );
    }
}
