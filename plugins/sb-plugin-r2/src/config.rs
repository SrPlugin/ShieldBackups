//! The R2 storage target's configuration schema and the validated
//! configuration.
//!
//! Everything the user can tune about the plugin lives here, and here is where
//! whatever will not work gets rejected. Validation is deliberately **early**: a
//! `part_size_mb` that is not enough for the largest object expected to be
//! uploaded is a failure that, without this check, would show up three hours
//! into the upload and with the parts already billed.

use std::collections::HashMap;

use sb_plugin_sdk::sb_proto::{Field, FieldType, Value, value::Kind};
use sb_plugin_sdk::tonic::Status;

pub const FIELD_ACCOUNT_ID: &str = "account_id";
pub const FIELD_BUCKET: &str = "bucket";
pub const FIELD_ACCESS_KEY_ID: &str = "access_key_id";
pub const FIELD_SECRET_ACCESS_KEY: &str = "secret_access_key";
pub const FIELD_ENDPOINT: &str = "endpoint";
pub const FIELD_PREFIX: &str = "prefix";
pub const FIELD_PART_SIZE_MB: &str = "part_size_mb";
pub const FIELD_CONCURRENCY: &str = "concurrency";
pub const FIELD_MAX_OBJECT_GB: &str = "max_object_gb";
pub const FIELD_STORAGE_CLASS: &str = "storage_class";

const MIB: u64 = 1024 * 1024;
/// The gigabyte in `max_object_gb` is decimal, like the one Cloudflare and AWS
/// use for billing and for documenting their limits. Mixing it with the
/// mebibyte of `part_size_mb` jars, but each unit is the one used by whoever
/// publishes it.
const GB: u64 = 1_000_000_000;

/// Smallest part size S3's multipart protocol accepts, in MiB. The last part
/// may be smaller; no other one may.
pub const MIN_PART_MB: u64 = 5;
/// Largest part size S3's multipart protocol accepts, in MiB.
pub const MAX_PART_MB: u64 = 5 * 1024;
/// Parts a single multipart upload admits. It is a protocol limit, not a choice
/// of ours: together with it, `part_size_mb` fixes the largest object that can
/// be uploaded.
pub const MAX_PARTS: u64 = 10_000;

const DEFAULT_PART_SIZE_MB: i64 = 64;
const DEFAULT_CONCURRENCY: i64 = 4;
const DEFAULT_MAX_OBJECT_GB: i64 = 640;
const MAX_CONCURRENCY: i64 = 256;
/// Object limit S3 -- and R2 -- admits: 5 TiB, rounded to decimal GB.
const MAX_OBJECT_GB_LIMIT: i64 = 5_500;

/// Domain under which Cloudflare publishes each account's S3 endpoint.
const R2_DOMAIN: &str = "r2.cloudflarestorage.com";

/// What can go wrong when reading the configuration.
///
/// No variant carries the value of a secret field inside: an error ends up in a
/// log, and a log with a key in it is a leak.
#[derive(Debug, thiserror::Error)]
pub enum R2ConfigError {
    #[error("the required field `{field}` is missing")]
    MissingField { field: &'static str },
    #[error("the field `{field}` must be {expected}")]
    WrongType {
        field: &'static str,
        expected: &'static str,
    },
    #[error(
        "`{}` is {mb} MiB and the minimum of S3's multipart protocol is {MIN_PART_MB} MiB: every part except the last must reach it",
        FIELD_PART_SIZE_MB
    )]
    PartTooSmall { mb: i64 },
    #[error(
        "with {mb} MiB parts and a cap of {MAX_PARTS} parts only {ceiling_gb} GB are reachable, below the {max_object_gb} GB of `{}`: raise `{}` to at least {minimum_mb} MiB",
        FIELD_MAX_OBJECT_GB,
        FIELD_PART_SIZE_MB
    )]
    PartTooSmallForMaxObject {
        mb: i64,
        max_object_gb: i64,
        ceiling_gb: u64,
        minimum_mb: u64,
    },
    #[error("the field `{field}` must be between {min} and {max}, and it is {value}")]
    OutOfRange {
        field: &'static str,
        value: i64,
        min: i64,
        max: i64,
    },
    #[error(
        "`{}` only accepts `{}` or `{}`",
        FIELD_STORAGE_CLASS,
        R2StorageClass::STANDARD,
        R2StorageClass::INFREQUENT_ACCESS
    )]
    UnknownStorageClass,
    #[error(
        "`{}` must be an absolute URL with an `http://` or `https://` scheme",
        FIELD_ENDPOINT
    )]
    InvalidEndpoint,
}

/// A configuration error is always the fault of what the core sent, so it
/// travels as `invalid_argument` and not as an internal failure.
impl From<R2ConfigError> for Status {
    fn from(e: R2ConfigError) -> Self {
        Self::invalid_argument(e.to_string())
    }
}

/// The two storage classes R2 offers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2StorageClass {
    /// Frequent access. This is the default one.
    Standard,
    /// Cheaper to keep and dearer to read; for long retentions.
    InfrequentAccess,
}

impl R2StorageClass {
    pub(crate) const STANDARD: &'static str = "Standard";
    pub(crate) const INFREQUENT_ACCESS: &'static str = "InfrequentAccess";

    /// The name exactly as R2's API expects it. It is what gets shown in the
    /// logs and in the preflight, not necessarily what gets sent.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => Self::STANDARD,
            Self::InfrequentAccess => Self::INFREQUENT_ACCESS,
        }
    }

    /// The value of the `x-amz-storage-class` header, or `None` if it must not
    /// be sent.
    ///
    /// The standard class is **not sent**, and this is not a byte-saving
    /// measure. `Standard` is the name R2 gives its default class, but the
    /// header belongs to S3 and there that name does not exist: an
    /// S3-compatible server that is not R2 answers `400 InvalidStorageClass`
    /// and the whole upload fails. The integration tests against `MinIO`
    /// uncovered it, which is exactly the scenario the `endpoint` field exists
    /// for.
    ///
    /// Omitting it leaves the object in the bucket's default class, which in R2
    /// is `Standard` unless the operator set another one on the bucket itself.
    /// That is the only case where asking for `Standard` here and not sending
    /// it differ: a bucket whose default class is `InfrequentAccess` will also
    /// store there whatever this target writes. That is a decision taken on the
    /// bucket, not something this plugin can contradict without breaking every
    /// other server.
    #[must_use]
    pub fn header(self) -> Option<&'static str> {
        match self {
            Self::Standard => None,
            Self::InfrequentAccess => Some(Self::INFREQUENT_ACCESS),
        }
    }

    fn parse(value: &str) -> Result<Self, R2ConfigError> {
        // Case-insensitive: the user types this by hand into a TOML and
        // `standard` should not cost them a failed run.
        if value.eq_ignore_ascii_case(Self::STANDARD) {
            Ok(Self::Standard)
        } else if value.eq_ignore_ascii_case(Self::INFREQUENT_ACCESS) {
            Ok(Self::InfrequentAccess)
        } else {
            Err(R2ConfigError::UnknownStorageClass)
        }
    }
}

/// The fields the plugin accepts, exactly as `Schema` publishes them.
///
/// Both keys are marked as secret: the core refuses to accept a secret field as
/// a literal in the user's TOML and requires it to come from a credential
/// store, so marking them is what keeps them out of a versioned configuration
/// file.
#[must_use]
pub fn schema() -> Vec<Field> {
    vec![
        text(
            FIELD_ACCOUNT_ID,
            true,
            false,
            "Cloudflare account ID; the R2 endpoint is derived from it",
            String::new(),
        ),
        text(
            FIELD_BUCKET,
            true,
            false,
            "R2 bucket where the artifacts are stored",
            String::new(),
        ),
        text(
            FIELD_ACCESS_KEY_ID,
            true,
            true,
            "Access key of the R2 token",
            String::new(),
        ),
        text(
            FIELD_SECRET_ACCESS_KEY,
            true,
            true,
            "Secret key of the R2 token",
            String::new(),
        ),
        text(
            FIELD_ENDPOINT,
            false,
            false,
            "Explicit endpoint; overrides the one derived from `account_id`. For pointing at a local MinIO in tests",
            String::new(),
        ),
        text(
            FIELD_PREFIX,
            false,
            false,
            "Common prefix of every key inside the bucket, with no trailing slash",
            String::new(),
        ),
        integer(
            FIELD_PART_SIZE_MB,
            "Size in MiB of each part of the multipart upload; S3's minimum is 5",
            DEFAULT_PART_SIZE_MB,
        ),
        integer(
            FIELD_CONCURRENCY,
            "Parts uploaded at the same time",
            DEFAULT_CONCURRENCY,
        ),
        integer(
            FIELD_MAX_OBJECT_GB,
            "Largest expected artifact size in decimal GB; validates that `part_size_mb` is enough for it",
            DEFAULT_MAX_OBJECT_GB,
        ),
        text(
            FIELD_STORAGE_CLASS,
            false,
            false,
            "Storage class: `Standard` or `InfrequentAccess`",
            R2StorageClass::STANDARD.to_string(),
        ),
    ]
}

fn text(
    name: &str,
    required: bool,
    secret: bool,
    description: &str,
    default_value: String,
) -> Field {
    Field {
        name: name.into(),
        r#type: FieldType::String as i32,
        required,
        secret,
        description: description.into(),
        default_value,
    }
}

fn integer(name: &str, description: &str, default_value: i64) -> Field {
    Field {
        name: name.into(),
        r#type: FieldType::Int as i32,
        required: false,
        secret: false,
        description: description.into(),
        default_value: default_value.to_string(),
    }
}

/// The storage target's configuration, already validated. It only exists if
/// `Configure` was accepted.
///
/// The credentials are kept private and only come out through
/// [`R2Config::access_key_id`] and [`R2Config::secret_access_key`], which the
/// client construction uses. `Debug` is written by hand so they do not come out
/// that way.
#[derive(Clone)]
pub struct R2Config {
    pub account_id: String,
    pub bucket: String,
    access_key_id: String,
    secret_access_key: String,
    /// Explicit endpoint. `None` means "derive it from `account_id`".
    endpoint: Option<String>,
    /// Already normalised prefix: no stray slashes at the edges.
    prefix: String,
    /// Size of each multipart part, in bytes.
    pub part_size: usize,
    /// Parts uploaded at the same time.
    pub concurrency: usize,
    /// Storage class each object is created with.
    pub storage_class: R2StorageClass,
}

impl R2Config {
    /// Validates the `ConfigureRequest` map and returns the configuration.
    ///
    /// # Errors
    ///
    /// [`R2ConfigError`] if a required field is missing, if any of them has a
    /// type that does not belong to it, or if the part size is unusable.
    pub fn from_values(values: &HashMap<String, Value>) -> Result<Self, R2ConfigError> {
        let account_id = required_string(values, FIELD_ACCOUNT_ID)?;
        let bucket = required_string(values, FIELD_BUCKET)?;
        let access_key_id = required_string(values, FIELD_ACCESS_KEY_ID)?;
        let secret_access_key = required_string(values, FIELD_SECRET_ACCESS_KEY)?;

        let endpoint = match optional_string(values, FIELD_ENDPOINT)? {
            Some(e) => Some(validated_endpoint(e)?),
            None => None,
        };

        // A prefix is a key prefix, not a path: the slashes at the edges are
        // noise and are stripped exactly once, here, so that `key` does not
        // have to decide anything.
        let prefix = optional_string(values, FIELD_PREFIX)?
            .unwrap_or_default()
            .trim_matches('/')
            .to_string();

        let part_size_mb =
            optional_int(values, FIELD_PART_SIZE_MB)?.unwrap_or(DEFAULT_PART_SIZE_MB);
        let max_object_gb =
            optional_int(values, FIELD_MAX_OBJECT_GB)?.unwrap_or(DEFAULT_MAX_OBJECT_GB);
        let concurrency = optional_int(values, FIELD_CONCURRENCY)?.unwrap_or(DEFAULT_CONCURRENCY);

        let part_size = part_size_in_bytes(part_size_mb, max_object_gb)?;
        let concurrency = in_range(FIELD_CONCURRENCY, concurrency, 1, MAX_CONCURRENCY)?;

        let storage_class = match optional_string(values, FIELD_STORAGE_CLASS)? {
            Some(c) => R2StorageClass::parse(c)?,
            None => R2StorageClass::Standard,
        };

        Ok(Self {
            account_id: account_id.to_string(),
            bucket: bucket.to_string(),
            access_key_id: access_key_id.to_string(),
            secret_access_key: secret_access_key.to_string(),
            endpoint,
            prefix,
            part_size,
            concurrency: usize::try_from(concurrency).unwrap_or(1),
            storage_class,
        })
    }

    /// The endpoint requests are signed against and sent to.
    ///
    /// R2 does not publish one endpoint per bucket but one per account, so the
    /// normal case is deriving it; the explicit one exists to point at a
    /// `MinIO` in tests.
    #[must_use]
    pub fn endpoint(&self) -> String {
        match &self.endpoint {
            Some(e) => e.clone(),
            None => format!("https://{}.{R2_DOMAIN}", self.account_id),
        }
    }

    /// The full key inside the bucket for one of the core's artifacts.
    ///
    /// Joins with a slash instead of concatenating. Concatenating would turn
    /// the key `..foo` -- legitimate, because `..` is only dangerous as a whole
    /// segment -- into a sibling of the backup directory instead of something
    /// inside it.
    #[must_use]
    pub fn key(&self, key: &str) -> String {
        let key = key.trim_start_matches('/');
        if self.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}/{key}", self.prefix)
        }
    }

    /// The already normalised prefix, with no slashes at the edges.
    ///
    /// `List` needs it to make the return trip with
    /// [`crate::keys::without_prefix`]: what R2 returns comes with the prefix
    /// attached and the core never wrote it.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    #[must_use]
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    #[must_use]
    pub fn secret_access_key(&self) -> &str {
        &self.secret_access_key
    }
}

/// Hand-written `Debug`: both keys come out redacted.
///
/// Deriving it would make any `tracing::debug!(?config)` -- or the `Debug` of a
/// struct containing it -- dump the credentials into the log.
impl std::fmt::Debug for R2Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("R2Config")
            .field("account_id", &self.account_id)
            .field("bucket", &self.bucket)
            .field("access_key_id", &"<redacted>")
            .field("secret_access_key", &"<redacted>")
            .field("endpoint", &self.endpoint())
            .field("prefix", &self.prefix)
            .field("part_size", &self.part_size)
            .field("concurrency", &self.concurrency)
            .field("storage_class", &self.storage_class)
            .finish()
    }
}

/// Validates `part_size_mb` against the protocol and against the largest object
/// expected to be uploaded, and returns it in bytes.
fn part_size_in_bytes(part_size_mb: i64, max_object_gb: i64) -> Result<usize, R2ConfigError> {
    if part_size_mb < i64::try_from(MIN_PART_MB).unwrap_or(i64::MAX) {
        return Err(R2ConfigError::PartTooSmall { mb: part_size_mb });
    }
    let part_size_mb = in_range(
        FIELD_PART_SIZE_MB,
        part_size_mb,
        i64::try_from(MIN_PART_MB).unwrap_or(i64::MAX),
        i64::try_from(MAX_PART_MB).unwrap_or(i64::MAX),
    )?;
    let max_object_gb = in_range(FIELD_MAX_OBJECT_GB, max_object_gb, 1, MAX_OBJECT_GB_LIMIT)?;

    // Both fit in u64 after going through `in_range`, which already ruled out
    // negatives.
    let bytes_per_part = u64::try_from(part_size_mb).unwrap_or(MIN_PART_MB) * MIB;
    let largest_object = u64::try_from(max_object_gb).unwrap_or(1) * GB;
    let ceiling = bytes_per_part * MAX_PARTS;
    if ceiling < largest_object {
        return Err(R2ConfigError::PartTooSmallForMaxObject {
            mb: part_size_mb,
            max_object_gb,
            ceiling_gb: ceiling / GB,
            // Rounded up: the part has to reach it, not get close.
            minimum_mb: largest_object.div_ceil(MAX_PARTS).div_ceil(MIB),
        });
    }
    usize::try_from(bytes_per_part).map_err(|_| R2ConfigError::OutOfRange {
        field: FIELD_PART_SIZE_MB,
        value: part_size_mb,
        min: i64::try_from(MIN_PART_MB).unwrap_or(i64::MAX),
        max: i64::try_from(MAX_PART_MB).unwrap_or(i64::MAX),
    })
}

fn in_range(field: &'static str, value: i64, min: i64, max: i64) -> Result<i64, R2ConfigError> {
    if value < min || value > max {
        return Err(R2ConfigError::OutOfRange {
            field,
            value,
            min,
            max,
        });
    }
    Ok(value)
}

/// An endpoint that is not an absolute URL is rejected here and not at the
/// first `Put`: the AWS SDK accepts it without complaint and fails much later.
fn validated_endpoint(value: &str) -> Result<String, R2ConfigError> {
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .ok_or(R2ConfigError::InvalidEndpoint)?;
    if rest.is_empty() {
        return Err(R2ConfigError::InvalidEndpoint);
    }
    Ok(value.trim_end_matches('/').to_string())
}

fn required_string<'a>(
    values: &'a HashMap<String, Value>,
    field: &'static str,
) -> Result<&'a str, R2ConfigError> {
    match optional_string(values, field)? {
        Some(s) => Ok(s),
        None => Err(R2ConfigError::MissingField { field }),
    }
}

/// Reads an optional string. An empty string counts as absent: a field set to
/// `""` in the TOML is a field the user never got round to filling in.
fn optional_string<'a>(
    values: &'a HashMap<String, Value>,
    field: &'static str,
) -> Result<Option<&'a str>, R2ConfigError> {
    match values.get(field).and_then(|v| v.kind.as_ref()) {
        None => Ok(None),
        Some(Kind::StringValue(s)) if s.is_empty() => Ok(None),
        Some(Kind::StringValue(s)) => Ok(Some(s)),
        Some(_) => Err(R2ConfigError::WrongType {
            field,
            expected: "a string",
        }),
    }
}

/// Reads an optional integer. `None` means "it was not there", not "it was
/// there but wrong".
fn optional_int(
    values: &HashMap<String, Value>,
    field: &'static str,
) -> Result<Option<i64>, R2ConfigError> {
    match values.get(field).and_then(|v| v.kind.as_ref()) {
        None => Ok(None),
        Some(Kind::IntValue(v)) => Ok(Some(*v)),
        Some(_) => Err(R2ConfigError::WrongType {
            field,
            expected: "an integer",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_plugin_sdk::sb_proto::{Value, value::Kind};

    fn v_str(s: &str) -> Value {
        Value {
            kind: Some(Kind::StringValue(s.into())),
        }
    }
    fn v_int(i: i64) -> Value {
        Value {
            kind: Some(Kind::IntValue(i)),
        }
    }

    fn base() -> std::collections::HashMap<String, Value> {
        let mut m = std::collections::HashMap::new();
        m.insert("account_id".into(), v_str("abc123"));
        m.insert("bucket".into(), v_str("backups"));
        m.insert("access_key_id".into(), v_str("AKIA"));
        m.insert("secret_access_key".into(), v_str("SECRET"));
        m
    }

    #[test]
    fn both_keys_are_marked_as_secret() {
        // If they were not, the configuration would accept them as literals in
        // the user's TOML file.
        let fields = schema();
        for name in ["access_key_id", "secret_access_key"] {
            let f = fields.iter().find(|f| f.name == name).unwrap();
            assert!(f.secret, "`{name}` must be marked as secret");
        }
    }

    #[test]
    fn the_non_sensitive_fields_are_not_marked_as_secret() {
        let fields = schema();
        for name in ["account_id", "bucket", "prefix"] {
            let f = fields.iter().find(|f| f.name == name).unwrap();
            assert!(!f.secret, "`{name}` is not a secret");
        }
    }

    #[test]
    fn every_field_has_a_description() {
        // `shieldbk plugin docs r2` prints them: a field without a description
        // is a field the user has to guess.
        for f in schema() {
            assert!(!f.description.is_empty(), "`{}` has no description", f.name);
        }
    }

    #[test]
    fn the_endpoint_is_derived_from_the_account_id() {
        let c = R2Config::from_values(&base()).unwrap();
        assert_eq!(c.endpoint(), "https://abc123.r2.cloudflarestorage.com");
    }

    #[test]
    fn an_explicit_endpoint_wins() {
        // Needed for testing against MinIO.
        let mut m = base();
        m.insert("endpoint".into(), v_str("http://localhost:9000"));
        assert_eq!(
            R2Config::from_values(&m).unwrap().endpoint(),
            "http://localhost:9000"
        );
    }

    #[test]
    fn the_default_part_size_is_64_mib() {
        assert_eq!(
            R2Config::from_values(&base()).unwrap().part_size,
            64 * 1024 * 1024
        );
    }

    #[test]
    fn a_part_size_below_s3s_minimum_is_rejected() {
        let mut m = base();
        m.insert("part_size_mb".into(), v_int(1));
        let err = R2Config::from_values(&m).err().unwrap();
        assert!(matches!(err, R2ConfigError::PartTooSmall { .. }));
        assert!(
            err.to_string().contains('5'),
            "it must say what the minimum is"
        );
    }

    #[test]
    fn a_part_size_that_is_not_enough_for_the_expected_maximum_is_rejected() {
        // 10 000 parts is the cap; with 5 MiB parts the ceiling is ~48 GiB.
        // Warning here is better than failing three hours into the upload.
        let mut m = base();
        m.insert("part_size_mb".into(), v_int(5));
        m.insert("max_object_gb".into(), v_int(500));
        let err = R2Config::from_values(&m).err().unwrap();
        assert!(matches!(
            err,
            R2ConfigError::PartTooSmallForMaxObject { .. }
        ));
        assert!(
            err.to_string().contains("part_size_mb"),
            "it must say what to raise"
        );
    }

    #[test]
    fn the_default_size_is_enough_for_the_default_maximum() {
        // That the default configuration be consistent with itself.
        assert!(R2Config::from_values(&base()).is_ok());
    }

    #[test]
    fn the_configuration_does_not_expose_the_keys_when_printed() {
        let c = R2Config::from_values(&base()).unwrap();
        let text = format!("{c:?}");
        assert!(!text.contains("SECRET"));
        assert!(!text.contains("AKIA"));
    }

    #[test]
    fn the_bucket_is_missing() {
        let mut m = base();
        m.remove("bucket");
        let err = R2Config::from_values(&m).err().unwrap();
        assert!(
            err.to_string().contains("bucket"),
            "it must name the missing field"
        );
    }

    #[test]
    fn the_secret_key_is_missing() {
        let mut m = base();
        m.remove("secret_access_key");
        assert!(R2Config::from_values(&m).is_err());
    }

    #[test]
    fn the_prefix_joins_the_key_with_a_single_slash() {
        // Concatenating without a separator would turn the key `..foo` --
        // legitimate, because `..` is only dangerous as a whole segment -- into
        // `/backups..foo`: a sibling of the backup directory, not inside it.
        let mut m = base();
        m.insert("prefix".into(), v_str("team/backups"));
        let c = R2Config::from_values(&m).unwrap();
        assert_eq!(c.key("x.age"), "team/backups/x.age");
        assert_eq!(c.key("..foo.age"), "team/backups/..foo.age");
    }

    #[test]
    fn a_trailing_slash_in_the_prefix_does_not_duplicate_the_separator() {
        let mut m = base();
        m.insert("prefix".into(), v_str("team/"));
        assert_eq!(
            R2Config::from_values(&m).unwrap().key("x.age"),
            "team/x.age"
        );
    }

    #[test]
    fn with_no_prefix_the_key_does_not_change() {
        assert_eq!(
            R2Config::from_values(&base()).unwrap().key("x.age"),
            "x.age"
        );
    }

    #[test]
    fn the_standard_class_sends_no_header_and_the_infrequent_one_does() {
        // `Standard` is what R2 calls its default class, but that name does not
        // exist in S3: sending it makes any other compatible server answer
        // `400 InvalidStorageClass` and the whole upload fail. With no header,
        // the object goes to the bucket's default class, which is what was
        // asked for.
        assert_eq!(R2StorageClass::Standard.header(), None);
        assert_eq!(
            R2StorageClass::InfrequentAccess.header(),
            Some("InfrequentAccess")
        );
    }

    #[test]
    fn the_class_is_read_case_insensitively_and_the_unknown_is_rejected() {
        let mut m = base();
        m.insert("storage_class".into(), v_str("infrequentaccess"));
        assert_eq!(
            R2Config::from_values(&m).unwrap().storage_class,
            R2StorageClass::InfrequentAccess
        );

        let mut m = base();
        m.insert("storage_class".into(), v_str("Glacier"));
        assert!(matches!(
            R2Config::from_values(&m),
            Err(R2ConfigError::UnknownStorageClass)
        ));
    }
}
