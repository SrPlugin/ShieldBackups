//! The plugin's configuration schema and the resolved configuration.
//!
//! Everything the core can tune lives here and nothing else: the data services
//! read an already validated [`Config`] and never look at the raw map again.

use std::collections::HashMap;
use std::path::PathBuf;

use sb_plugin_sdk::Configured;
use sb_plugin_sdk::sb_proto::{Field, FieldType, Value, value::Kind};
use sb_plugin_sdk::tonic::Status;

pub const FIELD_DIR: &str = "dir";
pub const FIELD_SEED: &str = "seed";
pub const FIELD_SIZE: &str = "size";

/// Default seed for the engine's generator.
pub const DEFAULT_SEED: u64 = 42;
/// Default dump size: one mebibyte.
pub const DEFAULT_SIZE: usize = 1_048_576;

/// The fields the plugin accepts, exactly as `Schema` publishes them.
///
/// None of them is a secret: a test plugin that asked for secrets would force
/// the core's tests to set up a credential store.
#[must_use]
pub fn fields() -> Vec<Field> {
    vec![
        Field {
            name: FIELD_DIR.into(),
            r#type: FieldType::Path as i32,
            required: true,
            secret: false,
            description:
                "Directory where the storage target keeps artifacts and the engine writes restored data"
                    .into(),
            default_value: String::new(),
        },
        Field {
            name: FIELD_SEED.into(),
            r#type: FieldType::Int as i32,
            required: false,
            secret: false,
            description: "Seed for the engine's deterministic generator".into(),
            default_value: DEFAULT_SEED.to_string(),
        },
        Field {
            name: FIELD_SIZE.into(),
            r#type: FieldType::Int as i32,
            required: false,
            secret: false,
            description: "Bytes the engine emits on each dump".into(),
            default_value: DEFAULT_SIZE.to_string(),
        },
    ]
}

/// Validated configuration. It only exists if `Configure` succeeded.
#[derive(Clone, Debug)]
pub struct Config {
    pub dir: PathBuf,
    pub seed: u64,
    pub size: usize,
}

impl Config {
    /// Validates the map that arrives in `ConfigureRequest`.
    ///
    /// # Errors
    /// [`Status::invalid_argument`] if `dir` is missing, if some field has a
    /// type that does not belong to it, or if a number does not fit where it
    /// must.
    pub fn from_map(map: &HashMap<String, Value>) -> Result<Self, Status> {
        let dir = match map.get(FIELD_DIR).and_then(|v| v.kind.as_ref()) {
            Some(Kind::StringValue(s)) if !s.is_empty() => PathBuf::from(s),
            Some(Kind::StringValue(_)) | None => {
                return Err(Status::invalid_argument(format!(
                    "the required field `{FIELD_DIR}` is missing"
                )));
            }
            Some(_) => {
                return Err(Status::invalid_argument(format!(
                    "the field `{FIELD_DIR}` must be a path (string)"
                )));
            }
        };

        let seed = int_field(map, FIELD_SEED)?.map_or(Ok(DEFAULT_SEED), |v| {
            u64::try_from(v).map_err(|_| {
                Status::invalid_argument(format!("`{FIELD_SEED}` cannot be negative, it is {v}"))
            })
        })?;

        let size = int_field(map, FIELD_SIZE)?.map_or(Ok(DEFAULT_SIZE), |v| {
            usize::try_from(v).map_err(|_| {
                Status::invalid_argument(format!(
                    "`{FIELD_SIZE}` must be between 0 and {}, it is {v}",
                    usize::MAX
                ))
            })
        })?;

        Ok(Self { dir, seed, size })
    }
}

/// Reads an optional integer field. `None` means "it was not there", not "it
/// was there but wrong".
fn int_field(map: &HashMap<String, Value>, name: &str) -> Result<Option<i64>, Status> {
    match map.get(name).and_then(|v| v.kind.as_ref()) {
        None => Ok(None),
        Some(Kind::IntValue(v)) => Ok(Some(*v)),
        Some(_) => Err(Status::invalid_argument(format!(
            "the field `{name}` must be an integer"
        ))),
    }
}

/// The configuration shared between the plugin's three services.
///
/// `Configure` writes it and the engine and the storage target read it. The SDK
/// provides the store and the rule that "before `Configure` there are no silent
/// defaults": reading it unconfigured yields `failed_precondition`, because a
/// dump written into a directory nobody asked for is worse than a clear error.
pub type State = Configured<Config>;

#[cfg(test)]
mod tests {
    use super::*;
    use sb_plugin_sdk::tonic::Code;

    fn string(s: &str) -> Value {
        Value {
            kind: Some(Kind::StringValue(s.into())),
        }
    }
    fn number(n: i64) -> Value {
        Value {
            kind: Some(Kind::IntValue(n)),
        }
    }

    #[test]
    fn the_schema_publishes_the_three_fields_and_none_is_secret() {
        let fields = fields();
        let names: Vec<&str> = fields.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec![FIELD_DIR, FIELD_SEED, FIELD_SIZE]);
        assert!(fields.iter().all(|c| !c.secret));
        assert!(fields[0].required);
        assert!(!fields[1].required && !fields[2].required);
    }

    #[test]
    fn seed_and_size_have_default_values() {
        let map = HashMap::from([(FIELD_DIR.to_string(), string("/tmp/x"))]);
        let c = Config::from_map(&map).unwrap();
        assert_eq!(c.seed, DEFAULT_SEED);
        assert_eq!(c.size, DEFAULT_SIZE);
    }

    #[test]
    fn without_dir_the_configuration_is_rejected() {
        let e = Config::from_map(&HashMap::new()).unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument);
    }

    #[test]
    fn a_wrong_type_is_rejected_instead_of_ignored() {
        let map = HashMap::from([
            (FIELD_DIR.to_string(), string("/tmp/x")),
            (FIELD_SEED.to_string(), string("forty two")),
        ]);
        assert_eq!(
            Config::from_map(&map).unwrap_err().code(),
            Code::InvalidArgument
        );
    }

    #[test]
    fn a_negative_size_is_rejected() {
        let map = HashMap::from([
            (FIELD_DIR.to_string(), string("/tmp/x")),
            (FIELD_SIZE.to_string(), number(-1)),
        ]);
        assert_eq!(
            Config::from_map(&map).unwrap_err().code(),
            Code::InvalidArgument
        );
    }

    #[test]
    fn without_configure_the_state_fails_with_failed_precondition() {
        let e = State::default().resolved().unwrap_err();
        assert_eq!(e.code(), Code::FailedPrecondition);
    }

    #[test]
    fn after_configure_the_state_returns_what_was_stored() {
        let state = State::default();
        let map = HashMap::from([
            (FIELD_DIR.to_string(), string("/tmp/mock")),
            (FIELD_SEED.to_string(), number(7)),
            (FIELD_SIZE.to_string(), number(10)),
        ]);
        state.store(Config::from_map(&map).unwrap());
        let c = state.resolved().unwrap();
        assert_eq!(c.dir, PathBuf::from("/tmp/mock"));
        assert_eq!(c.seed, 7);
        assert_eq!(c.size, 10);
    }
}
