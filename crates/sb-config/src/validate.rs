//! Validation of a configuration table against the plugin's schema.
//!
//! This is where the plugin architecture closes its circle: the core does not
//! know which fields a source —a database, a directory, a volume— or a cloud
//! destination needs, so it takes the schema the plugin declared over gRPC and
//! checks against it what the user wrote in the TOML. What comes out are the protocol's [`Value`]s, ready to
//! travel in `Configure`.
//!
//! Two symmetric rules govern secrets:
//!
//! 1. **A secret field does not accept a literal value.** If the plugin says a
//!    field is sensitive, only a reference to its origin (`env`, `file`,
//!    `keyring`, `command`) fits in the file. Allowing the literal would turn the
//!    configuration file —which is kept under version control and copied— into a
//!    password store.
//! 2. **A public field does not accept a secret reference.** Resolving it would
//!    spend a keyring read or a command execution on something that is not
//!    sensitive, and above all it would mislead whoever reads the configuration
//!    about which data really has to be protected.
//!
//! The secret is resolved *here*, not in the plugin: the plugin receives the
//! value and never knows where it came from. No error message of this module
//! contains a secret's value, not even the one chained as `source`.

use std::collections::HashMap;

use sb_proto::{Field, FieldType, StringList, Value, value::Kind};

use crate::model::{ConfigTable, ConfigValue, SecretRef};
use crate::secrets::{SecretError, resolve};

/// Maximum edit distance for considering that an unknown field is a typo of
/// another.
///
/// With 1, transpositions plus one extra character slip through; with 3 it starts
/// suggesting things that have nothing to do with each other ("ssl" for "url"),
/// and a wrong suggestion costs more time than none.
const MAX_DISTANCE: usize = 2;

/// Why a configuration is rejected.
///
/// **No variant contains a secret's value.** Those that talk about one name the
/// field or the origin —what is needed to fix it— and the only one that chains
/// another error does so over [`SecretError`], which carries the same guarantee.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    /// The schema declares the field as mandatory and it is not in the table.
    #[error("the mandatory field \"{field}\" is missing in the \"{section}\" section")]
    MissingRequiredField {
        /// Section of the file: `source` or `storage`.
        section: String,
        /// Field the plugin requires.
        field: String,
    },

    /// The table carries a field the plugin does not declare.
    ///
    /// It is rejected instead of ignored: a field the plugin does not read is
    /// almost always a typo, and accepting it in silence leaves the user
    /// believing they configured something that is not in effect.
    #[error("the field \"{field}\" does not exist in the \"{section}\" section; {suggestion}")]
    UnknownField {
        /// Section of the file: `source` or `storage`.
        section: String,
        /// Unknown field, exactly as the user wrote it.
        field: String,
        /// Hint: the similar field, or the list of the ones that do exist.
        suggestion: String,
    },

    /// The written value does not match the type the schema declares.
    #[error("the field \"{field}\" of the \"{section}\" section must be {expected}")]
    WrongType {
        /// Section of the file: `source` or `storage`.
        section: String,
        /// Field with the badly typed value.
        field: String,
        /// Description of the type the plugin expected.
        expected: String,
    },

    /// A secret field carries a literal value.
    ///
    /// The message enumerates the valid forms and does **not** include the
    /// rejected value: that would leak through the error exactly what it is
    /// trying to protect.
    #[error(
        "the field \"{field}\" of the \"{section}\" section is secret and does not accept a \
         literal value in the configuration file; write where to get it from: \
         {{ env = \"VARIABLE\" }}, {{ file = \"/path/to/the/secret\" }}, \
         {{ keyring = \"service/user\" }} or {{ command = [\"program\", \"argument\"] }}"
    )]
    LiteralSecret {
        /// Section of the file: `source` or `storage`.
        section: String,
        /// Secret field that carried the literal.
        field: String,
    },

    /// A field that is not secret carries a secret reference.
    #[error(
        "the field \"{field}\" of the \"{section}\" section is not secret: write its value \
         directly, without a reference to env, file, keyring or command"
    )]
    SecretRefInPublicField {
        /// Section of the file: `source` or `storage`.
        section: String,
        /// Public field that carried the reference.
        field: String,
    },

    /// The reference was correct, but the secret could not be obtained.
    ///
    /// The field goes in the message because a configuration can have several
    /// secrets and "the variable is not defined" on its own forces you to guess
    /// which one. The cause is chained as `source`.
    #[error("could not resolve the secret of the field \"{field}\"")]
    SecretNotResolved {
        /// Field whose secret could not be obtained.
        field: String,
        /// Failure of the resolution. It never contains the value.
        #[source]
        source: SecretError,
    },
}

/// Checks the configuration against the plugin's schema and converts it into the
/// protocol's [`Value`]s, resolving the secrets along the way.
///
/// `section` is `"source"` or `"storage"`, and it only feeds the error messages:
/// in a backup there are two configured plugins, and "the field host is missing"
/// without saying whose it is forces you to guess.
///
/// Optional fields that are absent do not appear in the result: the plugin
/// applies its own default, which is who knows it.
///
/// # Errors
///
/// Returns [`ValidationError`] if a field is left over, a mandatory one is
/// missing, a value does not match its type, a secret was written as a literal, a
/// public field carries a secret reference, or a secret could not be resolved.
pub fn validate_and_convert(
    cfg: &ConfigTable,
    schema: &[Field],
    section: &str,
) -> Result<HashMap<String, Value>, ValidationError> {
    // First what is left over: an unknown field is usually a typo of the field
    // the user believes they wrote, so warning that "host is missing" when they
    // wrote "hosst" would be telling half the story.
    for name in cfg.keys() {
        if !schema.iter().any(|field| &field.name == name) {
            return Err(ValidationError::UnknownField {
                section: section.to_owned(),
                field: name.clone(),
                suggestion: suggest(name, schema),
            });
        }
    }

    let mut out = HashMap::with_capacity(cfg.len());

    for field in schema {
        let Some(value) = cfg.get(&field.name) else {
            if field.required {
                return Err(ValidationError::MissingRequiredField {
                    section: section.to_owned(),
                    field: field.name.clone(),
                });
            }
            continue;
        };

        out.insert(field.name.clone(), convert(field, value, section)?);
    }

    Ok(out)
}

/// Converts a value already paired with its schema field.
fn convert(field: &Field, value: &ConfigValue, section: &str) -> Result<Value, ValidationError> {
    if field.secret {
        return convert_secret(field, value, section);
    }

    if let ConfigValue::Secret(_) = value {
        return Err(ValidationError::SecretRefInPublicField {
            section: section.to_owned(),
            field: field.name.clone(),
        });
    }

    let field_type = FieldType::try_from(field.r#type).unwrap_or(FieldType::Unspecified);

    let kind = match (field_type, value) {
        // `Path` and `Duration` travel as text: their semantics —what a valid
        // path is, how "30s" is written— are interpreted by the plugin, which is
        // the one that knows them. The core only transports.
        (FieldType::String | FieldType::Path | FieldType::Duration, ConfigValue::String(s)) => {
            Kind::StringValue(s.clone())
        }
        (FieldType::Int, ConfigValue::Int(n)) => Kind::IntValue(*n),
        (FieldType::Bool, ConfigValue::Bool(b)) => Kind::BoolValue(*b),
        (FieldType::List, ConfigValue::List(l)) => {
            Kind::ListValue(StringList { values: l.clone() })
        }
        _ => {
            return Err(ValidationError::WrongType {
                section: section.to_owned(),
                field: field.name.clone(),
                expected: type_description(field_type).to_owned(),
            });
        }
    };

    Ok(Value { kind: Some(kind) })
}

/// Resolves the secret of a sensitive field.
///
/// What comes out is the value, not the reference: the plugin receives the
/// password and never the name of the variable nor the path of the file. Knowing
/// where it came from is of no use to it and would give it a path to go looking
/// for more.
fn convert_secret(
    field: &Field,
    value: &ConfigValue,
    section: &str,
) -> Result<Value, ValidationError> {
    let ConfigValue::Secret(reference) = value else {
        // The rejected value does not go into the error, not even truncated: it
        // is exactly the data this module exists to protect.
        return Err(ValidationError::LiteralSecret {
            section: section.to_owned(),
            field: field.name.clone(),
        });
    };

    resolve_reference(reference, &field.name)
}

/// Obtains a reference's value and puts it into a protocol [`Value`].
///
/// The error names the field —a configuration can have several secrets— and
/// chains the [`SecretError`], which does not contain the value either.
fn resolve_reference(reference: &SecretRef, field: &str) -> Result<Value, ValidationError> {
    let secret = resolve(reference).map_err(|source| ValidationError::SecretNotResolved {
        field: field.to_owned(),
        source,
    })?;

    Ok(Value {
        kind: Some(Kind::StringValue(secret.expose().clone())),
    })
}

/// How a schema type is named in an error message.
fn type_description(field_type: FieldType) -> &'static str {
    match field_type {
        FieldType::String => "a string",
        FieldType::Int => "an integer",
        FieldType::Bool => "a boolean (true or false)",
        FieldType::Duration => "a duration written as a string (for example \"30s\")",
        FieldType::Path => "a path written as a string",
        FieldType::List => "a list of strings",
        FieldType::Unspecified => "of a type the plugin does not declare; this is a plugin bug",
    }
}

/// Hint for a field the schema does not declare.
///
/// With a reasonable resemblance it is named: it is almost always the typo.
/// Without one, suggesting the "least distant" would be noise —the user did not
/// misspell `host`, they wrote something else— and what helps is showing them
/// which fields exist.
fn suggest(unknown: &str, schema: &[Field]) -> String {
    if schema.is_empty() {
        return "this plugin declares no configuration field".to_owned();
    }

    let similar = schema
        .iter()
        .map(|field| (distance(unknown, &field.name), &field.name))
        .filter(|(d, _)| *d <= MAX_DISTANCE)
        .min_by_key(|(d, _)| *d);

    if let Some((_, name)) = similar {
        return format!("did you mean \"{name}\"?");
    }

    let available: Vec<&str> = schema.iter().map(|field| field.name.as_str()).collect();
    format!("the available fields are: {}", available.join(", "))
}

/// Levenshtein distance between two strings, in characters.
///
/// It is counted per `char` and not per byte so that a typo in a name with
/// accents is not measured as if it were two changes.
fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();

    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }

    // Only two rows of the matrix are needed: the previous one and the one being
    // computed.
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current: Vec<usize> = vec![0; b.len() + 1];

    for (i, ca) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let substitution = previous[j] + usize::from(ca != cb);
            let deletion = previous[j + 1] + 1;
            let insertion = current[j] + 1;
            current[j + 1] = substitution.min(deletion).min(insertion);
        }
        std::mem::swap(&mut previous, &mut current);
    }

    previous[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_proto::{Field, FieldType};

    fn field(name: &str, field_type: FieldType, required: bool, secret: bool) -> Field {
        Field {
            name: name.into(),
            r#type: field_type as i32,
            required,
            secret,
            description: String::new(),
            default_value: String::new(),
        }
    }

    fn schema() -> Vec<Field> {
        vec![
            field("host", FieldType::String, true, false),
            field("port", FieldType::Int, false, false),
            field("password", FieldType::String, true, true),
            field("ssl", FieldType::Bool, false, false),
            field("path", FieldType::Path, false, false),
            field("exclude", FieldType::List, false, false),
        ]
    }

    fn table(pairs: Vec<(&str, ConfigValue)>) -> ConfigTable {
        pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    /// The minimal valid configuration: the two required fields.
    fn minimal() -> ConfigTable {
        table(vec![
            ("host", ConfigValue::String("db".into())),
            (
                "password",
                ConfigValue::Secret(SecretRef::Env("PATH".into())),
            ),
        ])
    }

    #[test]
    fn accepts_a_correct_configuration() {
        let r = validate_and_convert(&minimal(), &schema(), "source").unwrap();
        assert!(r.contains_key("host"));
        assert!(r.contains_key("password"));
    }

    #[test]
    fn the_secret_arrives_resolved_not_as_a_reference() {
        // The plugin receives the value, never the path nor the variable name.
        let r = validate_and_convert(&minimal(), &schema(), "source").unwrap();
        let v = r.get("password").unwrap();
        match &v.kind {
            Some(sb_proto::value::Kind::StringValue(s)) => {
                assert!(!s.is_empty());
                assert!(!s.contains("PATH"), "the variable name must not travel");
            }
            other => panic!("a string was expected, {other:?} arrived"),
        }
    }

    #[test]
    fn a_required_field_is_missing() {
        let cfg = table(vec![("host", ConfigValue::String("db".into()))]);
        let err = validate_and_convert(&cfg, &schema(), "source")
            .err()
            .unwrap();
        assert!(
            matches!(err, ValidationError::MissingRequiredField { ref field, .. } if field == "password")
        );
    }

    #[test]
    fn an_unknown_field_is_rejected_and_the_similar_one_is_suggested() {
        let mut cfg = minimal();
        cfg.insert("hosst".into(), ConfigValue::String("db".into()));
        let err = validate_and_convert(&cfg, &schema(), "source")
            .err()
            .unwrap();
        let text = err.to_string();
        assert!(text.contains("hosst"));
        assert!(
            text.contains("host"),
            "it must suggest the field that does exist"
        );
    }

    #[test]
    fn a_very_different_unknown_field_lists_the_available_ones() {
        // Without a reasonable resemblance, suggesting any of them would be
        // noise; better to show which fields exist.
        let mut cfg = minimal();
        cfg.insert("zzzzzzzz".into(), ConfigValue::String("x".into()));
        let text = validate_and_convert(&cfg, &schema(), "source")
            .err()
            .unwrap()
            .to_string();
        assert!(
            text.contains("host") && text.contains("port"),
            "it must list the available fields"
        );
    }

    #[test]
    fn a_wrong_type_is_rejected() {
        let mut cfg = minimal();
        cfg.insert("port".into(), ConfigValue::String("not-a-number".into()));
        assert!(matches!(
            validate_and_convert(&cfg, &schema(), "source")
                .err()
                .unwrap(),
            ValidationError::WrongType { .. }
        ));
    }

    #[test]
    fn a_secret_field_does_not_accept_a_literal_value() {
        // The most important rule of the module.
        let cfg = table(vec![
            ("host", ConfigValue::String("db".into())),
            ("password", ConfigValue::String("hunter2".into())),
        ]);
        let err = validate_and_convert(&cfg, &schema(), "source")
            .err()
            .unwrap();
        assert!(matches!(err, ValidationError::LiteralSecret { .. }));
        assert!(
            !err.to_string().contains("hunter2"),
            "the error must not leak the secret"
        );
    }

    #[test]
    fn the_literal_secret_error_states_the_alternatives() {
        let cfg = table(vec![
            ("host", ConfigValue::String("db".into())),
            ("password", ConfigValue::String("x".into())),
        ]);
        let text = validate_and_convert(&cfg, &schema(), "source")
            .err()
            .unwrap()
            .to_string();
        assert!(text.contains("env"), "it must say how to do it right");
        assert!(text.contains("file"));
    }

    #[test]
    fn a_non_secret_field_does_not_accept_a_secret_reference() {
        let mut cfg = minimal();
        cfg.insert(
            "host".into(),
            ConfigValue::Secret(SecretRef::Env("PATH".into())),
        );
        assert!(matches!(
            validate_and_convert(&cfg, &schema(), "source")
                .err()
                .unwrap(),
            ValidationError::SecretRefInPublicField { .. }
        ));
    }

    #[test]
    fn absent_optional_fields_do_not_get_in_the_way() {
        let r = validate_and_convert(&minimal(), &schema(), "source").unwrap();
        assert!(!r.contains_key("port"));
        assert!(!r.contains_key("ssl"));
    }

    #[test]
    fn the_path_and_duration_types_travel_as_text() {
        // Their semantics are interpreted by the plugin, not by the core.
        let mut cfg = minimal();
        cfg.insert("path".into(), ConfigValue::String("/var/lib/x".into()));
        let r = validate_and_convert(&cfg, &schema(), "source").unwrap();
        assert!(matches!(
            r.get("path").unwrap().kind,
            Some(sb_proto::value::Kind::StringValue(_))
        ));
    }

    #[test]
    fn a_list_travels_as_a_list() {
        let mut cfg = minimal();
        cfg.insert(
            "exclude".into(),
            ConfigValue::List(vec!["a".into(), "b".into()]),
        );
        let r = validate_and_convert(&cfg, &schema(), "source").unwrap();
        match &r.get("exclude").unwrap().kind {
            Some(sb_proto::value::Kind::ListValue(l)) => assert_eq!(l.values.len(), 2),
            other => panic!("a list was expected, {other:?} arrived"),
        }
    }

    #[test]
    fn a_boolean_travels_as_a_boolean() {
        let mut cfg = minimal();
        cfg.insert("ssl".into(), ConfigValue::Bool(true));
        let r = validate_and_convert(&cfg, &schema(), "source").unwrap();
        assert!(matches!(
            r.get("ssl").unwrap().kind,
            Some(sb_proto::value::Kind::BoolValue(true))
        ));
    }

    #[test]
    fn the_error_names_the_section() {
        // In a backup there are two configured plugins. "the field host is
        // missing" without saying whether it is the source's or the storage's
        // forces you to guess.
        let cfg = ConfigTable::new();
        let text = validate_and_convert(&cfg, &schema(), "storage")
            .err()
            .unwrap()
            .to_string();
        assert!(text.contains("storage"));
    }

    #[test]
    fn a_secret_that_cannot_be_resolved_gives_a_useful_error() {
        let cfg = table(vec![
            ("host", ConfigValue::String("db".into())),
            (
                "password",
                ConfigValue::Secret(SecretRef::Env("SB_DOES_NOT_EXIST_ABC_999".into())),
            ),
        ]);
        let err = validate_and_convert(&cfg, &schema(), "source")
            .err()
            .unwrap();
        let text = err.to_string();
        assert!(text.contains("password"), "it must say which field failed");
    }

    #[test]
    fn an_empty_schema_rejects_any_field() {
        let cfg = table(vec![("whatever", ConfigValue::String("x".into()))]);
        assert!(validate_and_convert(&cfg, &[], "source").is_err());
    }

    #[test]
    fn an_empty_schema_accepts_an_empty_configuration() {
        assert!(
            validate_and_convert(&ConfigTable::new(), &[], "source")
                .unwrap()
                .is_empty()
        );
    }
}
