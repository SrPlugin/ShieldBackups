//! Robustness of the configuration parser against arbitrary text.
//!
//! The configuration TOML is written by a person, but it can also come from a
//! shared repository or from a generated template. That it is invalid is normal;
//! that it takes the process down is not.

use proptest::prelude::*;
use sb_config::Config;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// No input, however absurd, may cause a panic.
    #[test]
    fn the_configuration_parser_never_panics(input in ".*") {
        let _ = Config::parse(&input);
    }

    /// Arbitrary bytes, including those that are not valid UTF-8.
    #[test]
    fn arbitrary_bytes_do_not_cause_a_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let text = String::from_utf8_lossy(&bytes);
        let _ = Config::parse(&text);
    }

    /// Structurally valid TOML but with extreme values in the fields the parser
    /// does interpret.
    #[test]
    fn a_valid_toml_with_extreme_values_does_not_panic(
        level in any::<i64>(),
        name in ".*",
        template in ".*",
    ) {
        let text = format!(
            "[defaults]\ncompression_level = {level}\n\n[[target]]\nname = {}\nengine = \"e\"\n\
             storage = \"s\"\nrecipient = \"age1x\"\nartifact_template = {}\n",
            toml_str(&name),
            toml_str(&template),
        );
        let _ = Config::parse(&text);
    }

    /// Many targets, with names that may repeat: the path that detects duplicates
    /// is external input too.
    #[test]
    fn many_targets_with_arbitrary_names_do_not_cause_a_panic(
        names in prop::collection::vec("[a-z]{0,3}", 0..64),
    ) {
        use std::fmt::Write as _;
        let mut text = String::new();
        for n in &names {
            let _ = write!(
                text,
                "[[target]]\nname = {}\nengine = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\n\n",
                toml_str(n)
            );
        }
        let _ = Config::parse(&text);
    }

    /// The opaque plugin tables accept any shape: the core does not interpret
    /// them, so it has to swallow whatever comes without breaking.
    #[test]
    fn arbitrary_opaque_tables_do_not_cause_a_panic(
        key in "[a-z_]{1,8}",
        value in ".*",
    ) {
        let text = format!(
            "[[target]]\nname = \"t\"\nengine = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\n\
             [target.engine_config]\n{key} = {}\n",
            toml_str(&value)
        );
        let _ = Config::parse(&text);
    }
}

/// Writes `s` as a TOML string literal.
///
/// It does not use `unwrap`: in a free helper of a `tests/` file that is
/// forbidden, and here it would also be unnecessary —serializing a `String` to
/// TOML cannot fail, but saying so with an `unwrap_or` costs the same as
/// asserting it—.
fn toml_str(s: &str) -> String {
    toml::to_string(&toml::Value::String(s.to_owned()))
        .map_or_else(|_| "\"\"".to_owned(), |t| t.trim().to_owned())
}

#[test]
fn an_enormous_file_does_not_exhaust_memory() {
    // A ten-megabyte TOML of garbage has to fail, not take the process down.
    let enormous = "x".repeat(10 * 1024 * 1024);
    assert!(Config::parse(&enormous).is_err());
}

#[test]
fn a_deeply_nested_toml_does_not_overflow_the_stack() {
    // A stack overflow is NOT a catchable panic: it aborts the process.
    let deep = format!("a = {}1{}", "[".repeat(10_000), "]".repeat(10_000));
    assert!(Config::parse(&deep).is_err());
}

#[test]
fn an_empty_configuration_is_rejected_without_a_panic() {
    assert!(Config::parse("").is_err());
}
