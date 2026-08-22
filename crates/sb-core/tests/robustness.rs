//! Robustness of the core's parsers against arbitrary input.
//!
//! Everything tested here processes data the core did not write: the lockfile on
//! disk, the manifest that comes down from the storage, the template and the
//! target name that come from the user's configuration, and the digests and
//! public keys that travel inside the manifest. None of them may cause a panic,
//! and in the case of [`sb_core::naming::render`] none of them may sneak an
//! unsafe key through either.

use std::fmt::Write as _;

use proptest::prelude::*;
use sb_core::lockfile::Lockfile;
use sb_core::model::Manifest;
use sb_core::naming::{MAX_KEY_BYTES, NamingContext, render};
use sb_crypto::{Digest, Recipient};

/// Checks the invariants that make an artifact key safe.
///
/// It is exactly what the storage takes for granted: that the key does not leave
/// the backup directory, that it injects nothing into the request headers, and
/// that the object storage is going to accept it.
fn safe_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("the key is empty".to_owned());
    }
    if key.starts_with('/') {
        return Err(format!("\"{key}\" is absolute"));
    }
    if key.contains('\\') {
        return Err(format!("\"{key}\" contains a backslash"));
    }
    if let Some(c) = key
        .chars()
        .find(|c| matches!(*c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}'))
    {
        return Err(format!(
            "\"{key}\" contains the control character U+{:04X}",
            c as u32
        ));
    }
    if key.len() > MAX_KEY_BYTES {
        return Err(format!("\"{key}\" takes {} bytes", key.len()));
    }
    for segment in key.split('/') {
        if matches!(segment, ".." | "." | "") {
            return Err(format!("\"{key}\" has a \"{segment}\" segment"));
        }
    }
    Ok(())
}

/// A context with every field arbitrary: the name of the target, the engine and
/// the storage come from the user's configuration, so they are external input
/// just as much as the template.
fn arbitrary_context() -> impl Strategy<Value = NamingContext> {
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

    /// No input, however absurd, may cause a panic.
    #[test]
    fn the_lockfile_parser_never_panics(input in ".*") {
        let _ = Lockfile::from_toml(&input);
    }

    /// Arbitrary bytes, including those that are not valid UTF-8.
    #[test]
    fn arbitrary_bytes_do_not_break_the_lockfile(
        bytes in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let text = String::from_utf8_lossy(&bytes);
        let _ = Lockfile::from_toml(&text);
    }

    /// TOML with the right shape and extreme values: enormous versions,
    /// arbitrary plugin names and hashes.
    #[test]
    fn a_valid_lockfile_with_extreme_values_does_not_panic(
        version in any::<u64>(),
        name in "[a-z-]{1,16}",
        sha in ".*",
    ) {
        let text = format!(
            "version = {version}\n\n[plugins.{name}]\nsha256 = {}\n",
            toml_str(&sha)
        );
        let _ = Lockfile::from_toml(&text);
    }

    // ---------- manifest ----------

    #[test]
    fn the_manifest_parser_never_panics(input in ".*") {
        let _ = Manifest::parse(&input);
    }

    #[test]
    fn arbitrary_bytes_do_not_break_the_manifest(
        bytes in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let text = String::from_utf8_lossy(&bytes);
        let _ = Manifest::parse(&text);
    }

    /// JSON with the exact shape of the manifest and extreme values: sizes at the
    /// edge of `u64`, future versions and very long strings.
    #[test]
    fn a_valid_manifest_with_extreme_values_does_not_panic(
        version in any::<u32>(),
        plaintext in any::<u64>(),
        ciphertext in any::<u64>(),
        level in any::<i32>(),
        length in 0_usize..8192,
        free_text in ".*",
    ) {
        let string = "\u{e1}".repeat(length);
        let json = serde_json::json!({
            "version": version,
            "target": string,
            "engine": {
                "plugin": free_text,
                "plugin_version": string,
                "server_version": string,
            },
            "created_at": free_text,
            "artifact_key": string,
            "plaintext_bytes": plaintext,
            "ciphertext_bytes": ciphertext,
            "plaintext_sha256": string,
            "ciphertext_sha256": free_text,
            "compression": { "algorithm": free_text, "level": level },
            "encryption": { "algorithm": free_text, "recipient": free_text },
        })
        .to_string();
        // If it is accepted, deriving the manifest key must not break either.
        if let Ok(m) = Manifest::parse(&json) {
            let _ = m.manifest_key();
        }
    }

    /// Deep arrays —but within serde_json's recursion limit— where the manifest
    /// expects an object.
    #[test]
    fn a_manifest_with_deep_arrays_does_not_panic(depth in 0_usize..120) {
        let json = format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
        prop_assert!(Manifest::parse(&json).is_err());
    }

    // ---------- naming ----------

    /// The template is written by the user: it can be anything.
    #[test]
    fn render_never_panics_with_arbitrary_templates(template in ".*") {
        let ctx = NamingContext::new("t", "e", "s", 0);
        let _ = render(&template, &ctx);
    }

    /// Templates biased towards braces, which is where the slicing logic is:
    /// `.*` almost never generates a `{` followed by a `}`.
    #[test]
    fn render_survives_templates_full_of_braces(
        template in "[{}a-z/.\\\\{}0-9]{0,64}",
    ) {
        let ctx = NamingContext::new("t", "e", "s", 0);
        let _ = render(&template, &ctx);
    }

    /// The context is external input too: the target's name comes from the
    /// user's configuration.
    #[test]
    fn render_never_panics_with_arbitrary_contexts(
        template in ".*",
        ctx in arbitrary_context(),
    ) {
        let _ = render(&template, &ctx);
    }

    /// **The property that really matters**: if `render` returns `Ok`, the key
    /// satisfies the safety invariants. Not panicking is not enough; the
    /// validation must not be bypassable with any combination of template and
    /// context.
    #[test]
    fn an_accepted_key_is_always_safe(
        template in ".*",
        ctx in arbitrary_context(),
    ) {
        if let Ok(key) = render(&template, &ctx)
            && let Err(reason) = safe_key(&key)
        {
            prop_assert!(false, "render accepted an unsafe key: {reason}");
        }
    }

    /// The same property, with templates and contexts biased towards the
    /// dangerous characters: slashes, dots, braces, control characters and null
    /// bytes. With `.*` the probability of generating `{target}` is practically
    /// nil.
    #[test]
    fn an_accepted_key_is_safe_with_hostile_input_too(
        template in prop::collection::vec(
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
        ).prop_map(|parts| parts.concat()),
        target in prop_oneof![
            Just("..".to_owned()),
            Just("/".to_owned()),
            Just(".".to_owned()),
            Just(String::new()),
            Just("a/../..".to_owned()),
            Just("x\r\nX-Injected: yes".to_owned()),
            Just("\u{f1}".repeat(600)),
            Just("a".repeat(2000)),
            "[a-z./\\\\]{0,8}",
        ],
    ) {
        let mut ctx = NamingContext::new(&target, "e", "s", 0);
        ctx.storage = target.clone();
        if let Ok(key) = render(&template, &ctx)
            && let Err(reason) = safe_key(&key)
        {
            prop_assert!(false, "render accepted an unsafe key: {reason}");
        }
    }

    /// The context constructor receives the system clock's timestamp: a broken
    /// clock cannot bring a backup down.
    #[test]
    fn the_context_is_built_with_any_timestamp(
        epoch in any::<i64>(),
        target in ".*",
    ) {
        let ctx = NamingContext::new(&target, "e", "s", epoch);
        prop_assert!(!ctx.timestamp.is_empty());
    }

    // ---------- crypto ----------

    /// `Digest::from_hex` receives strings that come from the manifest, that is,
    /// from the remote storage.
    #[test]
    fn the_digest_parser_never_panics(input in ".*") {
        let _ = Digest::from_hex(&input);
    }

    /// Strings of exactly 64 **bytes** made of multibyte characters: the length
    /// check is in bytes and the slicing into pairs is too, so a two- or
    /// three-byte character falls right in the middle.
    #[test]
    fn a_64_byte_non_ascii_digest_does_not_panic(
        filler in prop::collection::vec(
            prop_oneof![Just('a'), Just('\u{f1}'), Just('\u{20ac}'), Just('\u{1d11e}'), Just('f'), Just('0')],
            0..64,
        ),
    ) {
        let mut s: String = filler.into_iter().collect();
        while s.len() > 64 {
            s.pop();
        }
        while s.len() < 64 {
            s.push('0');
        }
        prop_assert_eq!(s.len(), 64);
        let _ = Digest::from_hex(&s);
    }

    /// A well-formed hexadecimal digest always makes the full round trip.
    #[test]
    fn a_valid_hexadecimal_digest_round_trips(bytes in prop::array::uniform32(any::<u8>())) {
        let hex = bytes.iter().fold(String::with_capacity(64), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        });
        let d = Digest::from_hex(&hex).unwrap();
        prop_assert_eq!(d.to_hex(), hex);
    }

    /// The age public key comes from the configuration and from the manifest.
    #[test]
    fn the_recipient_parser_never_panics(input in ".*") {
        let _ = Recipient::parse(&input);
    }

    /// Biased towards what *looks* like an age key: the right prefix with an
    /// arbitrary bech32 body exercises the decoder for real.
    #[test]
    fn a_recipient_that_looks_like_age_does_not_panic(body in "[a-z0-9]{0,80}") {
        let _ = Recipient::parse(&format!("age1{body}"));
    }
}

/// Writes `s` as a TOML string literal.
///
/// It does not use `unwrap`: in a free helper of a `tests/` file that is
/// forbidden by the workspace's clippy configuration.
fn toml_str(s: &str) -> String {
    toml::to_string(&toml::Value::String(s.to_owned()))
        .map_or_else(|_| "\"\"".to_owned(), |t| t.trim().to_owned())
}

#[test]
fn an_enormous_lockfile_does_not_exhaust_memory() {
    let enormous = "x".repeat(10 * 1024 * 1024);
    assert!(Lockfile::from_toml(&enormous).is_err());
}

#[test]
fn an_enormous_manifest_does_not_exhaust_memory() {
    let enormous = "x".repeat(10 * 1024 * 1024);
    assert!(Manifest::parse(&enormous).is_err());
}

#[test]
fn a_deeply_nested_manifest_does_not_overflow_the_stack() {
    // A stack overflow is NOT a catchable panic: it aborts the process.
    let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
    assert!(Manifest::parse(&deep).is_err());
}

#[test]
fn a_deeply_nested_lockfile_does_not_overflow_the_stack() {
    let deep = format!("a = {}1{}", "[".repeat(10_000), "]".repeat(10_000));
    assert!(Lockfile::from_toml(&deep).is_err());
}

#[test]
fn an_enormous_template_does_not_exhaust_memory() {
    // The resulting key would exceed the S3 limit long before it mattered.
    let enormous = "x".repeat(10 * 1024 * 1024);
    let ctx = NamingContext::new("t", "e", "s", 0);
    assert!(render(&enormous, &ctx).is_err());
}

#[test]
fn many_unclosed_braces_do_not_cause_an_infinite_loop() {
    // An unclosed brace is literal text: `render`'s loop has to keep advancing or
    // it would never terminate.
    let ctx = NamingContext::new("t", "e", "s", 0);
    let template = "{".repeat(100_000);
    assert!(
        render(&template, &ctx).is_err(),
        "it exceeds the byte limit"
    );
    assert_eq!(render("{{{{", &ctx).unwrap(), "{{{{");
}

#[test]
fn a_64_byte_digest_with_multibyte_characters_does_not_panic() {
    // 21 euro signs (3 bytes each) plus an "a": exactly 64 bytes, but the slicing
    // into pairs falls in the middle of a character.
    let s = format!("{}a", "\u{20ac}".repeat(21));
    assert_eq!(s.len(), 64, "the trap is that it measures 64 bytes");
    assert!(Digest::from_hex(&s).is_err());
}
