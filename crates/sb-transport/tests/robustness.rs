//! Robustness of the handshake in the face of an external binary's output.
//!
//! The handshake is the first surface of a plugin the core sees: a child
//! process that may be broken, of a different version, or outright hostile. A
//! panic here is a failure of the core caused by whatever somebody else wrote
//! to their stdout, so the property under test is not "it parses correctly" but
//! "it panics on nothing".

use proptest::prelude::*;
use sb_transport::{Bootstrap, Ready};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// No input, however absurd, may cause a panic.
    #[test]
    fn the_ready_parser_never_panics(input in ".*") {
        let _ = Ready::from_line(&input);
    }

    #[test]
    fn the_bootstrap_parser_never_panics(input in ".*") {
        let _ = Bootstrap::from_line(&input);
    }

    /// Arbitrary bytes, including ones that are not valid UTF-8.
    #[test]
    fn arbitrary_bytes_do_not_cause_a_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let text = String::from_utf8_lossy(&bytes);
        let _ = Ready::from_line(&text);
        let _ = Bootstrap::from_line(&text);
    }

    /// Structurally valid JSON with extreme values.
    #[test]
    fn json_with_extreme_values_does_not_cause_a_panic(
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

    /// A plugin may announce any list of versions, including huge or empty
    /// ones. Negotiating must not panic even when there is nothing in common.
    #[test]
    fn version_negotiation_never_panics(
        from_core in prop::collection::vec(any::<u32>(), 0..64),
        from_plugin in prop::collection::vec(any::<u32>(), 0..64),
    ) {
        let json = format!(
            r#"{{"magic":"SHIELDBK_PLUGIN","handshake_version":1,"core_protocol_versions":{},"control_socket":"/tmp/x.sock","tls":{{"ca_cert_pem":"","server_cert_pem":"","server_key_pem":""}}}}"#,
            serde_json::to_string(&from_core).unwrap()
        );
        let b = Bootstrap::from_line(&json).unwrap();
        let chosen = b.negotiate(&from_plugin);
        // If a version was chosen, it has to be in both lists: negotiating
        // cannot invent one that neither side supports.
        if let Ok(v) = chosen {
            prop_assert!(from_core.contains(&v));
            prop_assert!(from_plugin.contains(&v));
        }
    }

    /// The envelope the core writes can always be read back, whatever the
    /// content of the fields that come from outside.
    #[test]
    fn the_bootstrap_survives_its_own_round_trip(
        socket in ".*",
        ca in ".*",
        cert in ".*",
        key in ".*",
    ) {
        let b = Bootstrap::new(
            vec![1],
            socket.clone(),
            sb_transport::ServerBundle {
                ca_cert_pem: ca,
                server_cert_pem: cert,
                server_key_pem: key,
            },
        );
        let line = b.to_line().unwrap();
        prop_assert!(!line.contains('\n'), "the envelope has to fit on one line");
        prop_assert_eq!(Bootstrap::from_line(&line).unwrap().control_socket, socket);
    }
}

#[test]
fn a_huge_line_does_not_exhaust_memory() {
    // A broken plugin could write gigabytes to stdout.
    let huge = "x".repeat(10 * 1024 * 1024);
    assert!(Ready::from_line(&huge).is_err());
}

#[test]
fn deeply_nested_json_does_not_overflow_the_stack() {
    // A stack overflow is NOT a catchable panic: it aborts the process.
    let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
    assert!(Ready::from_line(&deep).is_err());
}

#[test]
fn the_right_magic_with_everything_else_missing_is_rejected() {
    assert!(Ready::from_line(r#"{"magic":"SHIELDBK_PLUGIN"}"#).is_err());
}

#[test]
fn a_deeply_nested_bootstrap_does_not_overflow_the_stack() {
    let deep = format!(
        "{}{}",
        "{\"a\":".repeat(10_000),
        "1".to_owned() + &"}".repeat(10_000)
    );
    assert!(Bootstrap::from_line(&deep).is_err());
}
