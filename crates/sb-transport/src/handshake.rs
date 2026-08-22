use serde::{Deserialize, Serialize};

use crate::pki::ServerBundle;

/// Marker that opens both handshake messages.
///
/// It exists so that a binary which is not a shieldbk plugin fails immediately
/// and with a clear message, instead of hanging while it waits for something
/// that will never arrive.
pub const MAGIC: &str = "SHIELDBK_PLUGIN";

/// Version of the handshake envelope.
///
/// Distinct from `core_protocol_versions`, which negotiates the gRPC protocol
/// that follows. This one versions the startup JSON itself, so that adding a
/// mandatory field in the future makes an old plugin fail **at startup**, with
/// a clear message, instead of later and worse.
pub const HANDSHAKE_VERSION: u32 = 1;

/// How long the core waits, by default, for the plugin to announce itself.
/// Generous for slow startups, bounded so nothing hangs overnight.
pub const READY_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("the response is not valid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("the binary did not identify itself as a shieldbk plugin")]
    BadMagic,
    #[error("no protocol version in common: the core supports {core:?}, the plugin {plugin:?}")]
    NoCommonVersion { core: Vec<u32>, plugin: Vec<u32> },
    #[error(
        "handshake envelope version {found}; this version of shieldbk understands up to {supported}"
    )]
    UnsupportedEnvelope { found: u32, supported: u32 },
}

/// What the core writes to the plugin's stdin.
///
/// Deliberately single-line JSON: a plugin in any language reads it with one
/// `read_line` and parses it with its standard library. Speaking protobuf is
/// not a prerequisite for starting up.
#[derive(Clone, Serialize, Deserialize)]
pub struct Bootstrap {
    pub magic: String,
    /// Version of this envelope. `default` = 0 for envelopes older than the
    /// field.
    #[serde(default)]
    pub handshake_version: u32,
    pub core_protocol_versions: Vec<u32>,
    pub control_socket: String,
    /// Name the plugin must present in its server certificate. It is sent
    /// explicitly so that a plugin written in another language does not have to
    /// parse the certificate or know about a Rust constant.
    #[serde(default)]
    pub server_name: String,
    /// Name the plugin must require of the client. It makes the mTLS policy
    /// data rather than tribal knowledge.
    #[serde(default)]
    pub client_name: String,
    /// How long the plugin has to announce itself before the core gives it up
    /// for lost. The timing contract goes both ways.
    #[serde(default)]
    pub ready_timeout_ms: u64,
    pub tls: ServerBundle,
}

/// `Debug` redacted by hand: this struct holds the server's private key and
/// must never be able to end up whole in a log.
impl std::fmt::Debug for Bootstrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bootstrap")
            .field("magic", &self.magic)
            .field("handshake_version", &self.handshake_version)
            .field("core_protocol_versions", &self.core_protocol_versions)
            .field("control_socket", &self.control_socket)
            .field("server_name", &self.server_name)
            .field("client_name", &self.client_name)
            .field("ready_timeout_ms", &self.ready_timeout_ms)
            .field("tls", &"<redacted>")
            .finish()
    }
}

impl Bootstrap {
    /// Builds the envelope the core sends to the plugin.
    ///
    /// This is the recommended route: it fills in the marker, the envelope
    /// version, the TLS names and the timeout with the right values, so that
    /// adding a field in the future does not force a review of every place that
    /// constructs one.
    #[must_use]
    pub fn new(
        core_protocol_versions: Vec<u32>,
        control_socket: String,
        tls: ServerBundle,
    ) -> Self {
        Self {
            magic: MAGIC.into(),
            handshake_version: HANDSHAKE_VERSION,
            core_protocol_versions,
            control_socket,
            server_name: crate::pki::SERVER_NAME.into(),
            client_name: crate::pki::CLIENT_NAME.into(),
            ready_timeout_ms: READY_TIMEOUT_MS,
            tls,
        }
    }

    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_line(&self) -> Result<String, HandshakeError> {
        Ok(serde_json::to_string(self)?)
    }

    /// # Errors
    /// Returns an error if the line is not valid JSON, does not carry the
    /// marker, or declares an envelope version this build cannot read.
    pub fn from_line(line: &str) -> Result<Self, HandshakeError> {
        let b: Self = serde_json::from_str(line.trim())?;
        if b.magic != MAGIC {
            return Err(HandshakeError::BadMagic);
        }
        if b.handshake_version > HANDSHAKE_VERSION {
            return Err(HandshakeError::UnsupportedEnvelope {
                found: b.handshake_version,
                supported: HANDSHAKE_VERSION,
            });
        }
        Ok(b)
    }

    /// Picks the highest version both sides support.
    ///
    /// # Errors
    /// Returns `NoCommonVersion` if there is none in common, with both lists in
    /// the message so that whoever reads it knows what to upgrade.
    pub fn negotiate(&self, plugin_versions: &[u32]) -> Result<u32, HandshakeError> {
        self.core_protocol_versions
            .iter()
            .filter(|v| plugin_versions.contains(v))
            .max()
            .copied()
            .ok_or_else(|| HandshakeError::NoCommonVersion {
                core: self.core_protocol_versions.clone(),
                plugin: plugin_versions.to_vec(),
            })
    }
}

/// What the plugin writes to its stdout once it is listening.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ready {
    pub magic: String,
    pub protocol_version: u32,
    pub capabilities: Vec<String>,
    pub pid: u32,
}

impl Ready {
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_line(&self) -> Result<String, HandshakeError> {
        Ok(serde_json::to_string(self)?)
    }

    /// # Errors
    /// Returns an error if the line is not valid JSON or does not carry the
    /// marker.
    pub fn from_line(line: &str) -> Result<Self, HandshakeError> {
        let r: Self = serde_json::from_str(line.trim())?;
        if r.magic != MAGIC {
            return Err(HandshakeError::BadMagic);
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bootstrap() -> Bootstrap {
        Bootstrap::new(
            vec![1],
            "/run/user/1000/shieldbk-abc/control.sock".into(),
            crate::pki::ServerBundle {
                ca_cert_pem: "CA".into(),
                server_cert_pem: "CERT".into(),
                server_key_pem: "KEY".into(),
            },
        )
    }

    fn sample_ready() -> Ready {
        Ready {
            magic: MAGIC.into(),
            protocol_version: 1,
            capabilities: vec!["source".into()],
            pid: 4242,
        }
    }

    #[test]
    fn the_bootstrap_travels_as_a_single_json_line() {
        // One line: the plugin reads it with an ordinary read_line, without
        // needing a streaming parser or knowing how many bytes to expect.
        let line = sample_bootstrap().to_line().unwrap();
        assert!(!line.contains('\n'), "it must be exactly one line");
        let round_tripped = Bootstrap::from_line(&line).unwrap();
        assert_eq!(
            round_tripped.control_socket,
            "/run/user/1000/shieldbk-abc/control.sock"
        );
        assert_eq!(round_tripped.tls.server_key_pem, "KEY");
    }

    #[test]
    fn a_bootstrap_with_the_wrong_magic_is_rejected() {
        let mut b = sample_bootstrap();
        b.magic = "SOMETHING-ELSE".into();
        let line = serde_json::to_string(&b).unwrap();
        assert!(matches!(
            Bootstrap::from_line(&line).unwrap_err(),
            HandshakeError::BadMagic
        ));
    }

    #[test]
    fn a_bootstrap_that_is_not_json_is_rejected() {
        assert!(matches!(
            Bootstrap::from_line("this is not json").unwrap_err(),
            HandshakeError::InvalidJson(_)
        ));
    }

    #[test]
    fn an_empty_line_is_rejected() {
        // This is what you read from a binary that died without writing
        // anything.
        assert!(Bootstrap::from_line("").is_err());
        assert!(Ready::from_line("").is_err());
    }

    #[test]
    fn the_ready_travels_as_a_single_json_line() {
        let line = sample_ready().to_line().unwrap();
        assert!(!line.contains('\n'));
        let round_tripped = Ready::from_line(&line).unwrap();
        assert_eq!(round_tripped.pid, 4242);
        assert_eq!(round_tripped.capabilities, vec!["source".to_string()]);
    }

    #[test]
    fn a_ready_with_the_wrong_magic_is_rejected() {
        let mut r = sample_ready();
        r.magic = "I-AM-NOT-A-PLUGIN".into();
        let line = serde_json::to_string(&r).unwrap();
        assert!(matches!(
            Ready::from_line(&line).unwrap_err(),
            HandshakeError::BadMagic
        ));
    }

    #[test]
    fn surrounding_whitespace_and_newlines_do_not_get_in_the_way() {
        // A plugin in another language may write with println and leave \r\n.
        let line = sample_ready().to_line().unwrap();
        let dirty = format!("  {line}\r\n");
        assert_eq!(Ready::from_line(&dirty).unwrap().pid, 4242);
    }

    #[test]
    fn the_plugin_picks_a_version_the_core_supports() {
        let b = sample_bootstrap();
        assert_eq!(b.negotiate(&[1, 2]).unwrap(), 1);
    }

    #[test]
    fn the_highest_common_version_is_chosen() {
        let mut b = sample_bootstrap();
        b.core_protocol_versions = vec![1, 2, 3];
        assert_eq!(b.negotiate(&[1, 2]).unwrap(), 2);
    }

    #[test]
    fn with_no_version_in_common_it_fails_with_a_useful_message() {
        let mut b = sample_bootstrap();
        b.core_protocol_versions = vec![3, 4];
        let err = b.negotiate(&[1, 2]).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains('3'),
            "the message must say what the core asks for"
        );
        assert!(text.contains('1'), "and what the plugin offers");
    }

    #[test]
    fn a_plugin_with_no_versions_negotiates_nothing() {
        let b = sample_bootstrap();
        assert!(b.negotiate(&[]).is_err());
    }

    #[test]
    fn a_core_with_no_versions_negotiates_nothing() {
        let mut b = sample_bootstrap();
        b.core_protocol_versions = vec![];
        assert!(b.negotiate(&[1]).is_err());
    }

    #[test]
    fn the_bootstrap_does_not_reveal_the_private_key_when_printed() {
        // This struct holds the server's key. If somebody logs it to debug a
        // plugin startup, it must not leak.
        let text = format!("{:?}", sample_bootstrap());
        assert!(
            !text.contains("KEY"),
            "the private key must not appear in Debug"
        );
    }

    #[test]
    fn the_bootstrap_json_does_carry_the_key() {
        // The converse of the previous test: redacting Debug must not have
        // broken serialization, or the plugin would never receive its key.
        let line = sample_bootstrap().to_line().unwrap();
        assert!(line.contains("KEY"));
    }

    #[test]
    fn the_bootstrap_carries_the_tls_names_for_plugins_in_other_languages() {
        // A plugin in Go or Python cannot import SERVER_NAME/CLIENT_NAME from
        // the Rust crate. Without these fields it would have to parse the
        // certificate's DER just to know who to authorize.
        let b = Bootstrap::new(
            vec![1],
            "/tmp/x.sock".into(),
            crate::pki::ServerBundle {
                ca_cert_pem: "CA".into(),
                server_cert_pem: "CERT".into(),
                server_key_pem: "KEY".into(),
            },
        );
        assert_eq!(b.server_name, crate::pki::SERVER_NAME);
        assert_eq!(b.client_name, crate::pki::CLIENT_NAME);
    }

    #[test]
    fn the_bootstrap_declares_its_own_envelope_version() {
        let b = sample_bootstrap();
        assert_eq!(b.handshake_version, HANDSHAKE_VERSION);
    }

    #[test]
    fn the_bootstrap_announces_how_long_the_plugin_has_to_start_up() {
        // Without this the timing contract is one-sided: the plugin has no idea
        // whether it will be killed before it finishes opening its socket.
        let b = sample_bootstrap();
        assert!(b.ready_timeout_ms > 0);
    }

    #[test]
    fn an_envelope_from_a_future_version_is_rejected() {
        // A newer core might add mandatory fields. Better for the old plugin to
        // say so at startup than to fail later and worse.
        let mut b = sample_bootstrap();
        b.handshake_version = HANDSHAKE_VERSION + 1;
        let line = serde_json::to_string(&b).unwrap();
        assert!(matches!(
            Bootstrap::from_line(&line).unwrap_err(),
            HandshakeError::UnsupportedEnvelope { .. }
        ));
    }

    #[test]
    fn the_envelope_error_states_both_versions() {
        let mut b = sample_bootstrap();
        b.handshake_version = 77;
        let text = Bootstrap::from_line(&serde_json::to_string(&b).unwrap())
            .unwrap_err()
            .to_string();
        assert!(text.contains("77"), "it must say which version arrived");
        assert!(
            text.contains(&HANDSHAKE_VERSION.to_string()),
            "and which one is understood"
        );
    }

    #[test]
    fn a_bootstrap_without_the_new_fields_still_deserializes() {
        // Backwards compatibility: the new fields are #[serde(default)], so an
        // older envelope does not break. This is the property that lets the
        // protocol evolve without breaking published plugins.
        let json = r#"{
            "magic": "SHIELDBK_PLUGIN",
            "core_protocol_versions": [1],
            "control_socket": "/tmp/x.sock",
            "tls": {"ca_cert_pem":"CA","server_cert_pem":"CERT","server_key_pem":"KEY"}
        }"#;
        let b = Bootstrap::from_line(json).unwrap();
        assert_eq!(b.control_socket, "/tmp/x.sock");
        assert_eq!(
            b.handshake_version, 0,
            "an envelope with no version declares version 0"
        );
    }

    #[test]
    fn the_new_fields_travel_over_json() {
        let line = sample_bootstrap().to_line().unwrap();
        assert!(line.contains("server_name"));
        assert!(line.contains("client_name"));
        assert!(line.contains("handshake_version"));
        assert!(line.contains("ready_timeout_ms"));
    }

    #[test]
    fn the_constructor_fills_in_the_right_defaults() {
        let b = Bootstrap::new(
            vec![1, 2],
            "/tmp/y.sock".into(),
            crate::pki::ServerBundle {
                ca_cert_pem: "CA".into(),
                server_cert_pem: "CERT".into(),
                server_key_pem: "KEY".into(),
            },
        );
        assert_eq!(b.magic, MAGIC);
        assert_eq!(b.handshake_version, HANDSHAKE_VERSION);
        assert_eq!(b.core_protocol_versions, vec![1, 2]);
        assert_eq!(b.control_socket, "/tmp/y.sock");
        assert!(Bootstrap::from_line(&b.to_line().unwrap()).is_ok());
    }
}
