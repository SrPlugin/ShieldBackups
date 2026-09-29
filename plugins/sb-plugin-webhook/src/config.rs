//! The webhook notifier's configuration schema and the validated configuration.
//!
//! The URL is the whole secret here: Slack, Discord and healthchecks.io all put
//! the credential inside it. That is why it is declared `secret` (the core then
//! only accepts it from a credential store, never as a literal in the TOML) and
//! why nothing in this crate ever formats it into a message, a log line or a
//! `Debug`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use sb_plugin_sdk::Configured;
use sb_plugin_sdk::sb_proto::{Field, FieldType, Value, value::Kind};
use sb_plugin_sdk::tonic::Status;
use ureq::http::Uri;

pub const FIELD_URL: &str = "url";
pub const FIELD_FORMAT: &str = "format";
pub const FIELD_TIMEOUT_SECS: &str = "timeout_secs";
pub const FIELD_ALLOW_HTTP: &str = "allow_http";

const DEFAULT_TIMEOUT_SECS: i64 = 10;
const MAX_TIMEOUT_SECS: i64 = 60;

/// What can go wrong when reading the configuration.
///
/// No variant carries the URL, not even a fragment of it: an error ends up in
/// the core's log, and a log with a webhook token in it is a leak.
#[derive(Debug, thiserror::Error)]
pub enum WebhookConfigError {
    #[error("the required field `{FIELD_URL}` is missing")]
    MissingUrl,
    #[error("the field `{field}` must be {expected}")]
    WrongType {
        field: &'static str,
        expected: &'static str,
    },
    #[error("`{FIELD_URL}` is not a valid absolute URL")]
    InvalidUrl,
    #[error(
        "`{FIELD_URL}` must use `https://`; `http://` is only accepted for localhost or with `{FIELD_ALLOW_HTTP} = true`"
    )]
    InsecureUrl,
    #[error("`{FIELD_FORMAT}` only accepts `json`, `slack` or `discord`")]
    UnknownFormat,
    #[error("`{FIELD_TIMEOUT_SECS}` must be between 1 and {MAX_TIMEOUT_SECS}, and it is {value}")]
    TimeoutOutOfRange { value: i64 },
}

/// A configuration error is always the fault of what the core sent, so it
/// travels as `invalid_argument` and not as an internal failure.
impl From<WebhookConfigError> for Status {
    fn from(e: WebhookConfigError) -> Self {
        Self::invalid_argument(e.to_string())
    }
}

/// Body shape of the notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    /// The report exactly as the core produced it.
    Json,
    /// `{"text": <summary>}`, what a Slack incoming webhook expects.
    Slack,
    /// `{"content": <summary>}`, what a Discord webhook expects.
    Discord,
}

impl Format {
    fn parse(value: &str) -> Result<Self, WebhookConfigError> {
        match value {
            "json" => Ok(Self::Json),
            "slack" => Ok(Self::Slack),
            "discord" => Ok(Self::Discord),
            _ => Err(WebhookConfigError::UnknownFormat),
        }
    }
}

/// The fields the plugin accepts, exactly as `Schema` publishes them.
#[must_use]
pub fn schema() -> Vec<Field> {
    let field = |name: &str, ty, required, secret, description: &str, default: &str| Field {
        name: name.into(),
        r#type: ty as i32,
        required,
        secret,
        description: description.into(),
        default_value: default.into(),
    };
    vec![
        field(
            FIELD_URL,
            FieldType::String,
            true,
            true,
            "Webhook URL; it carries the token, so it must come from a secret reference",
            "",
        ),
        field(
            FIELD_FORMAT,
            FieldType::String,
            false,
            false,
            "Body shape: `json` (the raw report), `slack` or `discord`",
            "json",
        ),
        field(
            FIELD_TIMEOUT_SECS,
            FieldType::Int,
            false,
            false,
            "Seconds to wait for the whole request, from 1 to 60",
            &DEFAULT_TIMEOUT_SECS.to_string(),
        ),
        field(
            FIELD_ALLOW_HTTP,
            FieldType::Bool,
            false,
            false,
            "Accept a plain `http://` URL for a non-local host",
            "false",
        ),
    ]
}

/// The notifier's configuration, already validated. It only exists if
/// `Configure` was accepted.
#[derive(Clone)]
pub struct WebhookConfig {
    url: String,
    pub format: Format,
    pub timeout: Duration,
}

impl WebhookConfig {
    /// Validates the `ConfigureRequest` map and returns the configuration.
    ///
    /// # Errors
    ///
    /// [`WebhookConfigError`] if the URL is missing, malformed or insecure, if
    /// a field has the wrong type, or if `format` or `timeout_secs` is out of
    /// range.
    pub fn from_values(values: &HashMap<String, Value>) -> Result<Self, WebhookConfigError> {
        let allow_http = match kind(values, FIELD_ALLOW_HTTP) {
            None => false,
            Some(Kind::BoolValue(b)) => *b,
            Some(_) => return Err(wrong_type(FIELD_ALLOW_HTTP, "a boolean")),
        };
        // Trimmed: a secret read from a file usually ends in a newline, which
        // would otherwise be an "invalid URL" the user cannot see.
        let url = match string(values, FIELD_URL)? {
            Some(u) => u.trim().to_string(),
            None => return Err(WebhookConfigError::MissingUrl),
        };
        check_url(&url, allow_http)?;

        let format = match string(values, FIELD_FORMAT)? {
            Some(f) => Format::parse(f)?,
            None => Format::Json,
        };
        let secs = match kind(values, FIELD_TIMEOUT_SECS) {
            None => DEFAULT_TIMEOUT_SECS,
            Some(Kind::IntValue(v)) => *v,
            Some(_) => return Err(wrong_type(FIELD_TIMEOUT_SECS, "an integer")),
        };
        let timeout = u64::try_from(secs)
            .ok()
            .filter(|s| (1..=MAX_TIMEOUT_SECS.unsigned_abs()).contains(s))
            .map(Duration::from_secs)
            .ok_or(WebhookConfigError::TimeoutOutOfRange { value: secs })?;

        Ok(Self {
            url,
            format,
            timeout,
        })
    }

    /// The URL to POST to. Deliberately the only way out of the struct, and it
    /// is only meant for the HTTP client.
    pub(crate) fn url(&self) -> &str {
        &self.url
    }
}

/// Hand-written `Debug`: deriving it would print the URL, and with it the token.
impl std::fmt::Debug for WebhookConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookConfig")
            .field("url", &"<redacted>")
            .field("format", &self.format)
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// The configuration `Configure` leaves behind and `Notify` reads.
pub type State = Configured<WebhookConfig>;

/// Accepts `https://` anywhere, and `http://` only when the operator opted in
/// or the host cannot leave the machine.
///
/// The token travels in the URL, so plain HTTP to a remote host would hand it to
/// every hop on the path. Loopback is exempt because that is where a
/// self-hosted healthchecks or a test server lives, and nothing crosses a
/// network to get there.
fn check_url(value: &str, allow_http: bool) -> Result<(), WebhookConfigError> {
    let uri: Uri = value.parse().map_err(|_| WebhookConfigError::InvalidUrl)?;
    let host = uri.host().ok_or(WebhookConfigError::InvalidUrl)?;
    match uri.scheme_str() {
        Some("https") => Ok(()),
        Some("http") if allow_http || is_loopback(host) => Ok(()),
        // Plain HTTP to a remote host, or any other scheme (`ftp`, `file`...):
        // neither is a webhook this plugin will talk to.
        Some(_) => Err(WebhookConfigError::InsecureUrl),
        None => Err(WebhookConfigError::InvalidUrl),
    }
}

/// `localhost`, or an IP literal that is loopback. Nothing that needs a DNS
/// lookup beyond `localhost` qualifies: a name can be pointed anywhere.
fn is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    // `Uri::host` keeps the brackets of an IPv6 literal.
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

fn kind<'a>(values: &'a HashMap<String, Value>, field: &str) -> Option<&'a Kind> {
    values.get(field).and_then(|v| v.kind.as_ref())
}

fn wrong_type(field: &'static str, expected: &'static str) -> WebhookConfigError {
    WebhookConfigError::WrongType { field, expected }
}

/// Reads an optional string. An empty string counts as absent: a field set to
/// `""` in the TOML is a field the user never got round to filling in.
fn string<'a>(
    values: &'a HashMap<String, Value>,
    field: &'static str,
) -> Result<Option<&'a str>, WebhookConfigError> {
    match kind(values, field) {
        None => Ok(None),
        Some(Kind::StringValue(s)) if s.is_empty() => Ok(None),
        Some(Kind::StringValue(s)) => Ok(Some(s)),
        Some(_) => Err(wrong_type(field, "a string")),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use sb_plugin_sdk::tonic::Code;

    fn value(kind: Kind) -> Value {
        Value { kind: Some(kind) }
    }

    fn with(url: &str) -> HashMap<String, Value> {
        HashMap::from([(
            FIELD_URL.to_string(),
            value(Kind::StringValue(url.to_string())),
        )])
    }

    fn accepted(url: &str) -> bool {
        WebhookConfig::from_values(&with(url)).is_ok()
    }

    #[test]
    fn the_url_is_the_only_required_field_and_it_is_secret() {
        let fields = schema();
        for f in &fields {
            assert_eq!(f.required, f.name == FIELD_URL, "`{}`", f.name);
            assert_eq!(f.secret, f.name == FIELD_URL, "`{}`", f.name);
            assert!(!f.description.is_empty(), "`{}` has no description", f.name);
        }
    }

    #[test]
    fn a_missing_or_empty_url_is_rejected() {
        let e = WebhookConfig::from_values(&HashMap::new()).unwrap_err();
        assert!(matches!(e, WebhookConfigError::MissingUrl));
        assert!(matches!(
            WebhookConfig::from_values(&with("")).unwrap_err(),
            WebhookConfigError::MissingUrl
        ));
    }

    #[test]
    fn https_is_accepted() {
        assert!(accepted("https://hooks.slack.com/services/T0/B0/token"));
    }

    #[test]
    fn plain_http_to_a_remote_host_is_rejected() {
        let e =
            WebhookConfig::from_values(&with("http://example.com/hook/secret-token")).unwrap_err();
        assert!(matches!(e, WebhookConfigError::InsecureUrl));
    }

    #[test]
    fn plain_http_is_accepted_for_every_loopback_spelling() {
        for url in [
            "http://localhost:8080/ping/abc",
            "http://LOCALHOST/ping/abc",
            "http://127.0.0.1:9/ping/abc",
            "http://127.8.9.10/ping/abc",
            "http://[::1]:8080/ping/abc",
        ] {
            assert!(accepted(url), "{url} should be accepted");
        }
    }

    #[test]
    fn names_that_merely_look_local_are_not_loopback() {
        // A name can resolve anywhere; only the literal `localhost` is trusted.
        for url in [
            "http://localhost.example.com/x",
            "http://127.0.0.1.example.com/x",
            "http://notlocalhost/x",
            "http://128.0.0.1/x",
        ] {
            assert!(!accepted(url), "{url} should be rejected");
        }
    }

    #[test]
    fn allow_http_lets_a_remote_http_url_through() {
        let mut m = with("http://hc.internal.example/ping/abc");
        m.insert(FIELD_ALLOW_HTTP.into(), value(Kind::BoolValue(true)));
        assert!(WebhookConfig::from_values(&m).is_ok());
        m.insert(FIELD_ALLOW_HTTP.into(), value(Kind::BoolValue(false)));
        assert!(WebhookConfig::from_values(&m).is_err());
    }

    #[test]
    fn allow_http_does_not_open_any_other_scheme() {
        for url in [
            "ftp://example.com/x",
            "file:///etc/passwd",
            "gopher://example.com/x",
            "ws://example.com/x",
            "example.com/hook",
            "/just/a/path",
            "https://",
            "not a url",
        ] {
            let mut m = with(url);
            m.insert(FIELD_ALLOW_HTTP.into(), value(Kind::BoolValue(true)));
            assert!(
                WebhookConfig::from_values(&m).is_err(),
                "{url} should be rejected"
            );
        }
    }

    #[test]
    fn a_trailing_newline_from_a_secret_file_is_tolerated() {
        let c = WebhookConfig::from_values(&with("https://example.com/hook\n")).unwrap();
        assert_eq!(c.url(), "https://example.com/hook");
    }

    #[test]
    fn no_error_message_contains_the_url() {
        let secret = "s3cr3t-t0ken";
        for url in [
            format!("http://example.com/{secret}"),
            format!("ftp://example.com/{secret}"),
            format!("not a url {secret}"),
        ] {
            let e = WebhookConfig::from_values(&with(&url)).unwrap_err();
            assert!(!e.to_string().contains(secret), "{e}");
            let status = Status::from(e);
            assert_eq!(status.code(), Code::InvalidArgument);
            assert!(!status.message().contains(secret));
        }
    }

    #[test]
    fn debug_redacts_the_url() {
        let c = WebhookConfig::from_values(&with("https://example.com/s3cr3t")).unwrap();
        assert!(!format!("{c:?}").contains("s3cr3t"));
    }

    #[test]
    fn the_defaults_are_json_and_ten_seconds() {
        let c = WebhookConfig::from_values(&with("https://example.com/x")).unwrap();
        assert_eq!(c.format, Format::Json);
        assert_eq!(c.timeout, Duration::from_secs(10));
    }

    #[test]
    fn the_three_formats_parse() {
        for (name, want) in [
            ("json", Format::Json),
            ("slack", Format::Slack),
            ("discord", Format::Discord),
        ] {
            let mut m = with("https://example.com/x");
            m.insert(FIELD_FORMAT.into(), value(Kind::StringValue(name.into())));
            assert_eq!(WebhookConfig::from_values(&m).unwrap().format, want);
        }
    }

    #[test]
    fn an_unknown_format_names_the_valid_ones() {
        let mut m = with("https://example.com/x");
        m.insert(
            FIELD_FORMAT.into(),
            value(Kind::StringValue("teams".into())),
        );
        let msg = WebhookConfig::from_values(&m).unwrap_err().to_string();
        for valid in ["json", "slack", "discord"] {
            assert!(msg.contains(valid), "{msg}");
        }
    }

    #[test]
    fn the_timeout_is_limited_to_one_through_sixty() {
        for (secs, ok) in [(0, false), (1, true), (60, true), (61, false), (-5, false)] {
            let mut m = with("https://example.com/x");
            m.insert(FIELD_TIMEOUT_SECS.into(), value(Kind::IntValue(secs)));
            assert_eq!(WebhookConfig::from_values(&m).is_ok(), ok, "{secs}");
        }
    }

    #[test]
    fn fields_of_the_wrong_type_are_rejected() {
        for (field, kind) in [
            (FIELD_URL, Kind::IntValue(1)),
            (FIELD_FORMAT, Kind::BoolValue(true)),
            (FIELD_TIMEOUT_SECS, Kind::StringValue("10".into())),
            (FIELD_ALLOW_HTTP, Kind::StringValue("true".into())),
        ] {
            let mut m = with("https://example.com/x");
            m.insert(field.into(), value(kind));
            assert!(
                matches!(
                    WebhookConfig::from_values(&m),
                    Err(WebhookConfigError::WrongType { .. })
                ),
                "{field}"
            );
        }
    }
}
