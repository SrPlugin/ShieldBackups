//! Building the notification body and delivering it.
//!
//! Every failure here is reduced to a short fixed phrase on purpose. The
//! HTTP client's own error text can embed the request URL, and the URL carries
//! the webhook token, so that text is never formatted anywhere.

use std::io::ErrorKind;

use ureq::Error;

use crate::config::{Format, WebhookConfig};

/// Longest summary sent, in characters. Slack and Discord truncate or reject
/// long messages (Discord's limit is 2000), and an error can be a whole stack
/// of context: the head of it is what tells you what happened.
const MAX_SUMMARY_CHARS: usize = 1500;

/// One short line: `shieldbk backup: ok` or `shieldbk backup FAILED: <error>`.
///
/// The error is read from the report rather than passed by the core because the
/// report is the one document whose shape is a public contract; if it cannot be
/// parsed the line still says the command failed.
pub fn summary(command: &str, ok: bool, report_json: &str) -> String {
    let mut line = if ok {
        format!("shieldbk {command}: ok")
    } else {
        let error = serde_json::from_str::<serde_json::Value>(report_json)
            .ok()
            .and_then(|r| r.get("error")?.as_str().map(str::to_owned));
        match error {
            Some(e) => format!("shieldbk {command} FAILED: {e}"),
            None => format!("shieldbk {command} FAILED"),
        }
    };
    // Cut on a character boundary: slicing at a byte offset would panic in the
    // middle of a multibyte character.
    if let Some((cut, _)) = line.char_indices().nth(MAX_SUMMARY_CHARS) {
        line.truncate(cut);
    }
    line
}

/// The request body for the configured format.
pub fn body(format: Format, command: &str, ok: bool, report_json: &str) -> String {
    match format {
        // Byte for byte: whoever consumes it parses the contract of `--format json`.
        Format::Json => report_json.to_string(),
        Format::Slack => {
            serde_json::json!({ "text": summary(command, ok, report_json) }).to_string()
        }
        Format::Discord => {
            serde_json::json!({ "content": summary(command, ok, report_json) }).to_string()
        }
    }
}

/// POSTs `body` to the configured URL and returns a URL-free message on failure.
///
/// Blocking: call it from `spawn_blocking`.
///
/// Redirects are **not** followed: a `3xx` would forward the body -- the report
/// and, through the `Location`, possibly the token -- to a host the operator
/// never configured, so it is reported as a failure like any other non-2xx.
/// The response body is never read, so nothing the remote says can be echoed.
pub fn post(config: &WebhookConfig, body: String) -> Result<(), String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .max_redirects(0)
        .timeout_global(Some(config.timeout))
        // Statuses are judged below; ureq's own `StatusCode` error is not needed.
        .http_status_as_error(false)
        .build()
        .into();
    let response = agent
        .post(config.url())
        .header("Content-Type", "application/json")
        .send(body)
        .map_err(|e| format!("could not reach the webhook ({})", reason(&e)))?;
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("the webhook answered HTTP {}", status.as_u16()))
    }
}

/// A fixed phrase for what went wrong. Never `Display`s the error itself.
fn reason(e: &Error) -> &'static str {
    match e {
        Error::Timeout(_) => "timed out",
        Error::Tls(_) | Error::Rustls(_) => "tls error",
        Error::HostNotFound => "host not found",
        Error::Io(io) => match io.kind() {
            ErrorKind::ConnectionRefused => "connection refused",
            ErrorKind::TimedOut | ErrorKind::WouldBlock => "timed out",
            _ => "connection failed",
        },
        _ => "request failed",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use sb_plugin_sdk::sb_proto::{Value, value::Kind};

    use super::*;

    const REPORT: &str = r#"{"ok":false,"error":"connection to postgres refused"}"#;
    const TOKEN: &str = "s3cr3t-t0ken";

    #[test]
    fn a_successful_run_says_ok() {
        assert_eq!(summary("backup", true, "{}"), "shieldbk backup: ok");
    }

    #[test]
    fn a_failed_run_includes_the_error_from_the_report() {
        assert_eq!(
            summary("backup", false, REPORT),
            "shieldbk backup FAILED: connection to postgres refused"
        );
    }

    #[test]
    fn a_failed_run_with_an_unreadable_report_still_says_failed() {
        assert_eq!(summary("prune", false, "not json"), "shieldbk prune FAILED");
        assert_eq!(summary("prune", false, "{}"), "shieldbk prune FAILED");
        assert_eq!(
            summary("prune", false, r#"{"error":42}"#),
            "shieldbk prune FAILED"
        );
    }

    #[test]
    fn the_summary_is_cut_at_1500_characters_on_a_character_boundary() {
        // Two-byte characters: 1500 of them is 3000 bytes, so a byte-based cut
        // at 1500 would land in the middle of one and panic.
        let report = serde_json::json!({ "error": "é".repeat(3000) }).to_string();
        let s = summary("backup", false, &report);
        assert_eq!(s.chars().count(), MAX_SUMMARY_CHARS);
        assert!(s.ends_with('é'));
        assert!(s.starts_with("shieldbk backup FAILED: "));
    }

    #[test]
    fn a_summary_of_exactly_the_limit_is_left_alone() {
        let prefix = "shieldbk backup FAILED: ";
        let error = "x".repeat(MAX_SUMMARY_CHARS - prefix.len());
        let s = summary("backup", false, &format!(r#"{{"error":"{error}"}}"#));
        assert_eq!(s.chars().count(), MAX_SUMMARY_CHARS);
        assert!(s.ends_with('x'));
    }

    #[test]
    fn the_json_format_sends_the_report_byte_for_byte() {
        let odd = "{ \"ok\" :true,\n  \"n\":1.0 }\n";
        assert_eq!(body(Format::Json, "backup", true, odd), odd);
    }

    #[test]
    fn the_slack_body_is_a_text_object() {
        let b: serde_json::Value =
            serde_json::from_str(&body(Format::Slack, "backup", false, REPORT)).unwrap();
        assert_eq!(
            b,
            serde_json::json!({"text": "shieldbk backup FAILED: connection to postgres refused"})
        );
    }

    #[test]
    fn the_discord_body_is_a_content_object() {
        let b: serde_json::Value =
            serde_json::from_str(&body(Format::Discord, "prune", true, "{}")).unwrap();
        assert_eq!(b, serde_json::json!({"content": "shieldbk prune: ok"}));
    }

    // --- the webhook, played by a socket on loopback -----------------------

    /// What the fake webhook saw.
    struct Captured {
        request_line: String,
        headers: String,
        body: String,
    }

    /// Serves exactly one connection: reads the request, answers `response` (or
    /// stays silent if `None`) and reports what it read. Silent servers wait for
    /// the client to hang up so the thread can be joined.
    fn webhook(response: Option<String>) -> (u16, JoinHandle<Captured>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let captured = read_request(&mut stream);
            match response {
                Some(r) => stream.write_all(r.as_bytes()).unwrap(),
                None => {
                    let _ = stream.read(&mut [0u8; 1]);
                }
            }
            captured
        });
        (port, handle)
    }

    fn read_request(stream: &mut TcpStream) -> Captured {
        let mut raw = Vec::new();
        let mut buf = [0u8; 1024];
        let head_end = loop {
            let n = stream.read(&mut buf).unwrap();
            raw.extend_from_slice(&buf[..n]);
            if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            assert!(n > 0, "client closed before finishing the headers");
        };
        let head = String::from_utf8(raw[..head_end].to_vec()).unwrap();
        let length: usize = head
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length:")?
                    .trim()
                    .parse()
                    .ok()
            })
            .unwrap_or(0);
        while raw.len() < head_end + length {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0, "client closed before finishing the body");
            raw.extend_from_slice(&buf[..n]);
        }
        let (request_line, headers) = head.split_once("\r\n").unwrap();
        Captured {
            request_line: request_line.to_string(),
            headers: headers.to_ascii_lowercase(),
            body: String::from_utf8(raw[head_end..head_end + length].to_vec()).unwrap(),
        }
    }

    fn config(port: u16, format: &str, timeout_secs: i64) -> WebhookConfig {
        let text = |s: &str| Value {
            kind: Some(Kind::StringValue(s.into())),
        };
        WebhookConfig::from_values(&HashMap::from([
            (
                "url".to_string(),
                text(&format!("http://127.0.0.1:{port}/hook/{TOKEN}")),
            ),
            ("format".to_string(), text(format)),
            (
                "timeout_secs".to_string(),
                Value {
                    kind: Some(Kind::IntValue(timeout_secs)),
                },
            ),
        ]))
        .unwrap()
    }

    #[allow(clippy::unnecessary_wraps)] // matches the `Option` that `webhook` takes
    fn reply(status_line: &str) -> Option<String> {
        Some(format!(
            "HTTP/1.1 {status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ))
    }

    fn deliver(format: &str, ok: bool, report: &str) -> Captured {
        let (port, server) = webhook(reply("200 OK"));
        let c = config(port, format, 5);
        post(&c, body(c.format, "backup", ok, report)).unwrap();
        server.join().unwrap()
    }

    #[test]
    fn json_is_posted_verbatim_with_a_json_content_type() {
        let seen = deliver("json", false, REPORT);
        assert_eq!(seen.request_line, format!("POST /hook/{TOKEN} HTTP/1.1"));
        assert!(
            seen.headers.contains("content-type: application/json"),
            "{}",
            seen.headers
        );
        assert_eq!(seen.body, REPORT);
    }

    #[test]
    fn slack_is_posted_as_a_text_object() {
        let seen = deliver("slack", true, "{}");
        assert!(seen.request_line.starts_with("POST "));
        assert!(seen.headers.contains("content-type: application/json"));
        assert_eq!(seen.body, r#"{"text":"shieldbk backup: ok"}"#);
    }

    #[test]
    fn discord_is_posted_as_a_content_object() {
        let seen = deliver("discord", false, REPORT);
        assert!(seen.request_line.starts_with("POST "));
        assert_eq!(
            seen.body,
            r#"{"content":"shieldbk backup FAILED: connection to postgres refused"}"#
        );
    }

    #[test]
    fn any_2xx_is_a_success() {
        let (port, server) = webhook(reply("204 No Content"));
        let c = config(port, "json", 5);
        assert!(post(&c, "{}".into()).is_ok());
        server.join().unwrap();
    }

    #[test]
    fn a_500_is_an_error_that_does_not_contain_the_url() {
        let (port, server) = webhook(reply("500 Internal Server Error"));
        let e = post(&config(port, "json", 5), "{}".into()).unwrap_err();
        server.join().unwrap();
        assert_eq!(e, "the webhook answered HTTP 500");
        assert!(!e.contains(TOKEN) && !e.contains("127.0.0.1"), "{e}");
    }

    #[test]
    fn the_response_body_is_never_echoed() {
        let body = "SECRET-FROM-THE-REMOTE";
        let (port, server) = webhook(Some(format!(
            "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )));
        let e = post(&config(port, "json", 5), "{}".into()).unwrap_err();
        server.join().unwrap();
        assert_eq!(e, "the webhook answered HTTP 404");
    }

    #[test]
    fn a_redirect_is_not_followed_and_counts_as_a_failure() {
        // If the client followed the `Location`, the body would land here.
        let elsewhere = TcpListener::bind("127.0.0.1:0").unwrap();
        elsewhere.set_nonblocking(true).unwrap();
        let elsewhere_port = elsewhere.local_addr().unwrap().port();
        for status in [
            "301 Moved Permanently",
            "302 Found",
            "307 Temporary Redirect",
        ] {
            let (port, server) = webhook(Some(format!(
                "HTTP/1.1 {status}\r\nLocation: http://127.0.0.1:{elsewhere_port}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )));
            let e = post(&config(port, "json", 5), "{}".into()).unwrap_err();
            server.join().unwrap();
            assert_eq!(e, format!("the webhook answered HTTP {}", &status[..3]));
            assert_eq!(
                elsewhere.accept().unwrap_err().kind(),
                ErrorKind::WouldBlock,
                "the redirect target was contacted after {status}"
            );
        }
    }

    #[test]
    fn a_silent_server_hits_the_timeout() {
        let (port, server) = webhook(None);
        let started = std::time::Instant::now();
        let e = post(&config(port, "json", 1), "{}".into()).unwrap_err();
        assert_eq!(e, "could not reach the webhook (timed out)");
        assert!(started.elapsed() < Duration::from_secs(5));
        server.join().unwrap();
    }

    #[test]
    fn a_closed_port_is_a_connection_refused_without_the_url() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let e = post(&config(port, "json", 5), "{}".into()).unwrap_err();
        assert_eq!(e, "could not reach the webhook (connection refused)");
        assert!(!e.contains(TOKEN) && !e.contains("127.0.0.1"), "{e}");
    }
}
