//! Templates for the key under which an artifact is stored in the destination.
//!
//! A key is written with placeholders in braces, for example
//! `{target}/{yyyy}/{mm}/{dd}/{target}-{timestamp}-{source}.dump.zst.age`, and
//! [`render`] replaces them with the values of a [`NamingContext`].
//!
//! The destination may be a file system (the local disk plugin), so the
//! resulting key is validated before being returned: a template —or a target
//! name, which also comes from the user's configuration— cannot end up writing
//! outside the backup directory.

use time::OffsetDateTime;

/// Placeholders that [`render`] knows how to substitute. It is also used to
/// build the error message when a template names one that does not exist:
/// whoever gets a template wrong needs to see the list, not just a "no".
const PLACEHOLDERS: [&str; 7] = [
    "target",
    "source",
    "storage",
    "timestamp",
    "yyyy",
    "mm",
    "dd",
];

/// Maximum length of a key, in **bytes**.
///
/// It is the limit of S3 and of Cloudflare R2, the most restrictive of the
/// intended destinations: local disk and SFTP accept longer paths, but a key
/// that only works for some destinations is not a portable key. It is measured
/// in bytes and not in characters because that is how the destination measures
/// it: a name of 600 accented letters takes 1200 bytes.
///
/// Rejecting it here prevents the backup from failing —or the key from being
/// silently truncated— halfway through the upload.
pub const MAX_KEY_BYTES: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum NamingError {
    #[error(
        "the template uses the placeholder \"{placeholder}\", which does not exist. The valid \
         placeholders are: {valid}"
    )]
    UnknownPlaceholder { placeholder: String, valid: String },
    #[error("the key \"{key}\" cannot be used: {reason}")]
    UnsafeKey { key: String, reason: String },
}

/// Values with which a template is filled in.
///
/// The three date fields (`year`, `month`, `day`) are deliberately redundant
/// with `timestamp`: they allow partitioning the destination into folders
/// without the template having to slice the timestamp apart.
#[derive(Debug, Clone)]
pub struct NamingContext {
    pub target: String,
    pub source: String,
    pub storage: String,
    pub timestamp: String,
    pub year: String,
    pub month: String,
    pub day: String,
}

impl NamingContext {
    /// Builds the context for a backup started at `epoch_secs`.
    ///
    /// `epoch_secs` is UTC. Local time is never used: a nightly backup cannot
    /// change its name because the server changes time zone or enters daylight
    /// saving time, and two replicas in different time zones have to produce the
    /// same key for the same instant.
    ///
    /// The timestamp is formatted as `YYYYMMDDTHHMMSSZ`. If `epoch_secs` falls
    /// outside the range of representable dates —only with a clock broken by
    /// tens of thousands of years— it falls back to the epoch: a visibly absurd
    /// key is preferable to a panic in the middle of a backup.
    #[must_use]
    pub fn new(target: &str, source: &str, storage: &str, epoch_secs: i64) -> Self {
        let date =
            OffsetDateTime::from_unix_timestamp(epoch_secs).unwrap_or(OffsetDateTime::UNIX_EPOCH);
        let year = format!("{:04}", date.year());
        let month = format!("{:02}", u8::from(date.month()));
        let day = format!("{:02}", date.day());
        let timestamp = format!(
            "{year}{month}{day}T{:02}{:02}{:02}Z",
            date.hour(),
            date.minute(),
            date.second()
        );
        Self {
            target: target.to_owned(),
            source: source.to_owned(),
            storage: storage.to_owned(),
            timestamp,
            year,
            month,
            day,
        }
    }

    /// Value of a placeholder, or `None` if the name is not one of the valid
    /// ones.
    fn value(&self, placeholder: &str) -> Option<&str> {
        Some(match placeholder {
            "target" => &self.target,
            "source" => &self.source,
            "storage" => &self.storage,
            "timestamp" => &self.timestamp,
            "yyyy" => &self.year,
            "mm" => &self.month,
            "dd" => &self.day,
            _ => return None,
        })
    }
}

/// Fills `template` with the values of `ctx` and returns the artifact's key.
///
/// A `{` without its `}` is not a template but a typo, and it is treated as
/// literal text: rejecting the whole backup over that would be
/// disproportionate, as long as the resulting key is still safe.
///
/// Validation is done on the **already filled** key, not on the template: the
/// target's name comes from the user's configuration, so a target called `..` is
/// as dangerous as a `..` written by hand in the template.
///
/// # Limitation: one-second resolution
///
/// `{timestamp}` has one-second resolution. Two backups of the same target
/// started within the same second produce **the same key**, and the second one
/// would overwrite the first in the destination. It is not fixed here:
/// uniqueness is a property of the template, and whoever composes it can add a
/// placeholder that guarantees it. What this function promises is that the
/// substitution is deterministic, not that the result is unique.
///
/// # Errors
///
/// - [`NamingError::UnknownPlaceholder`] if the template names a placeholder
///   that is not on the list of valid ones.
/// - [`NamingError::UnsafeKey`] if the resulting key is empty, is absolute,
///   contains `\`, contains any control character, takes more than
///   [`MAX_KEY_BYTES`], or if any of its `/`-separated segments is empty or is
///   exactly `.` or `..`.
pub fn render(template: &str, ctx: &NamingContext) -> Result<String, NamingError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after_brace = &rest[open + 1..];
        if let Some(close) = after_brace.find('}') {
            let name = &after_brace[..close];
            let value = ctx
                .value(name)
                .ok_or_else(|| NamingError::UnknownPlaceholder {
                    placeholder: name.to_owned(),
                    valid: PLACEHOLDERS.join(", "),
                })?;
            out.push_str(value);
            rest = &after_brace[close + 1..];
        } else {
            out.push('{');
            rest = after_brace;
        }
    }
    out.push_str(rest);

    validate(&out)?;
    Ok(out)
}

/// Checks that an already filled key can be handed to a destination without it
/// writing where it should not.
fn validate(key: &str) -> Result<(), NamingError> {
    let unsafe_key = |reason: &str| NamingError::UnsafeKey {
        key: key.to_owned(),
        reason: reason.to_owned(),
    };

    if key.is_empty() {
        return Err(unsafe_key("an empty key does not identify any artifact"));
    }
    if key.starts_with('/') {
        return Err(unsafe_key(
            "it starts with \"/\", and an absolute key writes outside the backup directory when \
             the destination is a file system",
        ));
    }
    if key.contains('\\') {
        return Err(unsafe_key(
            "it contains \"\\\", which on a Windows destination opens hierarchy just like \"/\"",
        ));
    }
    if key.contains('\0') {
        return Err(unsafe_key(
            "it contains a null byte, which truncates the path in the system APIs and would leave \
             the artifact somewhere other than what the key says",
        ));
    }
    // The C0 range (U+0000-U+001F), U+007F and C1 (U+0080-U+009F). The null byte
    // is already checked above because its message is more specific; the rest
    // falls in here.
    if let Some(control) = key
        .chars()
        .find(|c| matches!(*c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}'))
    {
        return Err(unsafe_key(&format!(
            "it contains the control character U+{:04X}. The key travels in the headers of the \
             request to the object storage, and a line break there injects headers into the \
             request",
            control as u32
        )));
    }
    if key.len() > MAX_KEY_BYTES {
        return Err(unsafe_key(&format!(
            "it takes {} bytes and the maximum is {MAX_KEY_BYTES}: that is the limit of S3 and R2, \
             the most restrictive of the intended destinations. Accepting it here would only move \
             the failure to the destination, halfway through the backup",
            key.len()
        )));
    }
    // Only a whole segment is dangerous: "backup..2026.age" is a legitimate
    // name, "backup/../.." goes up two levels. The same goes for ".": artifact
    // names carry dots, but a segment that is just a dot does not.
    for segment in key.split('/') {
        let reason = match segment {
            ".." => {
                "it has a \"..\" segment, which goes up one level and would write outside the \
                 backup directory"
            }
            "." => {
                "it has a \".\" segment, which a file system ignores and object storage keeps: the \
                 same key would point to two different objects depending on the destination"
            }
            "" => {
                "it has an empty segment —two \"/\" in a row, or a trailing \"/\"—, which collapses \
                 on a file system and does not in object storage: two different keys would end up \
                 in the same object and the correspondence between key and artifact would be lost"
            }
            _ => continue,
        };
        return Err(unsafe_key(reason));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> NamingContext {
        NamingContext {
            target: "production".into(),
            source: "postgres".into(),
            storage: "r2".into(),
            timestamp: "20260821T100000Z".into(),
            year: "2026".into(),
            month: "08".into(),
            day: "21".into(),
        }
    }

    #[test]
    fn fills_in_every_placeholder() {
        let template = "{target}/{yyyy}/{mm}/{dd}/{target}-{timestamp}-{source}.dump.zst.age";
        assert_eq!(
            render(template, &context()).unwrap(),
            "production/2026/08/21/production-20260821T100000Z-postgres.dump.zst.age"
        );
    }

    #[test]
    fn a_placeholder_may_repeat() {
        assert_eq!(
            render("{target}/{target}", &context()).unwrap(),
            "production/production"
        );
    }

    #[test]
    fn the_storage_placeholder_also_works() {
        assert_eq!(render("{storage}/x", &context()).unwrap(), "r2/x");
    }

    #[test]
    fn a_template_without_placeholders_is_returned_as_is() {
        assert_eq!(render("fixed.bin", &context()).unwrap(), "fixed.bin");
    }

    #[test]
    fn an_empty_template_is_rejected() {
        // An empty key identifies nothing.
        assert!(render("", &context()).is_err());
    }

    #[test]
    fn an_unknown_placeholder_is_rejected() {
        let err = render("{target}/{invented}", &context()).err().unwrap();
        let text = err.to_string();
        assert!(text.contains("invented"));
        assert!(text.contains("target"), "it must list the valid ones");
    }

    #[test]
    fn an_unclosed_brace_is_literal_text() {
        // It is a typo, not a template; better to treat it as text than to
        // reject it, as long as the result is a safe key.
        assert_eq!(
            render("file{unclosed", &context()).unwrap(),
            "file{unclosed"
        );
    }

    #[test]
    fn a_template_that_escapes_the_prefix_is_rejected() {
        // The destination may be a file system: a `..` would write outside the
        // backup directory.
        assert!(matches!(
            render("{target}/../../other", &context()).err().unwrap(),
            NamingError::UnsafeKey { .. }
        ));
    }

    #[test]
    fn a_leading_dot_dot_is_rejected() {
        assert!(render("../outside", &context()).is_err());
    }

    #[test]
    fn a_trailing_dot_dot_is_rejected() {
        assert!(render("{target}/..", &context()).is_err());
    }

    #[test]
    fn a_name_containing_two_dots_without_being_a_segment_is_accepted() {
        // ".." is only dangerous as a whole segment; "backup..2026" is not.
        assert!(render("backup..2026.age", &context()).is_ok());
    }

    #[test]
    fn an_absolute_template_is_rejected() {
        assert!(matches!(
            render("/absolute/{target}", &context()).err().unwrap(),
            NamingError::UnsafeKey { .. }
        ));
    }

    #[test]
    fn a_null_byte_is_rejected() {
        assert!(render("file\0hidden", &context()).is_err());
    }

    #[test]
    fn a_backslash_is_rejected() {
        // On a Windows destination it would open hierarchy just like a normal
        // slash.
        assert!(render("folder\\outside", &context()).is_err());
    }

    #[test]
    fn the_context_is_built_from_a_timestamp() {
        let c = NamingContext::new("t", "e", "s", 1_755_770_400);
        assert_eq!(c.year.len(), 4);
        assert_eq!(c.month.len(), 2);
        assert_eq!(c.day.len(), 2);
        assert!(c.timestamp.ends_with('Z'), "the timestamp is UTC");
        assert_eq!(c.timestamp.len(), 16, "YYYYMMDDTHHMMSSZ format");
    }

    #[test]
    fn the_timestamp_is_utc_and_does_not_depend_on_the_local_time_zone() {
        // A nightly backup cannot change its name because the server changes
        // time zone or enters daylight saving time.
        let c = NamingContext::new("t", "e", "s", 0);
        assert_eq!(c.timestamp, "19700101T000000Z");
        assert_eq!(c.year, "1970");
        assert_eq!(c.month, "01");
        assert_eq!(c.day, "01");
    }

    #[test]
    fn the_context_date_matches_the_timestamp() {
        let c = NamingContext::new("t", "e", "s", 1_755_770_400);
        assert!(
            c.timestamp
                .starts_with(&format!("{}{}{}", c.year, c.month, c.day))
        );
    }

    #[test]
    fn two_backups_in_the_same_second_produce_the_same_key() {
        // Documents a real limitation: the default template has one-second
        // resolution. Whoever launches two backups of the same target in the
        // same second would overwrite one with the other.
        let a = NamingContext::new("t", "e", "s", 1_755_770_400);
        let b = NamingContext::new("t", "e", "s", 1_755_770_400);
        assert_eq!(a.timestamp, b.timestamp);
    }

    #[test]
    fn a_carriage_return_is_rejected() {
        // The key travels in HTTP headers towards the object storage: a \r\n is
        // header injection into the request.
        assert!(render("file\rbad", &context()).is_err());
    }

    #[test]
    fn a_line_break_is_rejected() {
        assert!(render("file\nbad", &context()).is_err());
    }

    #[test]
    fn any_control_character_is_rejected() {
        for c in ['\u{1}', '\u{7}', '\u{1b}', '\u{7f}', '\u{9b}'] {
            let template = format!("file{c}bad");
            assert!(
                render(&template, &context()).is_err(),
                "it should reject U+{:04X}",
                c as u32
            );
        }
    }

    #[test]
    fn a_target_name_with_a_line_break_is_also_rejected() {
        // The real vector: the name comes from the user's configuration, not
        // from the template.
        let mut ctx = context();
        ctx.target = "production\r\nX-Injected: yes".into();
        assert!(render("{target}/x.age", &ctx).is_err());
    }

    #[test]
    fn a_key_longer_than_the_s3_limit_is_rejected() {
        // S3 and R2 limit keys to 1024 bytes. Accepting it here would only move
        // the failure to the destination, halfway through a backup.
        let mut ctx = context();
        ctx.target = "a".repeat(2000);
        let err = render("{target}/x.age", &ctx).err().unwrap();
        assert!(matches!(err, NamingError::UnsafeKey { .. }));
        assert!(
            err.to_string().contains("1024"),
            "it must say what the limit is"
        );
    }

    #[test]
    fn a_key_exactly_at_the_limit_is_accepted() {
        let mut ctx = context();
        ctx.target = "a".repeat(1024);
        assert!(render("{target}", &ctx).is_ok());
    }

    #[test]
    fn the_limit_is_measured_in_bytes_not_in_characters() {
        // Names with accents or emoji take more than one byte, and the
        // destination's limit is in bytes.
        let mut ctx = context();
        ctx.target = "\u{f1}".repeat(600); // 1200 bytes in UTF-8
        assert!(render("{target}", &ctx).is_err());
    }

    #[test]
    fn an_empty_segment_is_rejected() {
        // `a//b` and `a/b` are the same path on a file system and two different
        // keys in S3. That ambiguity breaks the correspondence between key and
        // artifact that retention depends on.
        assert!(render("{target}//x.age", &context()).is_err());
    }

    #[test]
    fn a_key_ending_in_a_slash_is_rejected() {
        // It would be a "directory", not an object.
        assert!(render("{target}/", &context()).is_err());
    }

    #[test]
    fn a_segment_of_a_single_dot_is_rejected() {
        assert!(render("{target}/./x.age", &context()).is_err());
    }

    #[test]
    fn a_dot_inside_a_name_is_still_valid() {
        // Only the whole segment is a problem: artifact names carry dots all
        // over the place.
        assert!(render("{target}/x.dump.zst.age", &context()).is_ok());
    }

    #[test]
    fn a_hidden_name_is_still_valid() {
        assert!(render(".shieldbk/{target}.age", &context()).is_ok());
    }
}
