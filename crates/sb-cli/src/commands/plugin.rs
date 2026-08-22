//! `shieldbk plugin list | docs <plugin> | verify | lock`.
//!
//! All four revolve around the lockfile, which is what separates "a binary that
//! is in the directory" from "a binary this system authorises to receive its
//! database's credentials". `lock` grants that authorisation, `verify` checks
//! it without running anything, `list` shows it and `docs` is the only one that
//! starts a plugin -- and only to ask it which fields it accepts.
//!
//! `docs` **never prints values**, only the schema. The difference is not
//! cosmetic: the schema says there is a `password` field, and a command that
//! also printed "what is configured" would print it too.

use std::fmt::Write as _;

use sb_core::lockfile::{Lockfile, LockfileError};
use sb_proto::{Field, FieldType};

use crate::context::Context;
use crate::error::CliError;
use crate::output::Report;
use crate::plugins;

/// A binary's status with respect to the lockfile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// It is registered and its hash is still the same.
    Registered,
    /// The binary is there but nobody has authorised it.
    Unregistered,
    /// It is registered with **another** hash: somebody has changed it.
    Altered,
    /// The lockfile authorises it but the binary is not in the directory.
    Missing,
}

impl Status {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Unregistered => "unregistered",
            Self::Altered => "ALTERED",
            Self::Missing => "missing",
        }
    }

    /// Whether this status prevents running the binary.
    const fn is_failure(self) -> bool {
        !matches!(self, Self::Registered)
    }
}

/// `plugin list`: what is in the directory and what the lockfile says about it.
///
/// # Errors
/// Returns [`CliError::Plugin`] if the directory or the lockfile cannot be
/// read. A plugin being unregistered is **not** an error here: it is exactly
/// what this command exists to show.
pub fn list(ctx: &Context) -> Result<Report, CliError> {
    let (statuses, _) = inventory(ctx)?;

    let human = if statuses.is_empty() {
        format!("there is no plugin in `{}`", ctx.plugins_dir.display())
    } else {
        statuses
            .iter()
            .map(|(name, status)| format!("{name}: {}", status.as_str()))
            .collect::<Vec<_>>()
            .join("\n")
    };

    Ok(Report::new(
        human,
        serde_json::json!({
            "command": "plugin list",
            "dir": ctx.plugins_dir.to_string_lossy(),
            "lockfile": ctx.lockfile_path.to_string_lossy(),
            "plugins": statuses.iter().map(|(name, status)| serde_json::json!({
                "name": name,
                "status": status.as_str(),
                "usable": !status.is_failure(),
            })).collect::<Vec<_>>(),
        }),
    ))
}

/// `plugin verify`: check every hash **without starting anything**.
///
/// It is the check that can be run on a machine where no plugin is meant to be
/// executed: read files and compare digests, nothing else.
///
/// # Errors
/// Returns [`CliError::Plugin`] if the directory or the lockfile cannot be
/// read. The binaries that do not add up come out **inside** the report with
/// the failure set: the command exists to enumerate them, not to stop at the
/// first one.
pub fn verify(ctx: &Context) -> Result<Report, CliError> {
    let (statuses, _) = inventory(ctx)?;

    let failures: Vec<&(String, Status)> =
        statuses.iter().filter(|(_, e)| e.is_failure()).collect();
    let report = Report::new(
        statuses
            .iter()
            .map(|(name, status)| format!("{name}: {}", status.as_str()))
            .collect::<Vec<_>>()
            .join("\n"),
        serde_json::json!({
            "command": "plugin verify",
            "total": statuses.len(),
            "failed": failures.len(),
            "plugins": statuses.iter().map(|(name, status)| serde_json::json!({
                "name": name,
                "status": status.as_str(),
                "usable": !status.is_failure(),
            })).collect::<Vec<_>>(),
        }),
    );

    if failures.is_empty() {
        return Ok(report);
    }

    let detail = failures
        .iter()
        .map(|(name, status)| format!("  {name}: {}", status.as_str()))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(report.with_failure(CliError::plugin(format!(
        "{} of {} plugins cannot be run:\n{detail}\nIf the changes are expected, register them \
         again with `shieldbk plugin lock`. If they are not, do NOT run them: a plugin receives \
         your database's and your storage's credentials",
        failures.len(),
        statuses.len()
    ))))
}

/// `plugin lock`: register the hash of every binary in the directory.
///
/// It registers **what is there now**, without asking. That is right: whoever
/// runs this command is saying "these binaries are the ones I want", and trust
/// in their origin is their decision. What the lockfile guarantees from here on
/// is that they stay those.
///
/// # Errors
/// Returns [`CliError::Plugin`] if the directory cannot be read or the lockfile
/// cannot be written.
pub fn lock(ctx: &Context) -> Result<Report, CliError> {
    let binaries = plugins::binaries(&ctx.plugins_dir)?;

    // It starts from the existing lockfile and not from an empty one: a `lock`
    // must not silently erase the authorisation of a plugin that is not mounted
    // today.
    let mut lockfile = Lockfile::load(&ctx.lockfile_path)?;
    let mut registered = Vec::with_capacity(binaries.len());
    for (name, path) in &binaries {
        lockfile.register(name, path)?;
        registered.push(name.clone());
    }

    create_lockfile_dir(ctx)?;
    lockfile.save(&ctx.lockfile_path)?;

    let human = if registered.is_empty() {
        format!(
            "there was no plugin to register in `{}`",
            ctx.plugins_dir.display()
        )
    } else {
        format!(
            "{} plugins registered in `{}`: {}",
            registered.len(),
            ctx.lockfile_path.display(),
            registered.join(", ")
        )
    };

    Ok(Report::new(
        human,
        serde_json::json!({
            "command": "plugin lock",
            "lockfile": ctx.lockfile_path.to_string_lossy(),
            "registered": registered,
        }),
    ))
}

/// `plugin docs <plugin>`: the configuration schema, as a table.
///
/// # Errors
/// Returns [`CliError::Plugin`] if the binary is not there, is not authorised
/// or does not start.
pub async fn docs(ctx: &Context, name: &str) -> Result<Report, CliError> {
    let client = plugins::start(ctx, name).await?;
    let schema = client.schema().await;
    plugins::close(client).await;
    let schema = schema?;

    Ok(Report::new(
        table(name, &schema),
        serde_json::json!({
            "command": "plugin docs",
            "plugin": name,
            "fields": schema.iter().map(|field| serde_json::json!({
                "name": field.name,
                "type": type_name(field),
                "required": field.required,
                "secret": field.secret,
                "description": field.description,
                "default": field.default_value,
            })).collect::<Vec<_>>(),
        }),
    ))
}

/// Crosses what is in the directory with what the lockfile says.
///
/// Both directions are looked at on purpose: a binary that is there but is not
/// registered and a registration whose binary has disappeared are different
/// problems, and only looking at the directory would show the first.
fn inventory(ctx: &Context) -> Result<(Vec<(String, Status)>, Lockfile), CliError> {
    let binaries = plugins::binaries(&ctx.plugins_dir)?;
    let lockfile = Lockfile::load(&ctx.lockfile_path)?;

    let mut statuses: Vec<(String, Status)> = binaries
        .iter()
        .map(|(name, path)| {
            let status = match lockfile.verify(name, path) {
                Ok(()) => Status::Registered,
                Err(LockfileError::NotRegistered { .. }) => Status::Unregistered,
                Err(_) => Status::Altered,
            };
            (name.clone(), status)
        })
        .collect();

    for registered in lockfile.names() {
        if !binaries.iter().any(|(name, _)| name == &registered) {
            statuses.push((registered, Status::Missing));
        }
    }

    statuses.sort_by(|a, b| a.0.cmp(&b.0));
    Ok((statuses, lockfile))
}

/// Creates the lockfile's directory if it is needed.
///
/// It is the first write of a new installation: without this, `plugin lock`
/// would fail with a "no such file or directory" that talks about the parent
/// directory and not about the lockfile, which is what the user believes they
/// are creating.
fn create_lockfile_dir(ctx: &Context) -> Result<(), CliError> {
    let Some(parent) = ctx.lockfile_path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() || parent.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(parent).map_err(|source| {
        CliError::plugin(format!(
            "could not create the lockfile's directory `{}`: {source}",
            parent.display()
        ))
    })
}

/// The readable name of a field's type.
fn type_name(field: &Field) -> &'static str {
    match FieldType::try_from(field.r#type) {
        Ok(FieldType::String) => "string",
        Ok(FieldType::Int) => "int",
        Ok(FieldType::Bool) => "bool",
        Ok(FieldType::Duration) => "duration",
        Ok(FieldType::Path) => "path",
        Ok(FieldType::List) => "list",
        Ok(FieldType::Unspecified) | Err(_) => "unknown",
    }
}

/// The table that gets read. Columns aligned to the width of their content: a
/// table with fixed widths breaks with the first plugin that has a long field
/// name.
fn table(plugin: &str, fields: &[Field]) -> String {
    if fields.is_empty() {
        return format!("the plugin `{plugin}` accepts no configuration field");
    }

    let headers = ["FIELD", "TYPE", "REQ", "SECRET", "DEFAULT"];
    let rows: Vec<[String; 5]> = fields
        .iter()
        .map(|c| {
            [
                c.name.clone(),
                type_name(c).to_owned(),
                yes_no(c.required),
                yes_no(c.secret),
                // The default value is part of the schema the plugin publishes,
                // not a configured value: there is nothing to hide.
                if c.default_value.is_empty() {
                    "-".to_owned()
                } else {
                    c.default_value.clone()
                },
            ]
        })
        .collect();

    let mut widths = headers.map(str::len);
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }

    let mut text = format!("configuration fields of `{plugin}`\n\n");
    for (i, header) in headers.iter().enumerate() {
        let _ = write!(text, "{header:<width$}  ", width = widths[i]);
    }
    text.push('\n');

    for (row, field) in rows.iter().zip(fields) {
        for (i, cell) in row.iter().enumerate() {
            let padding = widths[i].saturating_sub(cell.chars().count());
            let _ = write!(text, "{cell}{:padding$}  ", "");
        }
        text.push('\n');
        if !field.description.is_empty() {
            let _ = writeln!(text, "    {}", field.description);
        }
    }

    text.trim_end().to_owned()
}

fn yes_no(value: bool) -> String {
    if value { "yes" } else { "no" }.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, kind: FieldType, required: bool, secret: bool) -> Field {
        Field {
            name: name.into(),
            r#type: kind as i32,
            required,
            secret,
            description: format!("description of {name}"),
            default_value: String::new(),
        }
    }

    #[test]
    fn only_the_registered_status_allows_running() {
        assert!(!Status::Registered.is_failure());
        for bad in [Status::Unregistered, Status::Altered, Status::Missing] {
            assert!(bad.is_failure(), "{bad:?} cannot bless a binary");
        }
    }

    #[test]
    fn the_table_shows_the_schemas_five_columns() {
        let text = table(
            "postgres",
            &[
                field("host", FieldType::String, true, false),
                field("password", FieldType::String, true, true),
            ],
        );
        for header in ["FIELD", "TYPE", "REQ", "SECRET", "DEFAULT"] {
            assert!(text.contains(header), "`{header}` is missing:\n{text}");
        }
        assert!(text.contains("host"));
        assert!(text.contains("password"));
        assert!(text.contains("description of host"));
    }

    #[test]
    fn the_table_marks_the_secret_fields_without_showing_any_value() {
        // `docs` describes the schema. A command that also printed "what is
        // configured" would print the password.
        let mut secret = field("password", FieldType::String, true, true);
        secret.default_value = String::new();
        let text = table("postgres", &[secret]);
        assert!(text.contains("yes"), "the secret field is marked:\n{text}");
        assert!(
            !text.to_lowercase().contains("hunter2"),
            "there cannot be values here"
        );
    }

    #[test]
    fn a_plugin_with_no_fields_says_so_instead_of_showing_an_empty_table() {
        let text = table("trivial", &[]);
        assert!(text.contains("accepts no configuration field"), "{text}");
    }

    #[test]
    fn the_protocols_types_have_a_readable_name() {
        assert_eq!(
            type_name(&field("a", FieldType::Path, false, false)),
            "path"
        );
        assert_eq!(type_name(&field("a", FieldType::Int, false, false)), "int");
        assert_eq!(
            type_name(&field("a", FieldType::List, false, false)),
            "list"
        );
        // A newer plugin may send a type this core does not know: it is
        // reported, not a crash.
        let odd = Field {
            r#type: 99,
            ..field("a", FieldType::Int, false, false)
        };
        assert_eq!(type_name(&odd), "unknown");
    }
}
