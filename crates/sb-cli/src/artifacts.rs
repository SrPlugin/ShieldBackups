//! Finding in the storage target the artifacts that belong to a target.
//!
//! `verify <target>` with no artifact and `storage gc <target>` need the same
//! thing: narrowing the storage target down to the part that belongs to one
//! target. The storage target does not know what a target is -- it only has
//! keys -- so the only thing available for narrowing is the very template the
//! artifacts are named with.
//!
//! From that comes this module's rule: **a target's prefix is its template up
//! to the first placeholder that depends on when the backup was made**. With
//! the default template, `{target}/{yyyy}/{mm}/{dd}/...`, that gives
//! `production/`, which is exactly the target's folder. With a template
//! starting with the date there would be no possible prefix, and then the empty
//! prefix -- list everything -- is the honest answer: better to look at too
//! much than to silence artifacts that really did belong to the target.

use sb_config::{Defaults, Target};
use sb_core::model::manifest_key_for;
use sb_core::plugin::PluginClient;
use sb_proto::storage_client::StorageClient;
use sb_proto::{AbortIncompleteRequest, ArtifactMeta, ListRequest};

use crate::error::CliError;

/// The prefix `target`'s artifacts live under.
#[must_use]
pub fn prefix_for(target: &Target, defaults: &Defaults) -> String {
    prefix_from_template(
        target.effective_template(defaults),
        &target.name,
        &target.source,
        &target.storage,
    )
}

/// The fixed part of a template, with the placeholders that are already known
/// substituted.
fn prefix_from_template(template: &str, target: &str, source: &str, storage: &str) -> String {
    let mut prefix = String::new();
    let mut rest = template;

    loop {
        let Some(open) = rest.find('{') else {
            // No placeholder is left: what remains of the template is fixed and
            // is part of the prefix. Without this branch, a template with no
            // placeholders would give an empty prefix and the whole storage
            // target would be listed.
            prefix.push_str(rest);
            return prefix;
        };

        let (literal, from_brace) = rest.split_at(open);
        prefix.push_str(literal);

        let Some(close) = from_brace.find('}') else {
            // An unclosed brace is a typo in the template, and `render` will
            // reject it when the time comes. Here all there is to do is stop
            // looking.
            return prefix;
        };
        let placeholder = &from_brace[1..close];
        match placeholder {
            "target" => prefix.push_str(target),
            "source" => prefix.push_str(source),
            "storage" => prefix.push_str(storage),
            // A placeholder that depends on when the backup was made cannot be
            // known while listing, and an unknown one cannot be substituted: in
            // both cases the prefix ends here.
            _ => return prefix,
        }
        rest = &from_brace[close + 1..];
    }
}

/// The storage target's artifacts under `prefix`, **without the manifests**.
///
/// The manifests are filtered out because they are not artifacts but their
/// labels: including them would make `verify` try to find a manifest for the
/// manifest and count twice as many checks as there are.
///
/// # Errors
/// Returns [`CliError::Operation`] if the storage target cannot list.
pub async fn list(storage: &PluginClient, prefix: &str) -> Result<Vec<ArtifactMeta>, CliError> {
    let mut grpc = StorageClient::new(storage.channel());
    let response = grpc
        .list(ListRequest {
            prefix: prefix.to_owned(),
        })
        .await
        .map_err(|status| {
            CliError::operation(format!(
                "the storage target `{}` could not list `{prefix}`: {}",
                storage.name(),
                status.message()
            ))
        })?;

    let suffix = manifest_key_for("");
    Ok(response
        .into_inner()
        .artifacts
        .into_iter()
        .filter(|a| !a.key.ends_with(&suffix))
        .collect())
}

/// Asks the storage target to abort the incomplete uploads under `prefix`.
///
/// Returns how many it aborted.
///
/// # Errors
/// Returns [`CliError::Operation`] if the storage target rejects the request.
pub async fn abort_incomplete(storage: &PluginClient, prefix: &str) -> Result<u32, CliError> {
    let mut grpc = StorageClient::new(storage.channel());
    let response = grpc
        .abort_incomplete(AbortIncompleteRequest {
            prefix: prefix.to_owned(),
        })
        .await
        .map_err(|status| {
            CliError::operation(format!(
                "the storage target `{}` could not abort the incomplete uploads of `{prefix}`: {}",
                storage.name(),
                status.message()
            ))
        })?;
    Ok(response.into_inner().aborted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_template_gives_the_targets_folder() {
        let prefix = prefix_from_template(
            "{target}/{yyyy}/{mm}/{dd}/{target}-{timestamp}-{source}.dump.zst.age",
            "production",
            "postgres",
            "r2",
        );
        assert_eq!(prefix, "production/");
    }

    #[test]
    fn every_fixed_placeholder_is_substituted_before_cutting() {
        let prefix = prefix_from_template(
            "{storage}/{source}/{target}/{timestamp}.age",
            "prod",
            "postgres",
            "r2",
        );
        assert_eq!(prefix, "r2/postgres/prod/");
    }

    #[test]
    fn a_template_starting_with_the_date_has_no_prefix() {
        // And that is right: listing too much and filtering is recoverable;
        // silencing the target's artifacts is not.
        assert_eq!(
            prefix_from_template("{yyyy}/{target}.age", "prod", "e", "s"),
            ""
        );
    }

    #[test]
    fn a_template_with_no_placeholders_is_its_own_prefix() {
        assert_eq!(
            prefix_from_template("fixed/artifact.age", "prod", "e", "s"),
            "fixed/artifact.age"
        );
    }

    #[test]
    fn an_unclosed_brace_cuts_the_prefix_instead_of_looping_forever() {
        assert_eq!(
            prefix_from_template("copies/{target/x", "prod", "e", "s"),
            "copies/"
        );
    }

    #[test]
    fn an_unknown_placeholder_cuts_the_prefix() {
        // `render` will give the error explaining it; there is nothing to
        // substitute here.
        assert_eq!(
            prefix_from_template("copies/{week}/x", "prod", "e", "s"),
            "copies/"
        );
    }
}
