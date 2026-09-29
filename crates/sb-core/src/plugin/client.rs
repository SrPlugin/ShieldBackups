//! The plugin as an interlocutor: live process + gRPC channel.
//!
//! [`PluginProcess`] starts the binary and guarantees its cleanup;
//! [`sb_transport::connect_control`] opens the encrypted channel. Neither of the
//! two knows how to speak the `Plugin` service. This module joins them and
//! exposes the five control RPCs with three things the backup operations need
//! and that `tonic::Status` does not give:
//!
//! * **A deadline on every call.** A plugin that hangs —waiting for a database
//!   server that does not answer— would leave the backup waiting forever. The
//!   control RPCs are all fast, so any long wait is a failure dressed up as
//!   slowness.
//! * **Errors that say who and in what.** A backup has two live plugins at once,
//!   the source and the storage; "configure failed" forces you to guess which of
//!   the two it was.
//! * **Version and capabilities checked before being used.** Asking a plugin
//!   that only knows how to store for a dump must fail when it is chosen, not
//!   halfway through the backup.

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::time::Duration;

use sb_proto::plugin_client::PluginClient as PluginGrpc;
use sb_proto::{
    ConfigureRequest, Field, InfoRequest, InfoResponse, PreflightRequest, PreflightResponse,
    SchemaRequest, ShutdownRequest, Value,
};
use sb_transport::{ControlError, connect_control};
use tonic::transport::Channel;

use super::process::{PluginProcess, PluginProcessError};

/// Maximum deadline of any control RPC.
///
/// All five are fast by definition —they inform, describe, store configuration
/// or check— so a minute is not a tight deadline but the point beyond which it
/// is clear that the plugin is not going to answer. It applies only to the
/// control channel: a `Dump` may take hours and does not go through here.
const RPC_DEADLINE: Duration = Duration::from_secs(60);

/// What a plugin knows how to do, as it declares at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// It can produce a byte stream and be rebuilt from one: it is a source. A
    /// database is the obvious case, but so is a directory, a volume or a disk
    /// image.
    Source,
    /// It can store and retrieve artifacts: it is a storage.
    Storage,
    /// It can be told how a command went and pass that on: it is a notifier.
    Notifier,
}

impl Capability {
    /// The name it travels under on the wire, which is the same one the plugin
    /// declares in its startup announcement.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Storage => "storage",
            Self::Notifier => "notifier",
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Everything that can go wrong while talking to a plugin.
///
/// Every variant names the plugin because the user has several and the message
/// is the only thing that tells them which one is giving them trouble.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("{0}")]
    Process(#[from] PluginProcessError),
    #[error("{0}")]
    Transport(#[from] ControlError),
    /// The plugin answered, but with an error.
    #[error("the plugin \"{plugin}\" failed on {operation}: {message}")]
    Rpc {
        plugin: String,
        operation: String,
        message: String,
    },
    /// The plugin did not answer within the deadline. It is told apart from
    /// `Rpc` because the remedy is different: here there is no plugin message to
    /// read, there is a process to look at.
    #[error("the plugin \"{plugin}\" did not answer {operation} in {} s", RPC_DEADLINE.as_secs())]
    Timeout { plugin: String, operation: String },
    #[error("the plugin \"{plugin}\" does not know how to act as \"{capability}\"")]
    MissingCapability { plugin: String, capability: String },
    #[error(
        "the plugin \"{plugin}\" speaks version {plugin_version} of the protocol and this core speaks {core_version}"
    )]
    IncompatibleVersion {
        plugin: String,
        plugin_version: u32,
        core_version: u32,
    },
}

/// A plugin started, connected and ready to take orders.
///
/// While this handle exists, the process exists and the channel is open.
/// `shutdown` closes it in an orderly fashion; if nobody calls it, the process's
/// `Drop` takes care of it anyway.
#[derive(Debug)]
pub struct PluginClient {
    process: PluginProcess,
    channel: Channel,
}

impl PluginClient {
    /// Starts the plugin, checks that they speak the same protocol and opens the
    /// control channel.
    ///
    /// The version is checked **before** connecting: if the plugin speaks
    /// another protocol, the channel would be useless and the only thing opening
    /// it would achieve is making the failure show up later and worse explained.
    ///
    /// # Errors
    /// Returns [`PluginError::Process`] if the binary does not start or does not
    /// announce itself, [`PluginError::IncompatibleVersion`] if the versions do
    /// not match, and [`PluginError::Transport`] if the channel cannot be
    /// opened.
    pub async fn start(name: &str, binary: &Path) -> Result<Self, PluginError> {
        let process = PluginProcess::spawn(name, binary).await?;

        if process.protocol_version() != sb_proto::PROTOCOL_VERSION {
            let error = PluginError::IncompatibleVersion {
                plugin: name.to_string(),
                plugin_version: process.protocol_version(),
                core_version: sb_proto::PROTOCOL_VERSION,
            };
            close_after_failure(process, &error).await;
            return Err(error);
        }

        let tls = match process.pki().client_config() {
            Ok(tls) => tls,
            Err(source) => {
                let error = PluginError::Transport(ControlError::from_pki(source));
                close_after_failure(process, &error).await;
                return Err(error);
            }
        };

        let channel = match connect_control(process.control_socket(), tls).await {
            Ok(channel) => channel,
            Err(source) => {
                let error = PluginError::Transport(source);
                close_after_failure(process, &error).await;
                return Err(error);
            }
        };

        Ok(Self { process, channel })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        self.process.name()
    }

    /// The process underneath: pid, runtime directory and declared
    /// capabilities.
    #[must_use]
    pub fn process(&self) -> &PluginProcess {
        &self.process
    }

    /// The control channel, ready to build a `SourceClient` or a
    /// `StorageClient` on top of it.
    ///
    /// Cloning it does not open another connection: a tonic `Channel` is a
    /// handle to the already established connection, and every call is
    /// multiplexed over it.
    #[must_use]
    pub fn channel(&self) -> Channel {
        self.channel.clone()
    }

    /// Whether the plugin declared it knows how to do that at startup.
    #[must_use]
    pub fn has_capability(&self, capability: Capability) -> bool {
        self.process
            .capabilities()
            .iter()
            .any(|c| c == capability.as_str())
    }

    /// Like [`Self::has_capability`], but turns the "no" into an error that can
    /// be propagated.
    ///
    /// It exists so that choosing a plugin for a role it cannot play fails when
    /// it is chosen and not halfway through the backup.
    ///
    /// # Errors
    /// Returns [`PluginError::MissingCapability`], which names the plugin and
    /// the capability it lacks.
    pub fn require_capability(&self, capability: Capability) -> Result<(), PluginError> {
        if self.has_capability(capability) {
            return Ok(());
        }
        Err(PluginError::MissingCapability {
            plugin: self.name().to_string(),
            capability: capability.as_str().to_string(),
        })
    }

    /// Identity, version and capabilities, now over the authenticated channel.
    ///
    /// # Errors
    /// Returns [`PluginError::Rpc`] or [`PluginError::Timeout`].
    pub async fn info(&self) -> Result<InfoResponse, PluginError> {
        let mut grpc = self.grpc();
        self.with_deadline("info", grpc.info(InfoRequest {})).await
    }

    /// The configuration fields the plugin accepts.
    ///
    /// # Errors
    /// Returns [`PluginError::Rpc`] or [`PluginError::Timeout`].
    pub async fn schema(&self) -> Result<Vec<Field>, PluginError> {
        let mut grpc = self.grpc();
        let response = self
            .with_deadline("schema", grpc.schema(SchemaRequest {}))
            .await?;
        Ok(response.fields)
    }

    /// Hands over the configuration already validated and with the secrets
    /// resolved.
    ///
    /// # Errors
    /// Returns [`PluginError::Rpc`] if the plugin rejects the configuration
    /// —the reason travels there— or [`PluginError::Timeout`].
    pub async fn configure(&self, config: HashMap<String, Value>) -> Result<(), PluginError> {
        let mut grpc = self.grpc();
        self.with_deadline("configure", grpc.configure(ConfigureRequest { config }))
            .await?;
        Ok(())
    }

    /// Check of connectivity, permissions and dependencies.
    ///
    /// That the report comes back with `ok: false` is **not** an error of this
    /// function: it is its answer, and it is exactly what `doctor` has to show
    /// the user. It only fails if the plugin never answers.
    ///
    /// # Errors
    /// Returns [`PluginError::Rpc`] or [`PluginError::Timeout`].
    pub async fn preflight(&self) -> Result<PreflightResponse, PluginError> {
        let mut grpc = self.grpc();
        self.with_deadline("preflight", grpc.preflight(PreflightRequest {}))
            .await
    }

    /// Closes the plugin: first it asks, then it makes sure.
    ///
    /// That the shutdown RPC fails is not a reason for an error —the plugin may
    /// already have died, which is exactly what was wanted—, but the process has
    /// to end no matter what: the failure is logged and we move on to closing
    /// the process, which kills the whole group and reaps the child.
    ///
    /// # Errors
    /// Returns [`PluginError::Process`] if the process cleanup fails.
    pub async fn shutdown(self) -> Result<(), PluginError> {
        let mut grpc = self.grpc();
        if let Err(error) = self
            .with_deadline("shutdown", grpc.shutdown(ShutdownRequest {}))
            .await
        {
            tracing::debug!(
                plugin = %self.name(),
                %error,
                "the plugin did not confirm the shutdown; closing it the hard way"
            );
        }
        // The channel is dropped before killing the process: otherwise the open
        // connection outlives the socket that no longer exists.
        drop(self.channel);
        self.process.shutdown().await?;
        Ok(())
    }

    /// Kills the plugin outright, as if it had crashed on its own.
    ///
    /// It exists so that we can check that talking to a dead plugin gives an
    /// error and not a hang. It sends `SIGKILL` to the whole group: no farewell,
    /// no chance to clean up. It is not a legitimate way to close a plugin.
    #[doc(hidden)]
    pub fn kill_for_test(&self) {
        super::process::kill_group(self.process.pid());
    }

    /// A fresh gRPC client over the already open channel.
    ///
    /// One is built per call on purpose: the generated client needs `&mut self`
    /// and the channel is cheap to clone, so this comes out cheaper than keeping
    /// a client behind a mutex and serializing the calls.
    fn grpc(&self) -> PluginGrpc<Channel> {
        PluginGrpc::new(self.channel())
    }

    /// The deadline and the error translation, in a single place.
    ///
    /// Repeating `tokio::time::timeout` in every RPC is exactly the kind of
    /// repetition that ends with a method without a deadline: forgetting it once
    /// is enough for a hung plugin to leave the backup waiting forever.
    async fn with_deadline<T, F>(&self, operation: &str, call: F) -> Result<T, PluginError>
    where
        F: Future<Output = Result<tonic::Response<T>, tonic::Status>>,
    {
        match tokio::time::timeout(RPC_DEADLINE, call).await {
            Ok(Ok(response)) => Ok(response.into_inner()),
            Ok(Err(status)) => Err(PluginError::Rpc {
                plugin: self.name().to_string(),
                operation: operation.to_string(),
                message: message_from(&status),
            }),
            Err(_) => Err(PluginError::Timeout {
                plugin: self.name().to_string(),
                operation: operation.to_string(),
            }),
        }
    }
}

/// What is left for the user out of a `Status`.
///
/// The bare message is what the plugin meant to say and it is what has to be
/// shown; when it comes empty —which happens with transport errors, where there
/// is nobody on the other side writing anything— the code is the only thing that
/// informs.
pub(crate) fn message_from(status: &tonic::Status) -> String {
    if status.message().is_empty() {
        format!("{:?}", status.code())
    } else {
        format!("{:?}: {}", status.code(), status.message())
    }
}

/// Closes a process whose startup did not reach a good end.
///
/// A plugin that cannot be talked to cannot stay alive: it keeps the session's
/// cryptographic material in memory and nobody is ever going to ask it for
/// anything.
async fn close_after_failure(process: PluginProcess, error: &PluginError) {
    tracing::warn!(plugin = %process.name(), %error, "could not open the channel with the plugin");
    if let Err(source) = process.shutdown().await {
        tracing::warn!(%source, "and it could not be closed cleanly either");
    }
}

#[cfg(test)]
use crate::plugin::test_support::mock_path;

#[cfg(test)]
mod tests {
    use super::*;

    fn v_str(s: &str) -> sb_proto::Value {
        sb_proto::Value {
            kind: Some(sb_proto::value::Kind::StringValue(s.into())),
        }
    }
    #[expect(dead_code, reason = "the mock's integer fields are optional")]
    fn v_int(i: i64) -> sb_proto::Value {
        sb_proto::Value {
            kind: Some(sb_proto::value::Kind::IntValue(i)),
        }
    }

    #[tokio::test]
    async fn connects_and_asks_for_info() {
        let c = PluginClient::start("mock", &mock_path()).await.unwrap();
        let info = c.info().await.unwrap();
        assert_eq!(info.name, "mock");
        assert_eq!(info.protocol_version, sb_proto::PROTOCOL_VERSION);
        c.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn asks_for_the_schema_and_gets_fields() {
        let c = PluginClient::start("mock", &mock_path()).await.unwrap();
        let fields = c.schema().await.unwrap();
        assert!(fields.iter().any(|f| f.name == "dir"));
        c.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn configures_and_runs_preflight() {
        let dir = tempfile::tempdir().unwrap();
        let c = PluginClient::start("mock", &mock_path()).await.unwrap();

        let mut cfg = std::collections::HashMap::new();
        cfg.insert("dir".to_string(), v_str(&dir.path().to_string_lossy()));
        c.configure(cfg).await.unwrap();

        let pre = c.preflight().await.unwrap();
        assert!(pre.ok, "the configured mock must pass the preflight");
        c.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn preflight_without_configuring_reports_instead_of_blowing_up() {
        // doctor needs a report, not an exception: if the plugin is not
        // configured, that is exactly what doctor must tell the user.
        let c = PluginClient::start("mock", &mock_path()).await.unwrap();
        let pre = c.preflight().await.unwrap();
        assert!(!pre.ok);
        assert!(!pre.checks.is_empty(), "it must explain what is missing");
        c.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn declares_its_capabilities_correctly() {
        let c = PluginClient::start("mock", &mock_path()).await.unwrap();
        assert!(c.has_capability(Capability::Source));
        assert!(c.has_capability(Capability::Storage));
        assert!(c.require_capability(Capability::Source).is_ok());
        c.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn requiring_a_missing_capability_gives_an_error_that_names_it() {
        let c = PluginClient::start("mock", &mock_path()).await.unwrap();
        // The mock has both, so the message is checked against the error type
        // directly.
        let err = PluginError::MissingCapability {
            plugin: "postgres".into(),
            capability: "storage".into(),
        };
        let text = err.to_string();
        assert!(text.contains("postgres"));
        assert!(text.contains("storage"));
        c.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn talking_to_a_dead_plugin_gives_an_error_not_a_hang() {
        let c = PluginClient::start("mock", &mock_path()).await.unwrap();
        c.kill_for_test();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let r = tokio::time::timeout(std::time::Duration::from_secs(5), c.info()).await;
        assert!(r.expect("it must not hang").is_err());
    }

    #[tokio::test]
    async fn a_plugin_error_names_the_plugin_and_the_operation() {
        // An error that only says "failed" forces you to guess which of a
        // backup's two plugins failed, and on which call.
        let err = PluginError::Rpc {
            plugin: "r2".into(),
            operation: "configure".into(),
            message: "nonexistent bucket".into(),
        };
        let text = err.to_string();
        assert!(text.contains("r2"));
        assert!(text.contains("configure"));
        assert!(text.contains("nonexistent bucket"));
    }

    #[tokio::test]
    async fn the_version_error_says_both_versions() {
        let err = PluginError::IncompatibleVersion {
            plugin: "old".into(),
            plugin_version: 7,
            core_version: 1,
        };
        let text = err.to_string();
        assert!(text.contains('7'), "the plugin's one");
        assert!(text.contains("old"));
    }

    #[tokio::test]
    async fn two_simultaneous_clients_work() {
        // A backup starts a source and a storage at once.
        let a = PluginClient::start("mock", &mock_path()).await.unwrap();
        let b = PluginClient::start("mock", &mock_path()).await.unwrap();
        assert_eq!(a.info().await.unwrap().name, "mock");
        assert_eq!(b.info().await.unwrap().name, "mock");
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn the_orderly_shutdown_ends_the_process() {
        let c = PluginClient::start("mock", &mock_path()).await.unwrap();
        let pid = c.process().pid();
        c.shutdown().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "shutdown must end the process"
        );
    }
}
