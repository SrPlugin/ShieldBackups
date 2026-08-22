//! Startup and lifecycle of a plugin as a child process.
//!
//! The core launches every plugin as a separate process, hands it on stdin the
//! envelope with the session's TLS material and waits for its announcement on
//! stdout. From then on the plugin listens on a Unix socket with mTLS and the
//! core talks to it over gRPC.
//!
//! This module is the core's side of that startup, and it is where three
//! guarantees that are not hygiene but security take shape:
//!
//! * **The child does not inherit the core's environment.** If the core has
//!   `PGPASSWORD` or `AWS_SECRET_ACCESS_KEY` in its environment, a plugin that
//!   inherited them would hold credentials nobody gave it —and a process's
//!   environment is readable in `/proc/<pid>/environ` by anyone who can read
//!   it—.
//! * **The plugin lives in its own process group.** The `PostgreSQL` plugin will
//!   launch `pg_dump` as a grandchild of the core; killing only the plugin would
//!   leave `pg_dump` orphaned, consuming resources of the database server and
//!   with an open transaction.
//! * **Cleanup is guaranteed.** An orphaned process keeps the session's
//!   cryptographic material in memory.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{DirBuilder, Permissions};
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sb_transport::{Bootstrap, EphemeralPki, HandshakeError, PkiError, READY_TIMEOUT_MS, Ready};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

/// The only environment variables a plugin receives from the core.
///
/// The list is deliberately short: it is easier to reason about what is let
/// through than about what is filtered out. `PATH` because a plugin needs to
/// find the tools it wraps (`pg_dump`, `mysqldump`), `HOME` and `TMPDIR` because
/// many libraries take them for granted, and `LANG`/`TZ` because without them
/// dates and messages come out in another language than the operator expects.
const INHERITED_VARIABLES: [&str; 5] = ["PATH", "HOME", "TMPDIR", "LANG", "TZ"];

/// `PATH` used if the core had none.
///
/// Without `PATH` a plugin cannot even run `pg_dump`. A minimal, explicit value
/// is preferred over inheriting the absence.
const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Permissions of the directory where the control socket lives.
///
/// `0700`: the socket is the door into the plugin and whoever can open it talks
/// to it. mTLS protects it anyway, but two locks are better than one.
const PRIVATE_MODE: u32 = 0o700;

/// Distinguishes directories of plugins started by the same core.
///
/// A backup uses an engine and a storage at once: two live plugins that cannot
/// share a socket. The core's pid separates different runs and this counter
/// separates the plugins of a single run.
static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
pub enum PluginProcessError {
    #[error("could not start the plugin \"{name}\" from {binary}: {source}")]
    SpawnFailed {
        name: String,
        binary: String,
        #[source]
        source: std::io::Error,
    },
    #[error("could not prepare the runtime directory {dir}: {source}")]
    RuntimeDirectory {
        dir: String,
        #[source]
        source: std::io::Error,
    },
    #[error("could not generate the session's cryptographic material: {0}")]
    Pki(#[from] PkiError),
    /// The plugin never announced itself: either it stayed silent until the
    /// deadline expired, or it died without writing anything. They are treated
    /// the same on purpose —from the core's point of view they are the same
    /// event, "this binary is not a working plugin"— and the difference is
    /// recorded in the log next to the process's stderr, which is where it is
    /// useful for debugging.
    #[error("the plugin did not announce itself within the startup deadline")]
    HandshakeTimeout,
    #[error("the plugin's announcement is not valid: {0}")]
    Announcement(#[from] HandshakeError),
    #[error("input/output failure while talking to the plugin: {0}")]
    Io(#[from] std::io::Error),
}

/// A started and announced plugin, with its process under control.
///
/// While this handle exists, the process exists. When it is destroyed —by
/// `shutdown` or by `Drop`—, the plugin and all its descendants die and its
/// runtime directory disappears.
pub struct PluginProcess {
    name: String,
    pid: u32,
    protocol_version: u32,
    capabilities: Vec<String>,
    runtime_dir: PathBuf,
    control_socket: PathBuf,
    pki: EphemeralPki,
    env: BTreeMap<String, String>,
    /// `None` only after `shutdown`, which takes the child away to reap it.
    child: Option<Child>,
}

/// `Debug` written by hand and redacted: this struct holds the session's PKI,
/// which includes two private keys. `EphemeralPki` deliberately does not
/// implement `Debug`, so here it is printed as `<redacted>`: the handle can be
/// dumped to a startup debug log without anything private coming out.
impl fmt::Debug for PluginProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginProcess")
            .field("name", &self.name)
            .field("pid", &self.pid)
            .field("protocol_version", &self.protocol_version)
            .field("capabilities", &self.capabilities)
            .field("runtime_dir", &self.runtime_dir)
            .field("control_socket", &self.control_socket)
            .field("pki", &"<redacted>")
            .field("env", &self.env)
            .field("child", &self.child)
            .finish()
    }
}

impl PluginProcess {
    /// Starts a plugin's binary and waits for it to announce itself.
    ///
    /// It generates an ephemeral PKI for this session, creates a private
    /// directory for the control socket, launches the process with a minimal
    /// environment and in its own group, hands it the envelope on stdin and
    /// waits for its `Ready`.
    ///
    /// If anything fails at any point —including the startup deadline— the
    /// process is killed **and reaped**, and the directory is removed, before
    /// returning the error: a failed startup cannot leave residue behind.
    ///
    /// # Errors
    /// Returns [`PluginProcessError::SpawnFailed`] if the binary cannot be
    /// executed, [`PluginProcessError::HandshakeTimeout`] if it does not
    /// announce itself in time, and the corresponding PKI, input/output or
    /// invalid-announcement errors.
    pub async fn spawn(name: &str, binary: &Path) -> Result<Self, PluginProcessError> {
        let pki = EphemeralPki::generate()?;
        let runtime_dir = create_private_dir()?;
        let control_socket = runtime_dir.join("control.sock");
        let env = minimal_env();

        let mut child = match launch(binary, &env) {
            Ok(child) => child,
            Err(source) => {
                // The directory was created before knowing that the binary does
                // not exist: it cannot stay there.
                remove_dir(&runtime_dir);
                return Err(PluginProcessError::SpawnFailed {
                    name: name.to_string(),
                    binary: binary.display().to_string(),
                    source,
                });
            }
        };

        // The pid is only available while the child has not been reaped, and it
        // is needed later to kill the whole group. Right after launching there
        // always is one; the 0 of the impossible case is harmless because
        // `kill_group` discards it before signalling anything.
        let pid = child.id().unwrap_or_default();
        let input = child.stdin.take();
        let output = child.stdout.take();
        relay_stderr(name, child.stderr.take());

        let envelope = Bootstrap::new(
            vec![sb_proto::PROTOCOL_VERSION],
            control_socket.display().to_string(),
            pki.server_bundle(),
        );

        let mut process = Self {
            name: name.to_string(),
            pid,
            protocol_version: 0,
            capabilities: Vec::new(),
            runtime_dir,
            control_socket,
            pki,
            env,
            child: Some(child),
        };

        match wait_for_announcement(&envelope, input, output).await {
            Ok(ready) => {
                tracing::info!(
                    plugin = %process.name,
                    pid,
                    protocol_version = ready.protocol_version,
                    "plugin started"
                );
                process.protocol_version = ready.protocol_version;
                process.capabilities = ready.capabilities;
                Ok(process)
            }
            Err(error) => {
                tracing::warn!(plugin = %process.name, pid, %error, "the plugin did not start");
                process.kill_and_reap().await;
                Err(error)
            }
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Pid of the plugin's process, which is also its group's.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Protocol version the plugin declared it speaks.
    #[must_use]
    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// What the plugin says it knows how to do: `engine`, `storage` or both.
    #[must_use]
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Private directory where the control socket lives.
    #[must_use]
    pub fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    /// Socket over which gRPC is spoken with the plugin.
    #[must_use]
    pub fn control_socket(&self) -> &Path {
        &self.control_socket
    }

    /// This session's PKI: from here comes the client configuration with which
    /// the core connects to the control channel.
    #[must_use]
    pub fn pki(&self) -> &EphemeralPki {
        &self.pki
    }

    /// The exact environment the child was launched with.
    ///
    /// It is stored —instead of being inferred— so that it is checkable: what
    /// this map does not contain, the plugin does not have.
    #[must_use]
    pub fn child_env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    /// Closes the plugin: kills the whole group, **reaps** the child and removes
    /// the runtime directory.
    ///
    /// Reaping the child is not optional: a process nobody `wait`s on becomes a
    /// zombie in the process table, and with one backup per hour they pile up.
    ///
    /// # Errors
    /// Today it does not fail —cleanup failures are logged and ignored, because
    /// there is nothing better to do with them—, but it returns a `Result` so
    /// that an orderly gRPC shutdown can report its failure without changing
    /// every caller.
    pub async fn shutdown(mut self) -> Result<(), PluginProcessError> {
        self.kill_and_reap().await;
        Ok(())
    }

    /// Kills the group, reaps the child and removes the directory. Idempotent.
    async fn kill_and_reap(&mut self) {
        kill_group(self.pid);
        if let Some(mut child) = self.child.take() {
            // That `start_kill` fails because it had already died does not
            // matter: what counts is the `wait`.
            let _ = child.start_kill();
            if let Err(source) = child.wait().await {
                tracing::warn!(plugin = %self.name, pid = self.pid, %source, "could not reap the plugin");
            }
        }
        remove_dir(&self.runtime_dir);
    }
}

/// Safety net against panics and shortcut exits.
///
/// In `Drop` nothing can be awaited, so this is the best that can be done
/// without blocking: the signal to the group is sent all the same —it is a
/// system call, not a wait— and reaping the child is left to `kill_on_drop`,
/// which tokio resolves in its orphan queue.
impl Drop for PluginProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            kill_group(self.pid);
            let _ = child.start_kill();
        }
        remove_dir(&self.runtime_dir);
    }
}

/// Launches the plugin's process with the three pipes under control.
fn launch(binary: &Path, env: &BTreeMap<String, String>) -> std::io::Result<Child> {
    let mut command = Command::new(binary);
    // The core's environment does not travel: we start from zero and add the
    // bare minimum.
    command.env_clear();
    command.envs(env);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // If the core panics between the spawn and the shutdown, the plugin does not
    // outlive it.
    command.kill_on_drop(true);
    // Its own process group (`setpgid(0, 0)`): the `PostgreSQL` plugin will
    // launch `pg_dump` as a grandchild of the core, and on abort they have to be
    // killable together. Killing only the plugin would leave a `pg_dump` orphan
    // with an open transaction against the production database.
    //
    // `process_group` is safe; `pre_exec`, which would be the other way of doing
    // this, is not —and the workspace forbids `unsafe`—.
    command.process_group(0);
    command.spawn()
}

/// Delivers the envelope, closes stdin and waits for the announcement with a
/// deadline.
async fn wait_for_announcement(
    envelope: &Bootstrap,
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
) -> Result<Ready, PluginProcessError> {
    let input = input
        .ok_or_else(|| std::io::Error::other("the plugin was launched without its own stdin"))?;
    send_envelope(envelope, input).await?;

    let output = output
        .ok_or_else(|| std::io::Error::other("the plugin was launched without its own stdout"))?;
    let mut reader = BufReader::new(output);
    let mut line = String::new();
    let read = tokio::time::timeout(
        Duration::from_millis(READY_TIMEOUT_MS),
        reader.read_line(&mut line),
    )
    .await
    .map_err(|_| PluginProcessError::HandshakeTimeout)??;

    if read == 0 {
        // End of file: the process died without announcing itself. For the core
        // it is the same event as silence, and it arrives sooner.
        return Err(PluginProcessError::HandshakeTimeout);
    }
    Ok(Ready::from_line(&line)?)
}

/// Writes the bootstrap envelope and **closes** the child's stdin.
///
/// Closing it is part of the contract: the plugin already has everything it
/// needs, and an open stdin is a channel nobody is going to talk on.
///
/// A write failure is not propagated as such because it almost always means the
/// process had already died —a broken pipe—; the good diagnosis comes from
/// waiting for the announcement, which will see the end of file, together with
/// the stderr that is being relayed.
async fn send_envelope(
    envelope: &Bootstrap,
    mut input: ChildStdin,
) -> Result<(), PluginProcessError> {
    let line = envelope.to_line()?;
    let write = async {
        input.write_all(line.as_bytes()).await?;
        input.write_all(b"\n").await?;
        input.flush().await
    }
    .await;
    if let Err(source) = write {
        tracing::debug!(%source, "could not deliver the bootstrap envelope");
    }
    drop(input);
    Ok(())
}

/// Reads the plugin's stderr and relays it to the core's log.
///
/// Without this, a plugin that fails does so in silence: its stderr is a pipe
/// nobody reads and the operator only sees "the plugin did not start".
fn relay_stderr(name: &str, stderr: Option<ChildStderr>) {
    let Some(stderr) = stderr else { return };
    let name = name.to_string();
    tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            tracing::info!(plugin = %name, "{line}");
        }
    });
}

/// The environment a plugin is launched with: the bare minimum, and nothing
/// else.
fn minimal_env() -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for key in INHERITED_VARIABLES {
        if let Ok(value) = std::env::var(key) {
            env.insert(key.to_string(), value);
        }
    }
    env.entry("PATH".to_string())
        .or_insert_with(|| DEFAULT_PATH.to_string());
    env
}

/// Creates the private directory where the control socket will live.
///
/// Under `XDG_RUNTIME_DIR` if it exists —it is on a tmpfs of the user's own and
/// the paths are short, which matters because a Unix socket does not accept more
/// than 108 bytes of path—, and otherwise under the system temporary directory.
/// The mode is requested at creation time, not afterwards: between creating and
/// fixing there is a window in which the directory would be readable by others.
fn create_private_dir() -> Result<PathBuf, PluginProcessError> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|d| d.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = base.join(format!("shieldbk-{}-{n}", std::process::id()));

    DirBuilder::new()
        .mode(PRIVATE_MODE)
        .create(&dir)
        .map_err(|source| PluginProcessError::RuntimeDirectory {
            dir: dir.display().to_string(),
            source,
        })?;
    // The process's `umask` can only take permissions away, never add them, so
    // this does not relax anything; it is here so that the mode is exactly 0700
    // even if somebody inherited an odd umask.
    std::fs::set_permissions(&dir, Permissions::from_mode(PRIVATE_MODE)).map_err(|source| {
        PluginProcessError::RuntimeDirectory {
            dir: dir.display().to_string(),
            source,
        }
    })?;
    Ok(dir)
}

/// Removes the runtime directory. Best-effort: if it cannot be done, it is
/// logged.
fn remove_dir(dir: &Path) {
    if let Err(source) = std::fs::remove_dir_all(dir)
        && source.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(dir = %dir.display(), %source, "could not remove the plugin's directory");
    }
}

/// Sends `SIGKILL` to the plugin's process group.
///
/// To the group, not to the process: that is what takes the grandchildren down
/// with it. Since the plugin was launched with `process_group(0)`, the group's
/// identifier is its own pid, and the core —which is in another group— does not
/// kill itself.
pub(crate) fn kill_group(pid: u32) {
    let Ok(raw) = i32::try_from(pid) else {
        return;
    };
    let Some(target) = rustix::process::Pid::from_raw(raw) else {
        return;
    };
    if let Err(source) = rustix::process::kill_process_group(target, rustix::process::Signal::KILL)
    {
        // `ESRCH` is normal when the plugin had already finished on its own.
        tracing::debug!(pid, %source, "could not signal the plugin's group");
    }
}

#[cfg(test)]
#[allow(
    clippy::for_kv_map,
    clippy::items_after_statements,
    reason = "these tests describe the contract as it would read in a review; walking the map by pairs makes it obvious that the keys of an environment are being inspected, and the `use` next to the permission check keeps the reason beside the assert"
)]
mod tests {
    use super::*;
    use crate::plugin::test_support::mock_path;

    #[tokio::test]
    async fn starts_a_plugin_and_completes_the_handshake() {
        let p = PluginProcess::spawn("mock", &mock_path()).await.unwrap();
        assert_eq!(p.protocol_version(), sb_proto::PROTOCOL_VERSION);
        assert!(p.capabilities().contains(&"engine".to_string()));
        assert!(p.capabilities().contains(&"storage".to_string()));
        p.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn the_child_does_not_inherit_the_core_environment() {
        // If the core has PGPASSWORD in its environment, a plugin that inherited
        // it would hold credentials nobody gave it. And a process's environment
        // is readable in /proc/<pid>/environ.
        let p = PluginProcess::spawn("mock", &mock_path()).await.unwrap();
        let env = p.child_env();
        assert!(!env.contains_key("SHIELDBK_VARIABLE_THAT_MUST_NOT_BE_INHERITED"));
        assert!(
            env.contains_key("PATH"),
            "but the bare minimum to work is there"
        );
        assert!(
            env.len() <= 6,
            "the environment must be minimal, it has {}",
            env.len()
        );
        p.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn the_child_environment_contains_nothing_that_looks_like_a_secret() {
        let p = PluginProcess::spawn("mock", &mock_path()).await.unwrap();
        for (key, _) in p.child_env() {
            let k = key.to_uppercase();
            assert!(
                !k.contains("PASSWORD")
                    && !k.contains("SECRET")
                    && !k.contains("TOKEN")
                    && !k.contains("KEY")
                    && !k.contains("CREDENTIAL"),
                "suspicious variable in the plugin's environment: {key}"
            );
        }
        p.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_nonexistent_binary_gives_a_clear_error() {
        let err = PluginProcess::spawn("ghost", std::path::Path::new("/does/not/exist/plugin"))
            .await
            .unwrap_err();
        assert!(matches!(err, PluginProcessError::SpawnFailed { .. }));
        let text = err.to_string();
        assert!(text.contains("ghost"), "it must name the plugin");
        assert!(
            text.contains("/does/not/exist/plugin"),
            "and say where it looked for it"
        );
    }

    #[tokio::test]
    async fn a_binary_that_does_not_speak_the_protocol_times_out() {
        let start = std::time::Instant::now();
        let err = PluginProcess::spawn("sleepy", std::path::Path::new("/bin/sleep"))
            .await
            .unwrap_err();
        assert!(matches!(err, PluginProcessError::HandshakeTimeout));
        assert!(
            start.elapsed() < std::time::Duration::from_secs(60),
            "the timeout must be bounded"
        );
    }

    #[tokio::test]
    async fn destroying_the_process_kills_the_child() {
        let pid = {
            let p = PluginProcess::spawn("mock", &mock_path()).await.unwrap();
            p.pid()
        };
        for _ in 0..100 {
            if !process_alive(pid) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            !process_alive(pid),
            "the plugin must not outlive its handle"
        );
    }

    #[tokio::test]
    async fn the_socket_directory_is_private_and_gets_removed() {
        let dir = {
            let p = PluginProcess::spawn("mock", &mock_path()).await.unwrap();
            let d = p.runtime_dir().to_path_buf();

            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&d).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);

            p.shutdown().await.unwrap();
            d
        };
        assert!(!dir.exists(), "the socket directory must not survive");
    }

    #[tokio::test]
    async fn two_simultaneous_plugins_do_not_share_a_directory() {
        // A backup uses an engine and a storage at once.
        let a = PluginProcess::spawn("mock", &mock_path()).await.unwrap();
        let b = PluginProcess::spawn("mock", &mock_path()).await.unwrap();
        assert_ne!(a.runtime_dir(), b.runtime_dir());
        assert_ne!(a.pid(), b.pid());
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn the_plugin_does_not_become_a_zombie_after_shutdown() {
        // A process nobody waits on stays as a zombie in the process table. With
        // one backup per hour, they pile up.
        let p = PluginProcess::spawn("mock", &mock_path()).await.unwrap();
        let pid = p.pid();
        p.shutdown().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!is_zombie(pid), "the process was left as a zombie");
    }

    /// Checks whether a pid is still alive without sending it a signal.
    fn process_alive(pid: u32) -> bool {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }

    /// Checks whether a pid is in the zombie state by reading /proc.
    fn is_zombie(pid: u32) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| {
                s.rsplit(right_paren())
                    .next()
                    .map(|rest| rest.trim_start().starts_with('Z'))
            })
            .unwrap_or(false)
    }

    fn right_paren() -> char {
        ')'
    }
}
