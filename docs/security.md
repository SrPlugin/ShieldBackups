# Security model

This document states each of ShieldBackups' security decisions **together with
the point where its guarantee stops.** A security document that lists only what
a system protects is worse than none: it teaches the reader to rely on
protections that are not there.

Read it alongside the honest summary in the
[README](../README.md#security-plainly) and the operational hazards in
[`deploy/README.md`](../deploy/README.md#four-things-that-will-bite-you).

---

## Table of contents

- [The shape of the system](#the-shape-of-the-system)
- [Ephemeral mTLS: the threat model](#ephemeral-mtls-the-threat-model)
- [Why the data channel carries no TLS](#why-the-data-channel-carries-no-tls)
- [Secrets are references, never literals](#secrets-are-references-never-literals)
- [What the lockfile protects, and what it does not](#what-the-lockfile-protects-and-what-it-does-not)
- [Memory: `Secret<T>` and its limits](#memory-secrett-and-its-limits)
- [Third-party errors that carry secrets inside](#third-party-errors-that-carry-secrets-inside)
- [Encryption and the key](#encryption-and-the-key)
- [Verification without the key](#verification-without-the-key)
- [Process isolation](#process-isolation)
- [A restore that fails may leave plaintext behind](#a-restore-that-fails-may-leave-plaintext-behind)
- [Out of scope](#out-of-scope)

---

## The shape of the system

`shieldbk` is a one-shot CLI that starts one or more **plugin processes**, hands
each its configuration over an authenticated channel, and pipes bytes between
them while compressing, encrypting and hashing.

The trust boundaries, from the outside in:

| Boundary | Crossed by | Protected by |
|---|---|---|
| The machine | nothing — `shieldbk` binds no network port | — |
| `shieldbk` ↔ plugin, control | configuration, **resolved secrets**, progress | mTLS over a Unix socket in a `0700` directory, with a per-process PKI |
| `shieldbk` ↔ plugin, data | the backup itself | Unix socket in a `0700` directory; **no cryptography** |
| `shieldbk` ↔ storage provider | the encrypted artifact | the storage plugin's own TLS, plus age |
| Whoever holds the artifact | nothing readable | age, with the private key never present |

Two facts about that table are worth stating explicitly.

**`shieldbk` never listens on a network socket.** It reaches out; nothing
reaches in. There is no daemon and no API.

**A plugin is inside the trust boundary by construction.** The whole point of a
source plugin is to hand it a database credential; the whole point of a storage
plugin is to hand it a bucket credential. No amount of sandboxing changes what
the job requires. Everything below is about limiting *how much* a plugin gets,
and about knowing which binary you handed it to — not about making a plugin
harmless.

## Ephemeral mTLS: the threat model

At every plugin start the core generates, in memory:

- a fresh certificate authority (`CN = shieldbk ephemeral CA`, path length 0),
- a **server** leaf signed by it, `CN`/`SAN = shieldbk-plugin`, for the plugin,
- a **client** leaf signed by it, `CN`/`SAN = shieldbk-core`, for itself.

The plugin receives, on stdin, only the CA certificate, the server certificate
and the server key. The core keeps the client key. Nothing is written to disk at
any point: a certificate on disk is a certificate somebody can steal. All of it
dies with the processes.

Both sides negotiate ALPN `h2` and require a certificate from the peer.

**What this defends against.** The realistic attack on a Unix-socket control
plane is a *local* one: another process on the same machine, running as a
different user or in a different container, that finds the socket and speaks
gRPC to it. Without client authentication that process would receive the
plugin's entire configuration — database password, bucket credentials —
by asking politely. With mandatory mTLS it is refused: the ephemeral CA signed
exactly one client certificate and that certificate never left the core's
memory.

It also defends against **cross-plugin escalation**. This is why the envelope
carries only the server bundle and never the client key: a plugin that held the
client key could connect to another plugin's control socket, present the core's
identity, and ask that plugin for *its* credentials. A compromised storage
plugin cannot use its own material to interrogate the source plugin.

Because the CA is created seconds earlier and signs exactly one client
certificate, verifying the chain against it already means "this is the core that
started me". A plugin whose TLS stack cannot inspect the peer's name — grpc-js
cannot — loses nothing by skipping that check. `server_name` and `client_name`
travel in the envelope anyway, so a plugin that *can* check has the values as
data rather than as folklore.

**What this does not defend against.**

- **Anyone running as the same user.** They can read the socket, read
  `/proc/<pid>/`, attach a debugger, or simply replace the plugin binary before
  the next run. mTLS is not a defence against your own uid.
- **Root**, obviously.
- **The plugin itself.** It is authenticated, not constrained. Authentication
  answers "who is this", never "what may they do".
- The certificates are not revocable, because they do not need to be: they
  outlive nothing.

## Why the data channel carries no TLS

The control plane is encrypted and authenticated. The data plane — the socket
the actual backup flows through — is not, and that is deliberate.

Both ends are processes **of the same user, on the same machine**, talking over
a socket inside a directory the core created with mode `0700`. Anyone who can
open that socket already *is* that user, and that user already holds the
database password, the bucket credentials, and read access to the plugin
binaries. Encrypting the data channel would not remove a single capability from
that attacker.

It would cost, on a path that moves hundreds of gigabytes, CPU on every byte —
and it would do so on the machine that is usually also serving the database.

The asymmetry is the point: **the control plane is where the secrets travel and
its volume is negligible, so it gets the cryptography.** The data plane carries
bytes that are, in the direction that matters, already encrypted by the time
they leave the core.

The concrete protections that remain on the data channel are the directory mode,
the fact that the socket is unlinked when the transfer's channel is dropped, and
the fact that the whole runtime directory is removed when the plugin is torn
down.

If your threat model includes another user on the same host reading your `0700`
directory, the data channel is not your problem — that host is.

## Secrets are references, never literals

A secret field in a plugin's schema (`secret: true`) **cannot** hold a literal
value in the configuration file. `password = "hunter2"` is a hard error naming
the field and listing the alternatives.

The reason is what a configuration file *is*: an artifact kept in git, copied
between machines, pasted into tickets, attached to bug reports, and included in
container images. A literal in there is a leak with a delay fuse. The model
simply cannot express one — it can only say *where* the value is.

### The five sources

| Reference | Reads from | Notes |
|---|---|---|
| `{ env = "VAR" }` | an environment variable of the `shieldbk` process | **Not trimmed** — an exported variable is worth exactly what was exported, and trimming could silently break a password. Visible in `/proc/self/environ` and `docker inspect`. |
| `{ file = "/path" }` | a file's contents | **Rejected if any group or other permission bit is set** (`0o077`). Trailing newlines trimmed. |
| `{ file_insecure = "/path" }` | the same, permission check skipped | Logs a warning. Exists only for orchestrator-mounted secrets. |
| `{ keyring = "service/user" }` | the system keyring, via D-Bus Secret Service | Without a slash, the user defaults to `shieldbk`. |
| `{ command = ["prog", "arg"] }` | the first line of the program's stdout | **No shell.** |

Four details of the implementation matter more than the list:

**The permission check runs on the already-open descriptor, not on the path.**
Calling `stat` and then `open` leaves a window in which the file can be swapped
between the two operations. The file is opened first and its mode read from the
descriptor.

**`file_insecure` has a deliberately awkward name.** It exists because Docker
mounts `/run/secrets` at `0444` and Kubernetes mounts secret volumes at `0644`
by default — so the correct check would rule out the most common container
deployment. Rejecting with no alternative would push people to `env`; relaxing
the check by default would be worse. It relaxes the permission check and nothing
else: a missing or unreadable file is still a hard error. The real fix is
`defaultMode: 0400` on the volume; see
[`deploy/README.md`](../deploy/README.md#1-mounted-secrets-are-world-readable-by-default).

**`command` takes an argv, not a command line.** The program and its arguments
go separately to `Command`, so an argument containing `;`, `$(…)` or `&&` is
literal text for that program and not another instruction. Injection is
eliminated by construction, not filtered by a denylist. Its `stdin` is closed so
a program that wants to prompt fails instead of hanging, and both `stdout` and
`stderr` are captured rather than inherited, so a broker that prints the secret
in the wrong place does not print it into your terminal.

**`keyring` does not work in a container**, over SSH without a graphical
session, or from `cron`. There is no session bus and no agent to serve it. That
is not a bug to work around: a per-user desktop credential store has no meaning
in an unattended scheduled job.

### The symmetric rule

**A field the plugin did *not* mark secret refuses a secret reference.**
Resolving one into a value that is then handled as ordinary configuration —
printed by `plugin docs`, echoed in a diagnostic, written to a log — would leak
it. Both halves of the rule are enforced, and both produce an error naming the
field.

### Resolution happens in the core, once

Only the core touches the sources. The plugin receives the resolved **value**
over the authenticated channel and never learns its origin. That keeps the
secret policy in a single auditable place instead of being reinvented, with
different criteria and different bugs, in every plugin.

### And a secret never travels in `argv`

`/proc/<pid>/cmdline` is world-readable, and `ps` prints it. A password passed
as `--password=hunter2` is visible to **every user on the machine** for as long
as the command runs. A plugin that shells out to a tool must pass the credential
through the child's **environment** instead, which is readable only by the
process owner. That is not perfect — it is inherited by children — but it is the
best the POSIX process model offers for handing a secret to a program you did
not write. The worked example does exactly this; see
[`writing-a-plugin.md`](plugins/writing-a-plugin.md#the-three-safety-rules-it-demonstrates).

## What the lockfile protects, and what it does not

`shieldbk` runs **no plugin binary it has not registered.** `shieldbk plugin
lock` records the SHA-256 of every `sb-plugin-*` file in `plugins.dir` into
`plugins.lock`; every subsequent run re-hashes the file on disk and refuses to
**execute** it unless the hashes match.

The verification happens *before* the process is spawned, not after. That
ordering is the whole property: a binary that is not the one you registered must
never run, because running it means handing it your credentials.

It is the same guarantee Terraform's provider lockfile gives, for the same
reason.

### What it protects against

- A plugin that was **silently updated** — by a package manager, an installer
  script, a CI job.
- A plugin **substituted** by an attacker who obtained write access to
  `plugins.dir`.
- A **volume mounted over** the plugin directory in a container, or a
  `docker cp` into a running container.
- A compromised host rewriting the file between runs.

The error is explicit and shows both hashes so it can be checked by hand:

```
the binary of plugin "mock" (…/plugins/sb-plugin-mock) has changed since it was
registered: the lockfile expected sha256 b9818b9f… and the file has e9f295e6…
If the change is expected (you updated the plugin), register it again with
`shieldbk plugin lock`. If you were not expecting it, do NOT run it: the binary
receives the credentials of your database and of your storage
```

An unregistered plugin and a changed plugin both exit **3**, and nothing is
written to the storage.

### What it does not protect against — read this part

**The lockfile protects against a binary *changing*. It does not protect against
a plugin being malicious.**

A plugin receives your credentials **by definition**. That is what it is for. A
source plugin is given the database password because it has to run the dump; a
storage plugin is given the bucket credentials because it has to do the upload.
A plugin that was hostile the first time you registered it is a plugin whose
hash matches perfectly, forever.

This is impossible to fix by construction, and it should not be papered over:

- **Registering a plugin is a decision to trust its author.** The hash proves
  the binary has not changed since you looked at it. It cannot prove you were
  right to look favourably on it.
- There is no signature verification, no publisher identity, no capability
  sandbox. A plugin is an ordinary process with your uid.
- A plugin can read every file you can read, open every network connection you
  can open, and exfiltrate anything it is handed.

What the architecture *does* buy, and it is not nothing:

- A plugin **never receives the age private key.** Encryption happens in the
  core. A compromised storage plugin sees ciphertext. A compromised source
  plugin already had the plaintext by definition — it produced it.
- A plugin **never receives the core's client certificate**, so it cannot
  impersonate the core to a sibling plugin.
- A plugin receives only the **values** of the secrets its own schema declared,
  never the other plugin's, and never the origin of its own.
- A plugin runs with a **cleared environment** except `PATH`, `HOME`, `TMPDIR`,
  `LANG` and `TZ`, so it cannot scrape a credential out of the core's
  environment.

### The lockfile hashes the entry file only

For a compiled, self-contained binary, the hash covers the whole plugin.

For an **interpreted** plugin it does not. `node_modules/` is not hashed, the
interpreter is not hashed, and nothing the script loads at runtime is hashed.
Swapping one transitive dependency changes what the plugin does while
`plugin list` still says `registered`.

For a real installation of a non-Rust plugin, compile it to a single executable
first — `bun build --compile` and its equivalents — so that what the lockfile
hashes *is* the plugin.

### Sealing it at build time

Outside a container, `plugin lock` is an installation chore somebody has to
remember. Inside an image the relationship inverts: the lock runs during
`docker build`, the image is immutable, and hash and binary travel together
under the image digest with no window in which they can drift. See
[`deploy/README.md`](../deploy/README.md#the-lockfile-is-sealed-at-build-time).

## Memory: `Secret<T>` and its limits

`Secret<T>` is the container every resolved credential travels in inside the
core.

**What it guarantees:**

- It implements **neither `Debug` nor `Display`**, so printing a credential is a
  *compile error*, not a log line. This is enforced by `trybuild` compile-fail
  tests (`crates/sb-crypto/tests/ui/`), which go red the day somebody adds a
  `#[derive(Debug)]`. `Identity` — the age private key — is protected the same
  way.
- The buffer it owns is **zeroed on drop**.
- `PartialEq` compares in constant time over the contents. It returns early on a
  length mismatch, so it leaks the length and not the value — the standard
  behaviour for credential comparison.

**What it does not guarantee — and this is the part that gets over-read:**

> `Secret<T>` prevents a credential from being *logged*. It does **not**
> guarantee that no copy survives in memory.

Concretely:

- A `String` that reallocated as it grew left its **previous buffer behind,
  unwiped**. Zeroing the final allocation does nothing for the old one.
- `Clone` creates a new, independent allocation. Two live copies means two
  buffers to wipe, and the compiler is under no obligation to keep either.
- The core takes care to wipe intermediate buffers explicitly where it can — the
  `Vec<u8>` a file secret is read into, the captured `stdout` of a `command`
  secret, and even the `stderr` it never reads, all get `zeroize()`d — but that
  is best effort against an optimising compiler and a virtual memory system, not
  a proof.
- Nothing prevents the operating system from paging a page holding a secret to
  swap. There is no `mlock`.
- A core dump of the `shieldbk` process may contain credentials.

Build a secret at its final capacity when you can, and do not assume more
protection than is actually here.

### And the core cannot guarantee any of it inside a plugin

Once a resolved secret crosses the control channel it is **in the plugin's
process**, in whatever data structure that plugin chose, in whatever language it
was written in.

The core cannot make a plugin wipe it. It cannot make a plugin avoid logging it.
It cannot stop a plugin from putting it in `argv`, where every user on the
machine can read it. `Secret<T>` is a Rust type; a plugin written in JavaScript
has a garbage-collected string that will sit in the heap until a collection that
may never come.

This is a documented limit of the design, not an oversight. It is another face
of the same fact: **a plugin is trusted by construction.** The guidance for
plugin authors is in
[`writing-a-plugin.md`](plugins/writing-a-plugin.md#what-secret-true-actually-does);
the guarantee stops at the socket.

## Third-party errors that carry secrets inside

This one is easy to miss and has bitten real projects: **an error value from a
third-party library can contain the credential that caused it**, and the moment
you `?` it into your own error type, it inherits that payload — straight into a
log line, a ticket, and a screenshot.

Three concrete cases, all present in this codebase's dependencies:

| Error | What it holds |
|---|---|
| `keyring::Error::BadEncoding(Vec<u8>)` | the **raw bytes of the credential** that failed to decode. The derived `Debug` prints them whole. |
| `std::env::VarError::NotUnicode(OsString)` | the **variable's value**, and its `Display` prints it. |
| `String::from_utf8` → `FromUtf8Error` | the **bytes that failed to parse**, retrievable and printable. |

The rule, applied throughout `sb-config`:

> **Never propagate a third-party error that could contain a secret. Map it to
> a message of your own that names the *origin* and never the value.**

In practice:

```rust
// env: the NotUnicode payload is discarded, not chained.
Err(std::env::VarError::NotUnicode(_)) => Err(SecretError::NotUtf8),
```

```rust
// keyring: Display and Debug are never used. Each variant is translated
// into a fixed description chosen here.
keyring::Error::BadEncoding(_) => "the value stored in the keyring is not UTF-8",
```

```rust
// utf-8: str::from_utf8 rather than String::from_utf8, and the error dropped.
std::str::from_utf8(&bytes)
    .map(|text| trim_trailing_newlines(text).to_owned())
    .map_err(|_| SecretError::NotUtf8)
```

The same reasoning shapes the whole `SecretError` enum: **no variant contains
the secret.** They name a path, an environment variable, a program, a keyring
entry — which is what an operator needs in order to fix the problem — and never
the value that was read. That holds for the derived `Debug` as well as for
`Display`, because every field is a string built locally rather than data coming
from the source.

Two consequences that look like missing features and are not:

- A failed `command` secret reports **only the program name**, never its output.
  A command that fails may have written the secret to stdout before failing, or
  dumped it into stderr next to the diagnosis. The exit status goes to the log,
  where the value does not travel; the error message says its output is
  deliberately omitted.
- A UTF-8 failure does not say **which** byte failed or at what offset. That
  would already be a partial leak.

If you add a dependency that produces errors from credential material, check its
`Debug` and `Display` before you chain it.

## Encryption and the key

The pipeline is `zstd → age → SHA-256`, applied in the **core**, between the two
process boundaries.

- **age** with an X25519 recipient. Each artifact is encrypted to the public key
  in the target's `recipient` field.
- The **private key never enters the core** except for `restore`, where it is
  read from the file named by `--identity`.
- **No plugin ever sees the private key**, on any code path.
- `shieldbk keygen --output PATH` writes the key file with mode `0600` and
  **refuses to overwrite an existing file** — losing a key silently is
  unrecoverable, so the command will not do it.
- The `recipient` in the manifest is a **public** key and is not a secret:
  knowing who an artifact is addressed to does not help decrypt it.

The shutdown *order* of the pipeline layers is a correctness property with a
security consequence: zstd must emit its final frame inside the age layer, and
age must close its last AEAD block before the last hashed byte is counted.
Reversing it produces a truncated artifact whose failure surfaces only at
restore time — a backup that looks fine until you need it.

On restore, integrity is checked twice, and the two catch different things:

- **age's AEAD** verifies every block as it is read, so tampered ciphertext
  fails on read.
- **The digest from the manifest** catches something AEAD cannot: that the
  storage served a *different* artifact from the one requested. A well-formed
  foreign artifact addressed to the same identity would decrypt without
  complaint.

**Back up the key file somewhere that is not the machine being backed up.** It
is the only thing that can restore anything, and `keygen` says so in as many
words.

## Verification without the key

Because it is the **ciphertext** that is hashed, `shieldbk verify` streams the
artifact from the storage, hashes it, compares against the manifest, and throws
the bytes away.

`run_verify` takes no `Identity` — not as a matter of policy but because the
operation contains nothing that decrypts. The consequences are worth being
explicit about:

- The machine that runs your nightly integrity check **holds no key material**.
  Compromising it yields ciphertext and metadata, not plaintext.
- Verification can be delegated to infrastructure you trust less than your
  restore path.
- Verification costs constant memory: a 300 GB artifact verifies in the same RAM
  as a 3 KB one, because the bytes go from the pipe to the hasher to a sink.

What verification proves: the object at that key is byte-for-byte the object
recorded in the manifest. What it does **not** prove: that the plaintext inside
is a valid database dump. That requires an actual restore, and a restore drill
is not something a hash can substitute for.

## Process isolation

Each plugin process gets:

- **Its own process group** (`process_group(0)`), so the core can kill the whole
  tree. This is what stops a `pg_dump` from outliving a cancelled backup.
- **A cleared environment**, except `PATH`, `HOME`, `TMPDIR`, `LANG` and `TZ`;
  `PATH` falls back to `/usr/local/bin:/usr/bin:/bin`. A plugin cannot read a
  credential out of the core's environment.
- **Its own runtime directory**, mode `0700`, under `$XDG_RUNTIME_DIR` or
  `TMPDIR`, holding its control socket and its data sockets, removed on
  teardown. The mode is set at creation **and again afterwards**, so a permissive
  umask cannot widen it.
- **Piped stdio.** stdin carries the envelope and is then closed; stdout carries
  exactly one line; stderr is relayed line by line into the core's log, so a
  plugin that fails does not fail in silence.

Teardown is `Shutdown` RPC → drop the channel → **`SIGKILL` to the process
group** → `wait()`. There is no `SIGTERM`; the grace period is the RPC itself.
The `wait()` is not optional — a process nobody reaps becomes a zombie, and at
one backup an hour they accumulate.

`shieldbk` reaps *its own* children. It is not an init system and does not adopt
arbitrary orphans, which matters when it runs as PID 1 in a container; see
[`deploy/README.md`](../deploy/README.md#2-zombie-processes-when-shieldbk-is-pid-1).

What this is **not**: a sandbox. There is no seccomp filter, no namespace, no
capability drop, no user separation. A plugin runs with your uid and can do
anything you can do. Container-level hardening — `--read-only`, `--cap-drop
ALL`, `no-new-privileges`, a non-root uid — is in the deployment guide and is
where that kind of confinement belongs.

## A restore that fails may leave plaintext behind

The most important operational hazard in the system, stated plainly.

age delivers AEAD blocks **already verified, incrementally**. Faced with a
truncated artifact, the read fails only *after* everything before the cut has
been handed to the source — legitimate plaintext, but partial. The digest check
is worse still: it can only run once the entire stream has been read, by which
point the source has received all of it.

The core does the only thing available to it: on failure it **abandons** the
source's channel rather than shutting it down in an orderly way, so the source
observes a cut and not a normal end of stream; it aborts both transfers; and it
returns an error without waiting for the plugins to claim success.

That is not sufficient, and it is worth saying so rather than implying
otherwise: **discarding what was written is the source plugin's
responsibility**, because it is the only party that knows what undoing means.
`pg_restore --single-transaction` is one correct answer — a half-finished dump
is never committed. A source that writes files directly must bring its own.

If you write a source plugin, decide what a cut restore means for your data
*before* you ship it.

## Out of scope

Things this system does not attempt, so nobody assumes otherwise:

- **No sandboxing of plugins.** Authentication is not authorisation.
- **No key management.** No rotation, no escrow, no splitting, no HSM. One age
  key pair, one file, your responsibility.
- **No signature verification of plugins.** Only hash pinning of a binary you
  already chose to trust.
- **No protection against a compromised machine.** Anything running as your uid
  has already won.
- **No network hardening**, because nothing listens on the network.
- **No audit log.** `-vv` logs to stderr; there is no tamper-evident record.
- **No anti-forensics.** Swap, core dumps and `/proc` are not defended against.
- **No multi-tenancy.** One user, one configuration, one key.
- **Linux only.** The permission checks are POSIX modes and the transport is
  Unix sockets; there is no Windows equivalent implemented.

### Reporting a problem

Security issues should be reported privately to the maintainers rather than
opened as a public issue.
