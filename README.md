# ShieldBackups

`shieldbk` takes a backup of something, compresses it, encrypts it to an
[age](https://age-encryption.org) public key and uploads it to object storage —
in a single streaming pass, without ever writing the dump to local disk. The
things it backs up and the places it stores them are **plugins: separate
processes** that speak a small gRPC protocol over a Unix socket, the way
Terraform talks to its providers. The core never learns what a database, a
bucket or a tar archive is; it only moves bytes between two processes and
encrypts them on the way through.

The point of paying the price of a process boundary is that **a plugin can be
written in any language, by somebody who does not know Rust**, and that a plugin
never sees the private key: it is handed a byte stream, not a decryption
capability. [`docs/plugins/examples/command-plugin/`](docs/plugins/examples/command-plugin/)
is a complete, working plugin in about 350 lines of JavaScript that proves it.

- **Status:** 0.1.0. PostgreSQL is not in this repository yet; the shipped
  plugins are `r2` (Cloudflare R2 / any S3-compatible store) and `mock` (a test
  fixture that is also the fastest way to try the whole cycle).
- **Platform:** Linux. The transport is Unix sockets and the permission checks
  are POSIX modes.
- **License:** Apache-2.0. No `unsafe` anywhere in the workspace
  (`unsafe_code = "forbid"`).

---

## Table of contents

- [How it works](#how-it-works)
- [Why the ciphertext is what gets hashed](#why-the-ciphertext-is-what-gets-hashed)
- [Getting started in five minutes](#getting-started-in-five-minutes)
- [Configuration](#configuration)
- [The commands](#the-commands)
- [Security, plainly](#security-plainly)
- [Memory and throughput](#memory-and-throughput)
- [What it does not do](#what-it-does-not-do)
- [Building from source](#building-from-source)
- [Where to go next](#where-to-go-next)

---

## How it works

A backup is one pass through a pipe with two process boundaries in it:

```
┌────────────────┐                    ┌──────────────┐                    ┌─────────────────┐
│  source plugin │ ──[data socket]──▶ │     core     │ ──[data socket]──▶ │ storage plugin  │
│  (own process) │                    │              │                    │  (own process)  │
└────────────────┘                    │  zstd        │                    └─────────────────┘
        ▲                             │   → age      │                            ▲
        │                             │   → SHA-256  │                            │
        │                             └──────────────┘                            │
        │                                    │                                    │
        └──────── gRPC over mTLS ────────────┴────────── gRPC over mTLS ──────────┘
                  (control plane, Unix socket, ephemeral PKI)
```

Nothing is ever materialised whole. The dump leaves the source as a stream,
crosses the core being compressed, encrypted and hashed on the fly, and leaves
for the storage as another stream. A one-terabyte backup uses the same memory as
a one-megabyte one.

**Two planes, deliberately different.**

| | Control plane | Data plane |
|---|---|---|
| Protocol | gRPC / HTTP-2 | raw bytes, no framing |
| Transport | Unix socket | Unix socket |
| Security | mTLS with a **per-run, in-memory PKI** | none — see [security.md](docs/security.md) |
| Carries | configuration, resolved secrets, progress | the backup itself |
| Volume | kilobytes | terabytes |

The core generates the whole PKI — a fresh CA, a server leaf for the plugin and
a client leaf for itself — at every plugin start, hands the plugin its three PEMs
on **stdin**, and never writes any of it to disk. The plugin creates no keys and
stores none. When the process ends, the certificates that could authenticate to
it stop existing.

**Two axes, and `Source` does not mean "database".** Every target names two
plugins:

- **`source`** — anything that can be serialised into a byte stream and rebuilt
  from one. `pg_dump`/`pg_restore` is the obvious case, but a directory piped
  through `tar`, a Docker volume, a virtual machine's disk or a bucket being
  copied to another provider all fit the same contract. The RPCs are called
  `Dump` and `Restore` because that is the *operation*, not the kind of thing.
- **`storage`** — anywhere that stream can be kept and fetched back.

A plugin may implement one axis or both.

## Why the ciphertext is what gets hashed

The pipeline order is `zstd → age → SHA-256`, so the digest recorded in the
manifest is the digest of the **encrypted** bytes.

That one decision is what makes `shieldbk verify` possible:

```
storage plugin ──[data socket]──▶ core ──▶ SHA-256 ──▶ /dev/null
```

A machine can prove that its backups are still byte-for-byte intact **without
holding anything that could read them**. `verify` takes no `--identity` — not
because it declines to use one, but because it cannot: there is nothing in the
operation that decrypts. The nightly integrity check on the backup server needs
no key material at all, so compromising that server yields no plaintext.

The artifact is also never loaded into memory to be checked: it is streamed
through the hasher into a sink, so verifying a 300 GB artifact costs the same
RAM as verifying a 3 KB one.

## Getting started in five minutes

This is the real cycle, run against the `mock` plugin, which is both a source
and a storage target and needs no credentials. Every command below was executed
exactly as written.

```sh
# 0. Build the CLI and the mock plugin, then set up a scratch directory.
cargo build --release -p sb-cli -p sb-plugin-mock
REPO=$PWD

mkdir -p ~/demo/plugins ~/demo/backups
cp "$REPO/target/release/sb-plugin-mock" ~/demo/plugins/
export PATH="$REPO/target/release:$PATH"
cd ~/demo
```

### 1. Generate the key every backup is encrypted to

```sh
shieldbk keygen --output key.txt
```

```
the private key was written to `key.txt` with 0600 permissions.
There is no way to recover it: whoever loses that file loses every backup encrypted to it.
# public key: age1rtq8xv2ywzqhkjvwqsykqxyggjk8nt67979sh9x2jxau2tf3cpeqkf67vy
Copy that public key into the `recipient` field of your target.
```

`keygen` needs no configuration file — it is what you run *before* there is one.
The file is created `0600` and an existing one is never overwritten. Back it up
somewhere that is not the machine being backed up: **that file is the only thing
that can restore anything.**

### 2. Write the smallest configuration that works

```sh
RECIPIENT=$(sed -n 's/^# public key: //p' key.txt)

cat > config.toml <<EOF
[plugins]
dir      = "$HOME/demo/plugins"
lockfile = "$HOME/demo/plugins.lock"

[[target]]
name      = "app"
source    = "mock"
storage   = "mock"
recipient = "$RECIPIENT"

[target.source_config]
dir  = "$HOME/demo/backups"
seed = 7
size = 1048576

[target.storage_config]
dir = "$HOME/demo/backups"
EOF
```

Only the `recipient` and the two plugin names are the core's business. Whatever
goes in `source_config` and `storage_config` is opaque to it and is validated
against the schema the plugin itself publishes — ask a plugin what it accepts
with `shieldbk plugin docs <name>`.

### 3. Authorise the plugin binaries

```sh
shieldbk --config config.toml plugin lock
```

```
1 plugins registered in `/home/you/demo/plugins.lock`: mock
```

`shieldbk` runs **no binary it has not registered**. `plugin lock` records the
SHA-256 of every `sb-plugin-*` file in the directory; every later run re-hashes
the file and refuses to execute it if it differs. Skipping this step is not
optional — the first `backup` exits 3 and tells you so.

### 4. Diagnose before you trust it

```sh
shieldbk --config config.toml doctor
```

```
app - ok
  ok [config] recipient: age1rtq8xv2ywzqhkjvwqsykqxyggjk8nt67979sh9x2jxau2tf3cpeqkf67vy
  ok [source] source version: mock
  ok [source] directory: /home/you/demo/backups exists
  ok [storage] directory: /home/you/demo/backups exists
```

`doctor` starts both plugins, configures them (resolving every secret exactly as
a real backup would) and asks each for its own preflight. It never stops at the
first problem: a report that told you one thing at a time would cost one full
round trip per mistake. A failing diagnosis exits **4** and still prints the
whole report.

### 5. Back up

```sh
shieldbk --config config.toml backup
```

```
app: app/2026/08/23/app-20260823T023625Z-mock.dump.zst.age (1048576 plaintext bytes -> 1049173 encrypted)
1/1 backups completed
```

Next to the artifact the storage receives a `*.manifest.json` describing it:

```json
{
  "version": 1,
  "target": "app",
  "source": { "plugin": "mock", "plugin_version": "0.1.0", "source_version": "mock" },
  "created_at": "2026-08-23T02:36:25Z",
  "artifact_key": "app/2026/08/23/app-20260823T023625Z-mock.dump.zst.age",
  "plaintext_bytes": 1048576,
  "ciphertext_bytes": 1049173,
  "plaintext_sha256": "82d97740c0817ac1d668db53ba9293fd443d2f87eea77d698d17f229c86b379c",
  "ciphertext_sha256": "74b0a3237d2479144773fe3cbc976af00ee9ba725d058f36a0a41c17bd96a77d",
  "compression": { "algorithm": "zstd", "level": 6 },
  "encryption": { "algorithm": "age", "recipient": "age1rtq8xv2ywz…" }
}
```

`verify` and `restore` read that file rather than inferring anything from the
key: a name can be changed, a manifest is authoritative.

### 6. Verify — without the key

```sh
shieldbk --config config.toml verify app
```

```
ok app/2026/08/23/app-20260823T023625Z-mock.dump.zst.age: 1049173 bytes
1/1 artifacts of `app` verified
```

Note that `key.txt` was not mentioned. It could be on a different continent.

### 7. Restore

```sh
KEY=$(shieldbk --config config.toml --format json backup \
      | python3 -c 'import sys,json; print(json.load(sys.stdin)["targets"][0]["artifact_key"])')

shieldbk --config config.toml restore app "$KEY" --identity key.txt
```

```
app: restored 1048576 bytes from app/2026/08/23/app-20260823T023637Z-mock.dump.zst.age
```

That is the entire lifecycle. A real installation swaps `mock` for a source
plugin that knows your data and a storage plugin that knows your bucket; nothing
else about the flow changes.

## Configuration

One TOML file, `~/.shieldbk/config.toml` unless `--config` says otherwise.

```toml
[plugins]
dir      = "~/.shieldbk/plugins"      # where sb-plugin-<name> binaries live
lockfile = "~/.shieldbk/plugins.lock" # the hashes that authorise them

[defaults]
compression_level = 6                 # zstd, 1..=22
artifact_template = "{target}/{yyyy}/{mm}/{dd}/{target}-{timestamp}-{source}.dump.zst.age"

[[target]]
name      = "production"
source    = "postgres"                # -> <dir>/sb-plugin-postgres
storage   = "r2"                      # -> <dir>/sb-plugin-r2
recipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
# compression_level = 12              # optional per-target override
# artifact_template = "…"             # optional per-target override

[target.source_config]                # opaque to the core; the plugin's schema rules
host     = "db.internal"
port     = 5432
database = "app"
user     = "backup"
password = { file = "/run/secrets/db_password" }

[target.storage_config]
account_id        = "0123456789abcdef0123456789abcdef"
bucket            = "backups"
access_key_id     = { env = "R2_ACCESS_KEY_ID" }
secret_access_key = { file = "/run/secrets/r2_secret" }
```

Unknown keys are a hard error, not a shrug: a typo in a field name is a field
that silently does nothing, and that is how a backup ends up not encrypted to
who you thought.

**A secret field never takes a literal.** The configuration file is the kind of
artifact that lands in git, gets copied between machines and shows up pasted
into a ticket, so the model simply cannot express a password — only where to
find one. The five sources are:

| Reference | Where it reads from |
|---|---|
| `{ env = "VAR" }` | an environment variable of the `shieldbk` process |
| `{ file = "/path" }` | a file, **rejected unless no group/other bit is set** |
| `{ file_insecure = "/path" }` | the same, permission check skipped, warning logged |
| `{ keyring = "service/user" }` | the system keyring (Secret Service / D-Bus) |
| `{ command = ["prog", "arg"] }` | an argv — no shell, so no injection — first line of stdout |

The reverse is enforced too: a field the plugin did **not** declare secret
refuses a reference, because resolving one into a value that then gets printed
in `plugin docs` output or a log would leak it.

**Artifact keys** come from `artifact_template`. The placeholders are
`{target}`, `{source}`, `{storage}`, `{timestamp}` (`YYYYMMDDTHHMMSSZ`, always
UTC), `{yyyy}`, `{mm}`, `{dd}`. UTC is not configurable on purpose: a nightly
backup must not change its name because the server entered daylight saving time,
and two replicas in different time zones must produce the same key for the same
instant. The rendered key is validated — no absolute paths, no `..`, no `.`, no
empty segments, no control characters, at most 1024 bytes — and the validation
runs on the **filled** key, so a target named `..` is caught just like a `..`
written into the template by hand.

## The commands

Run `shieldbk --help`, or `shieldbk <command> --help`, for the authoritative
version. Global options — `--config`, `--format human|json`, `--jobs N`,
`-v`/`-vv`/`-vvv` — work before or after the subcommand.

### `shieldbk keygen [--output PATH]`

Generates an age key pair. With `--output` the private key is written `0600` and
an existing file is refused; without it, the key goes to stdout in
`age-keygen`'s format (`shieldbk keygen > key.txt` works, but the redirect will
not give you `0600` — prefer `--output`). The reminder text goes to stderr.

### `shieldbk backup [TARGET]`

Backs up one target, or every target when none is named. `--jobs N` runs N
targets at a time; the default is **1**, because several simultaneous dumps
compete for the same disk and the same database server, and the loser is the
server that is serving your users.

```sh
shieldbk backup                       # everything
shieldbk backup production            # one target
shieldbk --jobs 3 --format json backup
```

### `shieldbk verify TARGET [ARTIFACT]`

Streams each artifact from the storage, hashes it and compares against the
manifest — digest **and** byte count. With no artifact named it lists the
target's prefix and checks them all, and one bad artifact never stops the next.
No private key involved.

### `shieldbk restore TARGET ARTIFACT --identity PATH`

Downloads, checks the digest against the manifest, decrypts, decompresses and
hands the plaintext to the source plugin. `--identity` is mandatory: without a
private key there is nothing to restore with, so the CLI will not even start a
plugin.

Read the warning in [Security, plainly](#security-plainly) about what a *failed*
restore can leave behind.

### `shieldbk doctor [TARGET]`

Starts the plugins, configures them, and runs everyone's preflight. Reports
everything it found, with an origin (`config`, `source`, `storage`) and a remedy
per failing check. Exits 4 if anything failed — which makes a scheduled
`doctor` a usable liveness check for the whole configuration.

### `shieldbk plugin <list|docs|verify|lock>`

```sh
shieldbk plugin list        # binaries found, and whether they are registered
shieldbk plugin lock        # register every sb-plugin-* in plugins.dir
shieldbk plugin verify      # re-hash them all, without starting any
shieldbk plugin docs mock   # ask a plugin what it accepts
```

```
configuration fields of `mock`

FIELD  TYPE  REQ  SECRET  DEFAULT
dir    path  yes  no      -
    Directory where the storage target keeps artifacts and the source writes restored data
seed   int   no   no      42
    Seed for the source's deterministic generator
size   int   no   no      1048576
    Bytes the source emits on each dump
```

`plugin docs` prints the *schema*, never a configured value, and `lock`/`list`
work on a configuration that has no `[[target]]` at all — which is exactly the
state of a machine that has just installed the plugins.

### `shieldbk storage gc TARGET`

Asks the storage plugin to abort incomplete multipart uploads under the target's
prefix. A failed upload leaves orphaned parts that the provider keeps billing
for. It is deliberately scoped to the target's prefix: a bucket may hold more
than this `shieldbk`'s backups, and aborting somebody else's uploads would be
worse than the problem it came to solve.

### Exit codes

```
0   success
2   configuration error   — the TOML, a secret reference, an age recipient
3   plugin error          — missing, unregistered, altered or crashed plugin
4   operation error       — the backup itself failed: source, network, storage
```

They are stable and meant to be routed to different people. `--format json`
prints a single object on stdout — logs always go to stderr, so the two never
mix even at `-vvv`:

```json
{"command":"backup","failed":0,"ok":true,"targets":[{"artifact_key":"app/2026/08/23/app-20260823T023637Z-mock.dump.zst.age","ciphertext_bytes":1049166,"ciphertext_sha256":"d640a867…","ok":true,"plaintext_bytes":1048576,"target":"app"}],"total":1}
```

On failure the same object carries `"ok": false`, a `"class"` (`"config"`,
`"plugin"`, `"operation"` — the string form of the exit code) and `"error"`.

## Security, plainly

The full argument, with the threat model and the places where the guarantees
stop, is in **[docs/security.md](docs/security.md)**. The short version, and the
part that is easiest to over-read:

**The lockfile protects against a binary *changing*, not against a plugin being
malicious.** It is the same guarantee Terraform's provider lockfile gives. It
catches a silent auto-update, a `PATH` substitution, a compromised host
rewriting the file, a volume mounted over the plugin directory. It does not and
cannot catch a plugin that was hostile the first time you registered it —
because **a plugin is handed your credentials by definition**. That is what the
architecture is for: the core resolves the secret and passes the *value* over
the authenticated channel so the plugin never learns where it came from, but the
plugin does receive it. Registering a plugin is a decision to trust its author,
and no hash can make that decision for you.

What the design does buy you, stated without inflation:

- **A plugin never receives the private key.** Encryption happens in the core.
  A compromised storage plugin gets ciphertext; a compromised source plugin
  already had the data.
- **A plugin never receives the core's client certificate**, only the server
  bundle — so it cannot impersonate the core to another plugin and ask it for
  credentials.
- **Nothing about the session survives it.** The CA, both leaves and both
  private keys are generated per plugin start, live in memory and die with the
  process.
- **A secret is never a literal in the configuration** and never travels in
  `argv`, where `/proc/<pid>/cmdline` and `ps` would publish it to every user on
  the machine.
- **`verify` cannot decrypt**, so the machine that checks your backups nightly
  is not a machine that can read them.

And what it does not buy you:

- The core cannot guarantee that a plugin wipes a credential from its own
  memory. Once the value crosses the socket it is the plugin's process.
- `Secret<T>` stops a credential from being printed by accident and wipes the
  buffer it owns on drop. It does **not** promise that no copy survives — a
  `String` that reallocated as it grew left its old buffer behind unwiped.
- The data plane carries no TLS. Both ends are the same user on the same
  machine, inside a `0700` directory; anyone who can open that socket already
  *is* that user and already has the credentials.
- **A failed restore may leave partial plaintext in the source.** age hands over
  verified AEAD blocks incrementally, so a truncated artifact fails only after
  everything before the cut has already been written. The core cuts the source's
  channel abruptly rather than closing it cleanly — so the source sees damage,
  not a normal end of stream — but *discarding* what arrived is the source
  plugin's job, because only it knows what undoing means. The PostgreSQL plugin's
  answer is `pg_restore --single-transaction`; a source that writes files
  directly has to bring its own.

## Memory and throughput

Measured, not estimated. `crates/sb-cli/tests/memory.rs` runs `shieldbk` as a
child and samples `/proc/<pid>/status` for the core **and every descendant** —
measuring only the core would miss a plugin that accumulates. Figures in MiB,
`x86_64`, Linux 6.17, 16 cores, `release`; "at once" is the peak of
`core + plugins` within a single sample, which is what has to fit in a container
limit.

| Scenario | Core | Plugins | At once |
|---|---:|---:|---:|
| backup 64 MiB | 15.2 | 14.6 | **29.8** |
| backup 256 MiB | 15.1 | 14.8 | **29.9** |
| backup 1 GiB | 15.3 | 14.8 | **30.0** |
| backup 2 GiB | 15.3 | 15.2 | **30.4** |
| verify 1 GiB | 9.8 | 7.6 | **17.4** |
| restore 1 GiB | 12.3 | 15.1 | **27.4** |
| 3 targets × 256 MiB, `--jobs 1` | 15.6 | 15.3 | **30.8** |
| 3 targets × 256 MiB, `--jobs 3` | 26.0 | 44.7 | **70.7** |

Read the first four rows together: **32× the data costs 1.02× the memory.** Each
extra concurrent target adds about **20 MiB**. End-to-end throughput is
**≈ 400 MiB/s**; the data socket on its own, with no pipeline attached, has been
measured at **≈ 3.7 GB/s**, which is why it is worth keeping framing and TLS off
it.

Memory is flat in the size of the input because nothing is buffered end to end:
the dump goes from one socket, through the compressor, the encryptor and the
hasher, into the other socket.

Reproduce it with:

```sh
cargo test --release --test memory -- --ignored --nocapture
```

Those tests are `#[ignore]`d because they move gigabytes; `--nocapture` is what
makes the numbers visible, and `--release` matters — the debug profile allocates
differently and its figures mean nothing.

**One number is deliberately *not* in that table.** The R2 plugin's multipart
uploader buffers each part in memory and keeps several in flight, so its ceiling
is `part_size_mb × concurrency` = **64 MiB × 4 = 256 MiB by default**, and you
have to add it. The 30 MiB figure was measured against the mock storage, which
writes each artifact in one call and never chunks. A single target going to R2
with the defaults wants roughly `30 + 256 = 286 MiB`; the trade-offs, and how to
lower it, are in [`deploy/README.md`](deploy/README.md#sizing-how-much-memory-and-cpu-to-give-it).

## What it does not do

Read this section before adopting it. Winning the wrong user is worse than
losing them.

- **No incremental backups. No deduplication.** Every run is a complete
  snapshot, compressed and encrypted from scratch. Ten daily backups of a 500 GB
  tree cost ten times the compressed size of that tree, and ten times the time.
- **No retention or pruning.** Nothing deletes an old artifact. `storage gc`
  aborts incomplete *uploads*; it does not implement a policy. Expiring old
  backups is a lifecycle rule on your bucket, or a cron job of your own.
- **No scheduler and no daemon.** `shieldbk` starts, does one thing and exits.
  Point cron, a systemd timer or a Kubernetes `CronJob` at it.
- **No automatic retries.** A transient network failure fails the run and exits
  4. Retry policy belongs to whatever scheduled it, where the backoff can be
  seen and tuned.
- **No backup catalogue.** There is no index; `verify` and `restore` list the
  storage and read manifests.
- **Linux only.**

**If you have a 500 GB tree that changes very little between runs, you want
[restic](https://restic.net) or [borg](https://borgbackup.org), not this.**
Their whole design is deduplicated incremental snapshots, and that is precisely
the problem `shieldbk` does not solve. `shieldbk` is for the case where the unit
of backup is a dump that has to be produced fresh every time anyway — a database,
a volume, a serialised bucket — where what you want is that the dump never
touches local disk, is encrypted before it leaves the process, can be verified
without the key, and comes from a plugin you can write yourself in an afternoon.

## Building from source

```sh
cargo build --release                     # everything
cargo build --release -p sb-cli           # just the CLI
```

Rust 1.92 (pinned in `rust-toolchain.toml`). The binaries land in
`target/release/`: `shieldbk`, `sb-plugin-r2`, `sb-plugin-mock`. Install the
plugins by copying them into `plugins.dir` under their own names —
`sb-plugin-<name>` is the only lookup rule — and running `shieldbk plugin lock`.

```sh
cargo test --workspace --all-features -- --test-threads=1
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check
```

`--test-threads=1` is not optional: several tests start real plugin processes
and get in each other's way otherwise.

## Where to go next

| | |
|---|---|
| [`deploy/README.md`](deploy/README.md) | Containers, Kubernetes `CronJob`, secret permissions, sizing, exit-code routing. **Start here to run it in production.** |
| [`docs/plugins/writing-a-plugin.md`](docs/plugins/writing-a-plugin.md) | How to write a plugin, in Rust and outside it — including the three traps that are invisible until they bite. |
| [`docs/plugins/protocol-reference.md`](docs/plugins/protocol-reference.md) | Every RPC, message and field; the mandatory call order; the versioning policy. |
| [`docs/security.md`](docs/security.md) | The security decisions and, more usefully, where each one stops. |
| [`docs/plugins/examples/command-plugin/`](docs/plugins/examples/command-plugin/) | A working non-Rust plugin. `./try-it.sh` runs a real backup and restore. |
| `crates/sb-proto/proto/shieldbk/v1/plugin.proto` | The contract itself. |
