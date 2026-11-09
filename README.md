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

- **Status:** 0.1.0. The shipped plugins are `postgres` (wraps `pg_dump`/
  `pg_restore`), `r2` (Cloudflare R2 / any S3-compatible store), `webhook` (a notifier: it
  POSTs the result of every command to Slack, Discord or any URL) and `mock` (a
  test fixture that is also the fastest way to try the whole cycle).
- **Platform:** Linux. The transport is Unix sockets and the permission checks
  are POSIX modes.
- **License:** Apache-2.0. No `unsafe` anywhere in the workspace
  (`unsafe_code = "forbid"`).

---

## Table of contents

- [Why ShieldBackups](#why-shieldbackups)
- [Advantages](#advantages)
- [How it works](#how-it-works)
- [Why the ciphertext is what gets hashed](#why-the-ciphertext-is-what-gets-hashed)
- [Getting started in five minutes](#getting-started-in-five-minutes)
- [Configuration](#configuration)
- [Notifications](#notifications)
- [The commands](#the-commands)
- [Security, plainly](#security-plainly)
- [Memory and throughput](#memory-and-throughput)
- [What it does not do](#what-it-does-not-do)
- [Building from source](#building-from-source)
- [Where to go next](#where-to-go-next)

---

## Why ShieldBackups

Most backup tooling makes one of two choices, and both cost something:

- **A single monolithic binary that knows about Postgres, MySQL, S3, GCS,
  encryption and compression all at once.** Adding a new source or a new
  destination means recompiling, and often means trusting a maintainer's
  release cycle for a feature you need next week.
- **A pile of shell scripts stitched together with cron**, each one calling
  `pg_dump` and piping it into whatever uploads to storage this month. It
  works until someone forgets `--single-transaction`, until a secret ends up
  in `ps`, until nobody remembers which script is authoritative.

ShieldBackups' answer is the process-boundary plugin architecture described
below: pay the cost of an RPC call per plugin operation, and get back a system
where a plugin can be written in any language by someone who has never seen
the core's source, where the core's security guarantees (streaming, no
plaintext on disk, ephemeral keys, verify-without-decrypt) apply to every
plugin automatically because they live in the one place every plugin's bytes
have to pass through, and where a broken or malicious plugin is contained by
the shape of the contract: a storage plugin only ever receives ciphertext, and
a source plugin never receives the encryption key.

The design bias that follows from this: ShieldBackups does **full snapshots**,
not incremental or deduplicated backups. That is what a byte-stream contract
between two subprocesses naturally supports, and it is why the tool competes
with `pg_dump`-and-upload workflows rather than with block-level backup
systems like restic or Borg.

## Advantages

Stated plainly, backed by what is actually measured and tested, not by
marketing:

- **Memory does not scale with backup size.** The whole pipeline is one
  streaming pass; nothing is buffered whole. A 64 MiB backup and a 2 GiB
  backup both fit comfortably under 31 MiB of combined core+plugin memory —
  see the numbers in [Memory and throughput](#memory-and-throughput). A
  container's memory limit does not have to grow with the database.
- **A compromised plugin's blast radius is architecturally bounded.** The
  private key never leaves the core; a storage plugin handles ciphertext
  only, and a source plugin already had the data it produces. Credentials
  cross the wire only as resolved values over an ephemeral, per-run mTLS
  channel — never as a literal in a config file that ends up in git, never in
  a process's `argv`, where `ps` and `/proc/<pid>/cmdline` would publish it to
  every user on the machine.
- **Backups are verifiable without the ability to read them.** `shieldbk
  verify` re-streams an artifact and checks its hash against the manifest
  with no private key involved — the machine that checks your backups nightly
  does not have to be a machine that can decrypt them.
- **Extending it costs a plugin, not a fork.** A new source or a new storage
  target is a separate binary that implements a handful of RPCs; the core,
  the CLI, the security model and every other plugin are untouched.
- **A restore that fails partway does not corrupt what was already there.**
  `pg_restore --single-transaction` rolls back a truncated restore instead of
  leaving the database half rewritten, and the contract asks every other
  source plugin to make the same promise its own way.
- **No `unsafe` anywhere in the workspace** (`unsafe_code = "forbid"`,
  enforced at the lint level, not by convention), Apache-2.0, permissively
  licensed dependencies only, audited with `cargo deny` on every change to
  the dependency tree.
- **Tested against the real thing, not a mock of it, where it matters.** The
  R2 plugin's integration suite runs against a real S3-speaking server
  (MinIO) in Docker; the PostgreSQL plugin's runs a real dump-and-restore
  round trip against a real PostgreSQL server in Docker, checking that the
  rows that come out are the rows that went in — and neither requires
  installing anything beyond Docker on the machine that runs them.

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
# retention_days = 5                  # `storage prune` deletes older artifacts; unset means keep forever
# [defaults.retention]                # ...or a grandfather-father-son schedule (not both)
# keep_daily = 7                      # newest artifact of each of the last 7 days that have one
# keep_weekly = 4
# keep_monthly = 12
# keep_yearly = 3

[[target]]
name      = "production"
source    = "postgres"                # -> <dir>/sb-plugin-postgres
storage   = "r2"                      # -> <dir>/sb-plugin-r2
recipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
# compression_level = 12              # optional per-target override
# artifact_template = "…"             # optional per-target override
# retention_days = 5                  # optional per-target override (or a `[target.retention]` table)

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

# [target.drill]                      # optional: what `shieldbk drill` asks after restoring
# check = "SELECT count(*) > 0 FROM users"
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

## Notifications

`shieldbk` does not know what Slack, Discord, Telegram or a mailbox is, and it
never will: **notifying is a plugin role**, like a source or a storage. After
`backup`, `restore`, `verify`, `drill`, `doctor`, `storage gc` and `storage prune`,
every `[[notify]]` block that asked to hear about the outcome gets the same JSON
document `--format json` prints, and its plugin decides what to do with it.

```toml
[[notify]]
plugin = "webhook"          # -> <dir>/sb-plugin-webhook
on     = "failure"          # "failure" (default), "success" or "always"

[notify.config]             # opaque to the core; the plugin's schema rules
url    = { env = "SLACK_WEBHOOK_URL" }
format = "slack"
```

- **`on = "failure"` is the default**, because an alert that fires on every
  success is one people learn to ignore. A dead-man's-switch ping is
  `on = "success"`: the thing that pages you is the ping *not* arriving.
- **A notification never changes the outcome.** The exit code and stdout are
  the command's, untouched; a notifier that cannot be reached is a `warning:` on
  stderr, because a silent alerting failure is exactly what alerting exists to
  prevent. Each notifier has 30 seconds, and is killed when they run out.
- **Same rules as any plugin**: the binary must be registered with
  `shieldbk plugin lock`, it talks over mTLS, and its secrets are references,
  never literals.

The official `webhook` notifier POSTs to a URL, and its `format` is `json` (the
report exactly as `--format json` prints it, for n8n, healthchecks.io or your
own endpoint), `slack` or `discord`. The URL is a secret because it carries the
token, so it is only ever a reference; it is never logged or echoed in an
error, redirects are not followed, and anything but `https://` is refused
unless the host is loopback or `allow_http = true`.

Writing a notifier for a channel nobody has covered yet is one RPC — see
[`docs/plugins/writing-a-plugin.md`](docs/plugins/writing-a-plugin.md), and
[`docs/plugins/examples/folder-plugin/`](docs/plugins/examples/folder-plugin/)
for one that tells Telegram.

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

### `shieldbk drill TARGET --identity PATH [--artifact KEY]`

A backup that has never been restored is a hope, not a backup. `drill` is how a
target proves otherwise, on a schedule: it restores the target's **newest**
artifact into a disposable place, asks the question you wrote, reports the
answer, and throws the place away — whatever happened in between.

```toml
[[target]]
name = "app"
# ...source, storage, recipient as usual...

[target.drill]
check = "SELECT count(*) > 0 FROM users"   # must return a single boolean

[target.drill.source_config]               # optional: laid over the target's own
host = "staging-db.internal"
user = "drill"                             # a role with CREATEDB
```

```sh
shieldbk drill app --identity key.txt
```

```
app: drill passed: restored 1048576 bytes from app/2026/08/23/app-20260823T023637Z-postgres.dump.zst.age; check: the check returned true (2.3s)
```

- **It cannot restore over the database you back up.** The *source plugin*
  makes the disposable place — for PostgreSQL, a `drill_<time>_<pid>` database
  created on the server `source_config` points at — and between `Provision` and
  `Teardown` its restores land there and nowhere else. There is no field to
  mistype to aim a drill at production, because the drill never reads one.
- **The question is yours, and the plugin's to interpret.** `check` goes to the
  source plugin verbatim. For PostgreSQL it passes only if the query prints
  exactly `t`; a number, `f`, no rows, or a query that errors (the table is gone)
  all fail it. That is the point: a check satisfied by almost anything proves
  almost nothing.
- **`[target.drill.source_config]` is an overlay**, field by field, over the
  target's own. Repeating eight fields to change two invites them to drift
  apart. Secrets are references here too.
- **No artifacts is a failure, not a pass.** A target whose backups are missing
  is what a drill exists to flag. `--artifact KEY` drills a specific one.
- **It needs the private key**, exactly like `restore`, so schedule it on a
  machine where the key may live.
- **A drill that runs and fails exits 4**, and the report says how far it got —
  `failed_stage` is `provision`, `restore` or `check` — so the page can say "the
  restore worked and the check found no rows". `teardown_ok: false` is a warning
  and never changes the verdict: the backup restored, but a scratch database is
  left to drop.

```json
{"artifact_key":"app/2026/08/23/app-20260823T023637Z-postgres.dump.zst.age","check":{"detail":"the check returned true","ok":true},"command":"drill","elapsed_ms":2310,"failed_stage":null,"failure":null,"ok":true,"passed":true,"plaintext_bytes":1048576,"restore_ms":1790,"scratch":"database `drill_1787452597_4242` on staging-db.internal:5432","target":"app","teardown_error":null,"teardown_ok":true}
```

The source plugin has to implement the `drill` capability: `postgres` does (it
needs `psql` on `PATH`, or `psql_path`), and so does `mock`. [`[[notify]]`
blocks](#notifications) hear about a drill as the command `drill`.

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

### `shieldbk storage prune TARGET [--dry-run]`

Deletes the artifacts (and their manifests) that the target's retention no
longer keeps, using the storage target's own `List`/`Delete` RPCs — the core
never needs to know it is Postgres or R2 on the other end, only each
`ArtifactMeta.modified_at`. Refuses with a configuration error if there is no
retention, on the target or in `[defaults]`: pruning deletes backups, so it never
runs on a guessed default.

Two kinds of retention, and a config that names both is rejected:

- `retention_days = N` keeps everything younger than `N` days.
- A grandfather-father-son table keeps the **newest artifact of each of the
  last N periods that have one**, for days, ISO weeks, months and years, and an
  artifact kept by any of them is kept:

  ```toml
  [target.retention]
  keep_daily   = 7
  keep_weekly  = 4
  keep_monthly = 12
  keep_yearly  = 3
  ```

  Periods are counted among the days that actually have a backup, so an outage
  does not eat the history that is left. A policy that keeps nothing is
  rejected, and an artifact whose age the storage target did not report is never
  deleted.

`--dry-run` lists what would go (`expired` in the JSON) and deletes nothing.
Try a new policy with it first.

```sh
shieldbk storage prune production --dry-run
shieldbk storage prune production
```

Run it on the same schedule as `backup` (a `cron` right after it, or its own
hourly entry) so the storage target never grows past what the retention allows.

### Exit codes

```
0   success
2   configuration error   — the TOML, a secret reference, an age recipient
3   plugin error          — missing, unregistered, altered or crashed plugin
4   operation error       — the backup itself failed: source, network, storage;
                            or a drill's restore or check did
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
**≈ 400 MiB/s**; the data socket on its own, with no pipeline attached, measures
**≈ 2.7 GB/s** on the same machine, which is why it is worth keeping framing and
TLS off it — anything added there is paid for once per byte of every backup.

Memory is flat in the size of the input because nothing is buffered end to end:
the dump goes from one socket, through the compressor, the encryptor and the
hasher, into the other socket.

Reproduce it with:

```sh
cargo test --release --test memory -- --ignored --nocapture
cargo test -p sb-transport --release --test throughput -- --ignored --nocapture
```

The first command reproduces the table; the second is where the 2.7 GB/s comes
from — `the_data_channel_moves_bytes_at_the_speed_of_the_socket` in
[`crates/sb-transport/tests/throughput.rs`](crates/sb-transport/tests/throughput.rs),
which pushes 256 MiB through a real `DataChannel`, prints the rate and checks
that every chunk arrived intact and in order. It asserts a floor of 500 MB/s
rather than the measured figure: the number depends on the machine, and what the
assertion is there to catch is an order-of-magnitude drop.

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
- **Retention is opt-in.** `storage prune` deletes what `retention_days` or a
  grandfather-father-son `[retention]` table no longer keeps; without either
  set, nothing is ever deleted. There is no "keep the last N artifacts" policy
  — only age and calendar periods. `storage gc`
  is separate: it aborts incomplete *uploads*, not old backups. A storage
  target's own lifecycle rule (e.g. R2's) is a perfectly good alternative to
  running `prune`, and the two are safe to use together.
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
`target/release/`: `shieldbk`, `sb-plugin-postgres`, `sb-plugin-r2`,
`sb-plugin-webhook`, `sb-plugin-mock`. Install the
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
| [`ROADMAP.md`](ROADMAP.md) | Features that could be added next, and what is deliberately not planned. |
