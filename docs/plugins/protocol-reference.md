# Protocol reference

The normative source is
[`crates/sb-proto/proto/shieldbk/v1/plugin.proto`](../../crates/sb-proto/proto/shieldbk/v1/plugin.proto).
This document explains it: what every field means, what the core actually does
with it, the call order that is mandatory, and which changes are compatible.

For *how* to write a plugin, start with
[`writing-a-plugin.md`](writing-a-plugin.md).

- **Package:** `shieldbk.v1`
- **Syntax:** proto3
- **Protocol version:** `1` (`sb_proto::PROTOCOL_VERSION`)
- **Handshake envelope version:** `1` (`sb_transport::HANDSHAKE_VERSION`)
- **Manifest version:** `1` (`sb_core::model::MANIFEST_VERSION`)
- **Lockfile version:** `1` (`sb_core::lockfile::LOCKFILE_VERSION`)

---

## Table of contents

- [Transport](#transport)
- [The startup envelope](#the-startup-envelope)
- [Service `Plugin`](#service-plugin)
- [Service `Source`](#service-source)
- [Service `Storage`](#service-storage)
- [Service `Notifier`](#service-notifier)
- [Service `Drill`](#service-drill)
- [Shared messages](#shared-messages)
- [Enumerations](#enumerations)
- [Call order](#call-order)
- [Who closes what](#who-closes-what)
- [Deadlines](#deadlines)
- [Error conventions](#error-conventions)
- [Versioning policy](#versioning-policy)
- [The artifact manifest](#the-artifact-manifest)

---

## Transport

| | Control plane | Data plane |
|---|---|---|
| Protocol | gRPC over HTTP/2 | raw bytes, no framing |
| Transport | Unix domain socket | Unix domain socket |
| Security | mTLS, ephemeral per-process PKI, ALPN `h2` | none |
| Direction | core dials, plugin listens | **plugin dials, core listens** |
| Lifetime | one per plugin process | one per transfer |

The direction reverses between the planes and it is easy to get backwards: the
plugin is the **server** on the control socket and the **client** on every data
socket.

Both sockets live in a runtime directory the core creates per plugin process,
mode `0700`, under `$XDG_RUNTIME_DIR` if that is a directory and `TMPDIR`
otherwise, named `shieldbk-<core-pid>-<n>`. The directory and everything in it
are removed when the plugin is torn down.

## The startup envelope

Before any gRPC, one line of JSON travels in each direction over the plugin's
stdin and stdout. Both carry `"magic": "SHIELDBK_PLUGIN"` so that a binary that
is not a plugin fails immediately with a clear message rather than hanging.

### `Bootstrap` — core → plugin, on stdin

Written as one line, followed by `\n`; **stdin is then closed.**

| Field | Type | Meaning |
|---|---|---|
| `magic` | string | `"SHIELDBK_PLUGIN"`. Reject anything else. |
| `handshake_version` | uint32 | Version of this envelope. Currently `1`. Absent means `0`. Reject a value **higher** than you understand. |
| `core_protocol_versions` | uint32[] | Every gRPC protocol version the core speaks. Choose the highest you also support. |
| `control_socket` | string | Absolute path of the socket to listen on. |
| `server_name` | string | `"shieldbk-plugin"` — the name in your certificate. |
| `client_name` | string | `"shieldbk-core"` — the name in the core's certificate. |
| `ready_timeout_ms` | uint64 | How long you have to announce yourself. Currently `30000`. |
| `tls.ca_cert_pem` | string | The session CA, PEM. Use as the client-certificate verifier root. |
| `tls.server_cert_pem` | string | Your leaf certificate, PEM. |
| `tls.server_key_pem` | string | Your leaf's private key, PEM. **Never log this.** |

The envelope deliberately does **not** contain the core's client key or client
certificate: a plugin that held them could impersonate the core to another
plugin and ask it for credentials.

### `Ready` — plugin → core, on stdout

One line, written **only after** the control socket is accepting connections.

| Field | Type | Meaning |
|---|---|---|
| `magic` | string | `"SHIELDBK_PLUGIN"`. |
| `protocol_version` | uint32 | The version negotiated from `core_protocol_versions`. |
| `capabilities` | string[] | Lowercase: `"source"`, `"storage"`, or both. |
| `pid` | uint32 | The plugin's process id. |

The core compares `protocol_version` against its own **before** dialling and
refuses a mismatch with
`the plugin "{p}" speaks version {a} of the protocol and this core speaks {b}`.

Everything else the plugin writes to stdout corrupts this line. Logs go to
stderr, which the core relays into its own log.

## Service `Plugin`

Mandatory. Every plugin implements all five RPCs.

### `Info(InfoRequest) → InfoResponse`

The first RPC over the authenticated channel. Confirms identity and
capabilities.

`InfoRequest` is empty.

| `InfoResponse` field | Type | Meaning |
|---|---|---|
| `name` | string | The plugin's own name. Informational — the core identifies a plugin by its **file name**, `sb-plugin-<name>`, not by this. |
| `version` | string | The plugin binary's version. Recorded in every artifact's manifest as `source.plugin_version`. |
| `protocol_version` | uint32 | The protocol version. Must match what was announced in `Ready`. |
| `capabilities` | `Capability[]` | Which axes this plugin serves. |

The core calls `Info` on the **source** during a backup, to fill
`plugin_version` in the manifest.

### `Schema(SchemaRequest) → SchemaResponse`

Describes the configuration fields the plugin accepts. `SchemaRequest` is empty;
`SchemaResponse` carries `repeated Field fields`.

Called on **every** plugin start, before `Configure`, because it is what the
core validates the user's TOML against. Also what `shieldbk plugin docs <name>`
prints — and that command prints the schema only, never a configured value.

### `Configure(ConfigureRequest) → ConfigureResponse`

Delivers the validated configuration.

`ConfigureRequest` carries `map<string, Value> config`. `ConfigureResponse` is
empty.

Three things have already happened by the time this arrives:

1. Every field name has been checked against `Schema`.
2. Every value's type has been checked against its declared `FieldType`.
3. **Every secret has been resolved.** A field declared `secret: true` arrives as
   a plain `string_value`. The plugin never learns whether it came from an
   environment variable, a file, the keyring or a command.

**A field the user omitted is simply absent from the map.** The core does not
substitute `Field.default_value`; see
[Enumerations → `Field`](#field). Apply your own defaults here.

Everything the core cannot know is still the plugin's job: ranges, mutually
exclusive options, "this list cannot be empty". Reject those with
`INVALID_ARGUMENT` and a message naming the field.

`Configure` may be called more than once. The last call wins.

### `Preflight(PreflightRequest) → PreflightResponse`

Checks connectivity, permissions and dependencies. This is what
`shieldbk doctor` shows, and the core also calls it on the source before a
backup — a cheap way to find an expired credential before moving a byte.

`PreflightRequest` is empty.

| `PreflightResponse` field | Type | Meaning |
|---|---|---|
| `ok` | bool | The overall verdict. |
| `checks` | `Check[]` | Every check performed, passing ones included. |
| `source_version` | string | Version of whatever the source sits in front of. Empty when there is no such notion. |

**`Preflight` must report, not fail.** It is the diagnostic RPC: a plugin that
has not been configured returns a failing `Check` saying so, not a
`FAILED_PRECONDITION`. `doctor` exists so a two-hour backup does not break at
the ninety-minute mark, and for that it has to show everything in one go — an
error would truncate the report.

If a plugin returns `ok: false` with no failing check, the core inserts a
synthetic one named `verdict`, with the detail
`the plugin "{name}" declares itself not ready but did not say which check
fails`. Do not make it do that.

`source_version` goes into every artifact's manifest as `source.source_version`
and appears in `doctor` as a check named `source version`. It is meant for the
database server version, the container runtime version, the hypervisor version.
A plain directory has none and returns `""`.

### `Shutdown(ShutdownRequest) → ShutdownResponse`

Orderly termination. Both messages are empty.

Reply first, exit second. The core does **not** send `SIGTERM`: once this RPC
returns — or its 60 s deadline elapses — it drops the channel and sends
`SIGKILL` to the plugin's whole **process group**, then reaps it. A shutdown
that does not confirm is logged and the process is closed the hard way; it is
not an error of the operation.

## Service `Source`

Something that produces a stream of bytes and can be rebuilt from one. That
contract is deliberately wider than "a database": a `pg_dump` is one, and so are
a directory piped through `tar`, a Docker volume, a VM disk or a bucket being
copied to another provider.

### `Dump(DumpRequest) → stream Progress`

`DumpRequest { string data_socket = 1; }`

Connect to `data_socket`, write the serialised copy, **close the write side**.
The close is the only end-of-stream signal there is.

### `Restore(RestoreRequest) → stream Progress`

`RestoreRequest { string data_socket = 1; }`

Connect to `data_socket`, read until end of stream, rebuild.

**A clean EOF means the artifact was complete. A cut does not.** On a failed
restore the core deliberately abandons the channel instead of shutting it down
in order, precisely so the two are distinguishable. See
[Who closes what](#who-closes-what).

## Service `Storage`

### `Put(PutRequest) → stream Progress`

`PutRequest { string key = 1; string data_socket = 2; }`

Connect to `data_socket`, read until end of stream, store the bytes under `key`.
The core closes the write side when the artifact is complete.

The same RPC uploads the artifact and, on a separate channel, its
`*.manifest.json`. There is no separate manifest RPC on purpose: a second path
would let the artifact and its manifest end up in different places, or with
different permissions, without anyone noticing.

### `Get(GetRequest) → stream Progress`

`GetRequest { string key = 1; string data_socket = 2; }`

Connect to `data_socket`, write the object's bytes, **close the write side**.
Used for the artifact (`restore`, `verify`) and for the manifest.

A `Get` for a key that does not exist must fail. `restore` and `verify` both
distinguish "the manifest is missing" from "the artifact is missing", and both
messages name the exact key that was looked up.

### `List(ListRequest) → ListResponse`

`ListRequest { string prefix = 1; }` → `ListResponse { repeated ArtifactMeta artifacts = 1; }`

Called by `shieldbk verify <target>` with no artifact named, to find everything
under the target's prefix. The core filters out keys ending in `.manifest.json`
itself.

`ArtifactMeta`:

| Field | Type | Meaning |
|---|---|---|
| `key` | string | The object's key. |
| `size` | uint64 | Its size in bytes. |
| `modified_at` | string | Last-modified timestamp — **format is part of the contract**, see below. |

`modified_at` is **RFC-3339, UTC, `Z` suffix, exactly twenty characters,
`YYYY-MM-DDTHH:MM:SSZ`, with no fractional seconds.** A target that receives
more precision from its server trims it.

The precision is pinned for a reason that is not obvious. If one target sent
milliseconds and another did not, their strings would stop being comparable:
`…:15Z` and `…:15.983Z` differ at character 19, where `Z` sorts above `.`, so
the older artifact would sort as the newer one. RFC-3339 is chosen over an epoch
because it sorts the same as text as it does as a date — comparing strings
already means comparing instants — and an operator can read it without
converting anything.

If the target does not know the timestamp, return **the empty string**. Never a
made-up value and never a zero: a fake timestamp is indistinguishable from a
real one and would end up deciding what a retention policy deletes.

### `Delete(DeleteRequest) → DeleteResponse`

`DeleteRequest { string key = 1; }` → `DeleteResponse {}` (empty)

Removes one object. **No core command currently calls it** — `shieldbk` has no
retention or pruning feature (see the README's *What it does not do*). It is
part of the contract so that a storage plugin is complete and so that retention
can be added without a protocol change. Implement it.

### `AbortIncomplete(AbortIncompleteRequest) → AbortIncompleteResponse`

`AbortIncompleteRequest { string prefix = 1; }` →
`AbortIncompleteResponse { uint32 aborted = 1; }`

Cleans up incomplete multipart uploads under `prefix`. Without it, a failure
leaves orphaned parts the provider keeps billing for.

Called by `shieldbk storage gc <target>`, always scoped to that target's prefix:
a bucket may hold more than this `shieldbk`'s backups, and aborting somebody
else's uploads would be worse than the problem it came to solve.

A store with no multipart concept returns `aborted: 0`. The call must still
succeed — `0` means "nothing to do", not "unsupported".

## Service `Notifier`

A notifier is told how a command went and passes it on: Slack, Discord, a
mailbox, a ticket, a dead-man's-switch URL. The core does not know which — it
hands every notifier the same event and the plugin decides what to do with it.

### `Notify(NotifyRequest) → NotifyResponse`

```proto
message NotifyRequest {
  string command     = 1;  // backup, restore, verify, drill, doctor, storage gc, storage prune
  bool   ok          = 2;  // a doctor that found problems is not ok
  string report_json = 3;  // the document `--format json` prints for that run
}
message NotifyResponse {}
```

`report_json` is exactly what a script piping `--format json` into `jq` would
read: the command's own body plus `ok` at the root, and `class`, `code` and
`error` when it failed. Its shape is the command's public contract, so a
notifier may rely on it as much as a script does. A command that failed before
it had a report (an unknown target, an unreadable configuration) still gets
one: `ok`, `class`, `code` and `error` and nothing else.

Which blocks are told is decided by the core, from the `on` of each `[[notify]]`
block (`failure` by default, `success` or `always`), **before** any process is
started: a notifier that asked only for failures is never launched on a good
day.

**Delivery is best-effort, and the contract says so.** A notifier that fails —
by returning an error, by not starting, by taking longer than 30 seconds — is
reported on the core's stderr and changes nothing else: not the exit code, not
stdout. The backup worked or it did not; a Slack outage does not turn a good
backup into a failed one. What a notifier must do for itself is keep its
credentials out of what it returns: the message of the gRPC status ends up on
the operator's terminal, so a webhook URL or a bot token has no place in it.

## Service `Drill`

A drill proves that a backup restores. It is a source that can make a **disposable
place** to restore into, answer whether what landed there is right, and throw the
place away. A database is the obvious case — a scratch database — but so is a
temporary directory or a throwaway volume. The core never knows which: it runs the
sequence and reports the verdict.

A plugin that implements `Drill` **also implements `Source`**, and the two are the
same process. That is not an accident of packaging, it is the mechanism: between
`Provision` and `Teardown`, `Source.Restore` writes into the disposable place and
**never** into what the plugin was configured to back up. The plugin keeps that
state itself — see `PostgresDrill` and `Scratch` in `sb-plugin-postgres` — and the
core has nothing to configure or get wrong.

It is additive, like `Notifier`: a source that does not implement it keeps working
for everything but `shieldbk drill`, and the core refuses a drill up front, naming
the plugin, if the capability is missing.

### `Provision(ProvisionRequest) → ProvisionResponse`

```proto
message ProvisionRequest {}
message ProvisionResponse {
  string description = 1;  // where restores now land: a database name, a directory
}
```

Creates the disposable place. From here on, `Source.Restore` writes there.
`description` goes into the report, so it must name the place without leaking a
credential. A second `Provision` without a `Teardown` in between is
`FAILED_PRECONDITION`: it would orphan the first place.

Record the place **only once it exists.** A `Provision` that fails leaves nothing
for `Teardown` to remove.

### `Check(CheckRequest) → CheckResponse`

```proto
message CheckRequest  { string query = 1; }
message CheckResponse {
  bool   ok     = 1;
  string detail = 2;  // why, in a line; shown whether it passed or not
}
```

`query` is exactly what the operator wrote in `[target.drill] check`. The core does
not interpret it: what a query means is the plugin's. (`sb-plugin-postgres` passes
only if it prints exactly `t`.)

**A check that does not hold is an answer, not an error.** Return `ok = false` and
say why in `detail`. That includes a query that fails *because the restore lost
something* — a missing table is the very thing a drill looks for. Return an RPC
error only when the question could not be asked at all (no `psql`, no scratch place
provisioned: `FAILED_PRECONDITION`).

### `Teardown(TeardownRequest) → TeardownResponse`

```proto
message TeardownRequest {}
message TeardownResponse {}
```

Throws the disposable place away. **Idempotent**: with nothing provisioned it
succeeds and does nothing, because the core calls it whatever happened before —
after a failed `Provision`, a failed restore, a failed check. If dropping fails,
return the error and keep the place recorded, so a retry knows what to drop.

The core reports a failing `Teardown` and does **not** let it change the verdict:
the backup restored or it did not, and a leftover scratch database is a leak to
tell about, not a reason to call a good backup bad.

## Shared messages

### `Field`

```proto
message Field {
  string    name          = 1;
  FieldType type          = 2;
  bool      required      = 3;
  bool      secret        = 4;
  string    description   = 5;
  string    default_value = 6;
}
```

| Field | Meaning |
|---|---|
| `name` | The TOML key inside `source_config` / `storage_config`. |
| `type` | See [`FieldType`](#fieldtype). The core enforces it. |
| `required` | The core rejects the configuration if it is missing. |
| `secret` | See below. |
| `description` | One line. Printed by `shieldbk plugin docs`. |
| `default_value` | **A string, for documentation only.** Printed in the `DEFAULT` column. Never applied. |

`default_value` is not applied by anyone but you. An omitted optional field is
**absent** from the `Configure` map; the plugin supplies its own default, and
nothing in the protocol keeps the declared string and the applied value in sync.
Build the `Field` from the same constant your code uses, or the two will drift
and `plugin docs` will lie.

**`secret: true`** changes core behaviour in three ways:

1. The configuration file may not contain a literal for that field. Only a
   reference is accepted: `{ env = "…" }`, `{ file = "…" }`,
   `{ file_insecure = "…" }`, `{ keyring = "service/user" }`,
   `{ command = ["prog", "arg"] }`.
2. The core resolves the reference and delivers the **value**, never its origin.
3. The value is never printed — not in `plugin docs`, not in a log, not in an
   error.

The rule is symmetric: **a field not marked secret refuses a secret reference**,
because resolving one into a value that is then treated as ordinary
configuration would leak it.

### `Value`

```proto
message StringList { repeated string values = 1; }

message Value {
  oneof kind {
    string     string_value = 1;
    int64      int_value    = 2;
    bool       bool_value   = 3;
    StringList list_value   = 4;
  }
}
```

The core picks the variant that matches the field's declared `FieldType`:

| `FieldType` | arrives as |
|---|---|
| `FIELD_TYPE_STRING` | `string_value` |
| `FIELD_TYPE_INT` | `int_value` |
| `FIELD_TYPE_BOOL` | `bool_value` |
| `FIELD_TYPE_DURATION` | `string_value` (`"30s"`, `"5m"`, `"1h"`, `"250ms"`) |
| `FIELD_TYPE_PATH` | `string_value` |
| `FIELD_TYPE_LIST` | `list_value` |
| any `secret: true` field | `string_value` |

### `Check`

```proto
message Check {
  string name        = 1;
  bool   ok          = 2;
  string detail      = 3;
  string remediation = 4;
}
```

| Field | Meaning |
|---|---|
| `name` | Short identifier. `doctor` prints it; keep it stable across runs. |
| `ok` | The verdict. |
| `detail` | What was seen — the path that does not exist, the error the server returned. |
| `remediation` | **What to do about it.** |

Every failing check needs a `remediation`. A preflight that says "it failed"
without saying how to fix it is worth nothing. A passing check leaves it empty.

`doctor` renders each check with its origin (`config`, `source` or `storage`),
because a backup has two live plugins at once and "missing permission" without
saying which of the two forces the operator to guess.

### `Progress`

```proto
message Progress { uint64 bytes = 1; string message = 2; }
```

Returned as a stream by `Dump`, `Restore`, `Put` and `Get`.

- `bytes` — cumulative bytes moved so far, not a delta.
- `message` — free text. **The core uses the last `Progress` as the summary of
  the operation**, so its message is what the operator ends up seeing.

Emit periodically; the Rust SDK emits one per MiB moved. The core drains this
stream throughout the transfer and applies backpressure — a core that is not
reading progress is a core that is not reading your data either.

Once the response headers have gone out, this stream is also the **only channel
an error can travel on**, and the core is listening on it precisely for that.

## Enumerations

### `Capability`

```proto
enum Capability {
  CAPABILITY_UNSPECIFIED = 0;
  CAPABILITY_SOURCE      = 1;
  CAPABILITY_STORAGE     = 2;
  CAPABILITY_NOTIFIER    = 3;
  CAPABILITY_DRILL       = 4;
}
```

Announced in `InfoResponse.capabilities`, and in lowercase string form
(`"source"`, `"storage"`, `"notifier"`, `"drill"`) in the `Ready` line. A plugin may
declare any subset of them.

The core checks the capability it needs **before** creating any data channel:
finding out that a plugin cannot play its assigned role costs a string
comparison, and finding out halfway through a dump costs the dump.

### `FieldType`

```proto
enum FieldType {
  FIELD_TYPE_UNSPECIFIED = 0;
  FIELD_TYPE_STRING      = 1;
  FIELD_TYPE_INT         = 2;
  FIELD_TYPE_BOOL        = 3;
  FIELD_TYPE_DURATION    = 4;
  FIELD_TYPE_PATH        = 5;
  FIELD_TYPE_LIST        = 6;
}
```

`DURATION` and `PATH` are `string_value` on the wire; they exist so that
`plugin docs` can say what shape a value takes, and so a future core can
validate them more tightly without a protocol change.

Prefer `LIST` over a space-separated `STRING` for anything that becomes a
command line. A string that gets split later is an injection waiting to happen.

## Call order

Every command follows the same prelude and the same teardown. **The order is not
advisory.**

### Prelude — every command that touches a plugin

```
1.  verify the binary's SHA-256 against the lockfile   (no RPC — no process yet)
2.  spawn the process, write Bootstrap, read Ready, dial with mTLS
3.  check the announced capability against the role     (no RPC)
4.  Schema
5.  validate the TOML and resolve secrets               (no RPC)
6.  Configure
```

Step 1 happens before step 2 for the reason the whole architecture exists: a
plugin is handed your credentials, so a binary that is not the one you
registered must never be *executed*, not merely never trusted.

### Teardown — every command

```
Shutdown  →  drop the channel  →  SIGKILL the process group  →  wait()
```

### `backup`

```
source: Schema, Configure
storage: Schema, Configure
Source.Info                     → manifest's plugin_version
Source.Preflight                → manifest's source_version, and a cheap credential check
Storage.Put   { artifact_key, data_socket }     ← THE CONSUMER FIRST
Source.Dump   { data_socket }
accept(dump channel), accept(put channel)
… stream: zstd → age → SHA-256 …
drain both Progress streams to completion
Storage.Put   { "<key>.manifest.json", data_socket }   (a fresh channel)
Shutdown ×2
```

**`Storage.Put` is called before `Source.Dump`, which is the opposite of how the
diagram reads.** This is the single most counter-intuitive thing in the
protocol, and it is not a style preference.

The dump socket has a kernel buffer of roughly 208 KiB
(`net.core.wmem_default`). If the producer starts before the consumer is in
place, it writes into a socket nobody will drain yet and blocks as soon as that
buffer fills — and what happens next depends on how the *plugin* is written,
which the core does not control:

- A plugin whose `Dump` writes **before** returning its response — which the
  protocol forbids, but a plugin can still do — would never answer, so `Put`
  would never be called at all. Only the open deadline cuts that short.
- With `Dump` first, a `Put` that fails (bad key, storage down) leaves a source
  already running and writing into a socket about to be closed under it. `Put`
  first makes that failure happen before a single byte moves.

The rule worth remembering: **the consumer is placed before the producer,
always.** It is free, and it removes a class of hangs that by definition do not
show up in tests where everything goes well.

The core also waits for both `Progress` streams to end **before** writing the
manifest. Without that wait, the manifest could describe an artifact the storage
has not finished closing.

### `restore`

```
source: Schema, Configure
storage: Schema, Configure
Storage.Get   { "<key>.manifest.json", data_socket }   → expected digest
Source.Restore { data_socket }                          ← THE CONSUMER FIRST (the source)
Storage.Get    { artifact_key, data_socket }
accept(get channel), accept(restore channel)
… stream: SHA-256 → age⁻¹ → zstd⁻¹ …
on success: shutdown the source's channel cleanly
on failure: abandon both transfers, drop the socket without shutdown
drain both Progress streams
Shutdown ×2
```

Same rule, mirrored: here the **source** is the consumer, so `Source.Restore`
goes first.

A missing manifest is a warning, not a failure — the digest check is skipped and
the restore proceeds. Refusing would mean leaving recoverable data unrecovered.

### `verify`

```
storage: Schema, Configure
Storage.List { prefix }            (only when no artifact was named)
per artifact, sequentially:
    Storage.Get { "<key>.manifest.json", data_socket }
    Storage.Get { artifact_key, data_socket }
    … stream → SHA-256 → sink …
    drain the Progress stream
Shutdown
```

No source plugin is started. No `Identity` is involved anywhere — verification
decrypts nothing.

The manifest is fetched **first**, because without it there is nothing to
compare against, and downloading a hundred gigabytes only to find that out at
the end is a cost you cannot get back. One bad artifact never interrupts the
next: the verdict is per artifact.

The verdict requires **both** the digest and the byte count to match.

### `drill`

```
source:  Schema, Configure   (the target's source_config, with [target.drill]'s laid over it)
storage: Schema, Configure
capabilities checked: source + drill on the source, storage on the storage
Storage.List { prefix }                             (only when no --artifact was named)
Storage.Get  { "<key>.manifest.json", data_socket }  → expected digest
Drill.Provision
  … the same calls as `restore`, from Source.Restore on …
Drill.Check { query }
Drill.Teardown                                      ← ALWAYS, whatever happened above
Shutdown ×2
```

The restore in the middle is the `restore` operation, unchanged — a drill that
restored by some other path would prove that *that* path works. What the drill adds
is around it.

`Teardown` runs after a failed `Provision`, a failed restore and a failed check
alike. Each drill RPC has a **5-minute** deadline, not the control channel's one
minute: a check is a query against a freshly restored database and may scan.

### `doctor`

```
recipient parsed locally                           (origin: config)
source:  Schema, Configure  (a startup failure becomes a check, not an abort)
storage: Schema, Configure
Source.Preflight
Storage.Preflight                                  ← in series, never in parallel
Shutdown ×2
```

No data channel at all. The two preflights run in series deliberately: saving a
few milliseconds does not make up for one plugin's log lines interleaving with
the other's, and the report reads better with the source first.

An empty report is **not** a pass. A `doctor` that produced no checks means
something never ran.

### `storage gc`

```
prefix derived from the artifact template          (local, no RPC)
storage: Schema, Configure
Storage.AbortIncomplete { prefix }
Shutdown
```

### Notification — after `backup`, `restore`, `verify`, `drill`, `doctor`, `storage gc` and `storage prune`

```
for each [[notify]] block whose `on` matches the outcome (at most 4 at a time):
  the prelude, with role "notify"
  Notifier.Notify { command, ok, report_json }        (30 s for the whole block)
  Shutdown
```

It runs after the command's own work is finished, so it cannot delay or alter
it, and its failure is a warning on stderr rather than a result.

## Who closes what

The write side of a data socket is closed by whoever is writing. That close is
the end-of-stream signal; there is no other one.

| Channel | Writer | Closes | Note |
|---|---|---|---|
| `Source.Dump` | plugin | **plugin** | End of dump. |
| `Storage.Put` | core | core | End of artifact, or of the manifest blob. |
| `Storage.Get` | plugin | **plugin** | End of object. |
| `Source.Restore` | core | core | **Only on success.** |

That last row is the one to internalise if you are writing a source.

age hands over AEAD blocks *already verified*, incrementally. Faced with a
truncated artifact, the read fails only **after** everything before the cut has
been written — legitimate plaintext, but partial. The digest check is worse
still: it can only run once the whole stream has been read, by which point the
source has received everything.

So on failure the core does the only thing it can: it **abandons** the source's
channel rather than shutting it down in order, and returns an error without
waiting for the plugins to report success. The source sees a cut, not a clean
EOF.

That is not enough on its own, and it is worth saying plainly: **discarding what
was written is the source plugin's responsibility**, because it is the only party
that knows what undoing means. `pg_restore --single-transaction` is one such
answer. A source that writes files directly has to bring its own.

## Deadlines

| What | Limit | On expiry |
|---|---|---|
| Plugin announces itself on stdout | **30 s** | `the plugin did not announce itself within the startup deadline`. EOF gives the same error, sooner. |
| Any control-plane RPC | **60 s** | `the plugin "{p}" did not answer {op} in 60 s` |
| Any `Drill` RPC (`Provision`, `Check`, `Teardown`) | **5 min** | `the plugin "{p}" did not answer {op} in 300 s`; the drill fails at that stage and still tears down |
| Transfer RPC response headers | **60 s** | transfer error |
| Plugin connects to a data socket | **30 s** | transfer error naming the plugin and the operation |
| SDK: socket must exist before announcing | **2 s** | `the control channel never listened on {path} after {waited_ms} ms` |
| SDK: control channel closes after `Shutdown` | **10 s** | logged, then the task is aborted |

The 10 s cap is **not** the shutdown mechanism. What guarantees the `Shutdown`
response reaches the core is tonic's `GOAWAY`, which waits for in-flight
streams; the cap only covers the pathological case of a stream that never ends.

Note that there is **no** overall deadline on a transfer. A dump may take hours.
Bound the whole run from outside — `activeDeadlineSeconds` on a Kubernetes
`Job`, a `timeout` in cron.

## Error conventions

**Before the response headers go out**, an error is a normal gRPC `Status`. Use
the code that matches:

| Code | When |
|---|---|
| `INVALID_ARGUMENT` | `Configure` got a value the plugin cannot use. Name the field. |
| `FAILED_PRECONDITION` | A data RPC arrived before `Configure`, or a capability was not configured (e.g. no `restore` command). |
| `NOT_FOUND` | `Get`/`Delete` on a key that is not there. |
| `INTERNAL` | Anything else. |

The core renders a failed RPC as
`the plugin "{plugin}" failed on {operation}: {Code}: {message}`, so the message
is read by an operator looking at the core's log, not by the plugin's author.
Write it for them.

**After the headers are out**, the RPC's status is gone. An error has to travel
on the `Progress` stream. In grpc-js:

```js
call.emit("error", { code: grpc.status.INTERNAL, details: error.message });
```

Anything you can detect up front — missing configuration, an unparseable key, an
artifact that does not exist — belongs before the first write, where it can
still be a proper `Status`.

**No error message may contain a credential.** That includes errors you did not
write: several third-party error types carry secret bytes inside their
`Display`. See
[`docs/security.md`](../security.md#third-party-errors-that-carry-secrets-inside).

## Versioning policy

Four version numbers travel independently, so that a change in one does not
force a change in the others.

| Number | Governs | Currently |
|---|---|---|
| `handshake_version` | the shape of the startup JSON | 1 |
| `protocol_version` | the gRPC contract | 1 |
| `MANIFEST_VERSION` | the `*.manifest.json` schema | 1 |
| `LOCKFILE_VERSION` | the `plugins.lock` TOML schema | 1 |

`protocol_version` is negotiated: the core sends every version it speaks, the
plugin picks the highest it also speaks, and no intersection is a startup
failure whose message contains **both lists**, so the reader knows what to
upgrade. All the other three are compared, and a value higher than the reader
understands is refused — an old reader cannot safely interpret a newer format,
and refusing beats restoring badly.

### Changes that do **not** require a protocol bump

Protobuf was chosen precisely so these are free:

- **Adding a field to an existing message.** An old plugin ignores it; a new
  plugin sees a default. This is the main reason the contract is protobuf and
  the envelope is JSON with `#[serde(default)]` on every added field.
- **Adding a value to an enum.** Readers must tolerate unknown values, and
  every enum here has an explicit `_UNSPECIFIED = 0`.
- **Adding an RPC to an existing service.** A core that does not call it does
  not notice; a core that does gets `UNIMPLEMENTED` from an old plugin, which is
  a diagnosable answer.
- **Adding a whole service**, for a future third axis.
- Changing a field's `description` or `default_value`.

### Changes that **do** require a protocol bump

- Removing or renaming a field, or reusing a tag number.
- Changing a field's type or its meaning.
- Making an optional field required.
- Changing the direction of a data channel, or who closes it.
- Any change to the mandatory call order.

### Renames are not aliased

When `Engine` became `Source` across the system — in the configuration keys, in
the manifest and in the service name — no `serde(alias)` compatibility shim was
added, and `MANIFEST_VERSION` stayed at 1 because no artifact of the old shape
exists anywhere.

That is a deliberate policy, not an oversight. The configuration model already
declares that an unrecognised key is an error, never something to swallow; an
alias would be the one permanent exception to that rule. An alias is a promise
you keep, test and document forever, and documenting two spellings teaches every
new reader that both exist. Renaming outright costs an old configuration one
loud, precise error naming the offending key.

## The artifact manifest

Not part of the gRPC contract, but part of what a storage plugin carries. Every
backup writes `<artifact_key>.manifest.json` next to the artifact, through the
same `Storage.Put` RPC on a separate channel.

```json
{
  "version": 1,
  "target": "app",
  "source": {
    "plugin": "mock",
    "plugin_version": "0.1.0",
    "source_version": "mock"
  },
  "created_at": "2026-08-23T02:36:25Z",
  "artifact_key": "app/2026/08/23/app-20260823T023625Z-mock.dump.zst.age",
  "plaintext_bytes": 1048576,
  "ciphertext_bytes": 1049173,
  "plaintext_sha256": "82d97740c0817ac1d668db53ba9293fd443d2f87eea77d698d17f229c86b379c",
  "ciphertext_sha256": "74b0a3237d2479144773fe3cbc976af00ee9ba725d058f36a0a41c17bd96a77d",
  "compression": { "algorithm": "zstd", "level": 6 },
  "encryption": {
    "algorithm": "age",
    "recipient": "age1rtq8xv2ywzqhkjvwqsykqxyggjk8nt67979sh9x2jxau2tf3cpeqkf67vy"
  }
}
```

- **`ciphertext_sha256` is what `verify` compares**, and why verification needs
  no private key.
- **`plaintext_sha256`** is recorded for whoever restores and wants to prove
  what came out matches what went in. It is not used by `verify`, which by
  design cannot see plaintext.
- **`recipient` is a public key**, and is not a secret: knowing who an artifact
  is addressed to does not help decrypt it.
- The manifest is authoritative. `verify` and `restore` read it rather than
  inferring anything from the key — a name can be changed, a manifest is a
  record.
- It is written indented, because it gets read by hand at three in the morning.
