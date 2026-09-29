# Writing a ShieldBackups plugin

A plugin is a **separate executable** that `shieldbk` starts, talks to over a
Unix socket, and kills when it is done. It is not a dynamic library, it does not
link against the core, and it does not have to be written in Rust. The contract
is one `.proto` file plus one line of JSON in each direction at startup.

That is the whole point of the architecture. If a plugin had to be a Rust crate
compiled into the core, "support a new database" would mean "recompile
`shieldbk`", and the set of people who can add a backup source would be the set
of people who know Rust. Instead:

- **In Rust**, with the SDK, a working plugin is about **50 lines**. See
  [Example: Rust](#example-rust-with-the-sdk).
- **Outside Rust**, a working plugin is about **350 lines** and no generated
  code at all. See
  [`examples/command-plugin/`](examples/command-plugin/) — it exists, it runs,
  and `./try-it.sh` performs a real backup and a real restore.

---

## Table of contents

- [The four services](#the-four-services)
- [The startup handshake](#the-startup-handshake)
- [The TLS names in the envelope](#the-tls-names-in-the-envelope)
- [The data channel](#the-data-channel)
- [Three traps for a plugin outside Rust](#three-traps-for-a-plugin-outside-rust)
- [Declaring the configuration schema](#declaring-the-configuration-schema)
- [Example: Rust, with the SDK](#example-rust-with-the-sdk)
- [Example: outside Rust](#example-outside-rust)
- [Two honest limits](#two-honest-limits)
- [Installing a plugin](#installing-a-plugin)
- [Checklist](#checklist)

---

## The four services

`crates/sb-proto/proto/shieldbk/v1/plugin.proto` defines four gRPC services.
A plugin serves them on a single socket: `Plugin` always, and any subset of
`Source`, `Storage` and `Notifier`.

### `Plugin` — mandatory, always

Every plugin implements all five RPCs. They are what the core uses to find out
who it is talking to and to hand it its configuration.

| RPC | Purpose |
|---|---|
| `Info` | name, version, protocol version, capabilities |
| `Schema` | the configuration fields this plugin accepts |
| `Configure` | the validated configuration, with secrets already resolved |
| `Preflight` | connectivity/permission checks — this is what `doctor` shows |
| `Shutdown` | orderly termination |

### `Source` — implement it if the plugin *produces* a byte stream

```proto
rpc Dump    (DumpRequest)    returns (stream Progress);
rpc Restore (RestoreRequest) returns (stream Progress);
```

A `Source` is **anything that can be serialised into a byte stream and rebuilt
from one**. The contract is deliberately wider than "a database": a `pg_dump` is
one, and so is a directory piped through `tar`, a Docker volume, a virtual
machine's disk or a bucket copied to another provider. Nothing in the service
knows what is on the other end of the stream. The RPCs keep the names `Dump` and
`Restore` because they name the *operation* — serialise out, rebuild in — not
the kind of thing being serialised.

Implement `Restore` unless you genuinely cannot rebuild the thing. A source that
only dumps is legal, but `shieldbk restore` will refuse that target, and a backup
you cannot restore is not a backup.

### `Storage` — implement it if the plugin *keeps* a byte stream

```proto
rpc Put             (PutRequest)             returns (stream Progress);
rpc Get             (GetRequest)             returns (stream Progress);
rpc List            (ListRequest)            returns (ListResponse);
rpc Delete          (DeleteRequest)          returns (DeleteResponse);
rpc AbortIncomplete (AbortIncompleteRequest) returns (AbortIncompleteResponse);
```

`AbortIncomplete` is what `shieldbk storage gc` calls. Without it, a failed
multipart upload leaves orphaned parts that the provider keeps billing for. A
store with no multipart concept returns `aborted: 0` — the call still has to
succeed.

### `Notifier` — implement it if the plugin *tells somebody* how a command went

```proto
rpc Notify (NotifyRequest) returns (NotifyResponse);
```

`NotifyRequest` carries `command`, `ok` and `report_json` — the very document
`--format json` prints for that run. The core never knows what a Slack channel
or a Telegram chat is: a `[[notify]]` block in the configuration names the
plugin, says when to tell it (`on = "failure" | "success" | "always"`) and gives
it an opaque config table, validated against the plugin's `Schema` like any
other. Delivery is best-effort by contract: a notifier that fails is a warning
on stderr and never changes the exit code of the command it was telling about.

```toml
[[notify]]
plugin = "webhook"
on     = "failure"

[notify.config]
url    = { env = "SLACK_WEBHOOK_URL" }   # a secret: never a literal
format = "slack"
```

Write your notifier so its errors never contain a credential — a webhook URL or
a bot token — because the status message ends up on the operator's terminal.

**A plugin may implement any subset of the roles.** `sb-plugin-mock` implements
all three: it announces `CAPABILITY_SOURCE`, `CAPABILITY_STORAGE` and
`CAPABILITY_NOTIFIER` and serves the three services on the same socket. Each role
is started as its **own process** with its **own config table**
(`source_config`, `storage_config`, `[notify.config]`), so a plugin that serves
several declares in one `Schema` every field any of its roles needs, marks them
all `required: false`, and checks the ones a call needs when the call arrives.

The declared capabilities are checked **before** the core starts any transfer,
against the `capabilities` list from `Info` and from the startup announcement.
Finding out that a plugin cannot play the role it was given costs a string
comparison; finding out halfway through a dump costs the dump.

## The startup handshake

Four steps, and the order is load-bearing.

```
core                                    plugin process
────────────────────────────────────────────────────────────────
1. fork/exec <plugins.dir>/sb-plugin-<name>
   env cleared except PATH HOME TMPDIR LANG TZ
   own process group; stdin/stdout/stderr piped
                                    ─▶
2. write ONE line of JSON to stdin,
   then close stdin
                                    ─▶  read one line, parse it
                                        bring up the gRPC server
                                        on control_socket with mTLS
3.                                  ◀─  write ONE line of JSON to stdout
   read one line (30 s deadline)
4. dial control_socket with mTLS,
   ALPN "h2"                        ─▶  accept
```

### Step 1 — how the binary is found

`<plugins.dir>/sb-plugin-<name>`, and nowhere else. There is no `PATH` search.
A target with `source = "postgres"` looks for `sb-plugin-postgres` in
`plugins.dir` (default `~/.shieldbk/plugins`). The file must be present, must be
a regular file, and its SHA-256 must already be in the lockfile — see
[Installing a plugin](#installing-a-plugin).

The environment is cleared and only `PATH`, `HOME`, `TMPDIR`, `LANG` and `TZ` are
passed through; if `PATH` is unset it is replaced with
`/usr/local/bin:/usr/bin:/bin`. **Do not expect to inherit anything else** —
notably, a plugin cannot read a credential out of the core's environment, which
is deliberate.

### Step 2 — the `Bootstrap` envelope, on stdin

One line of JSON, then stdin is closed. It is single-line JSON on purpose: a
plugin in any language reads it with one `read_line` and parses it with its
standard library. Speaking protobuf is not a prerequisite for starting up.

This is a real envelope, captured from a running core (PEM bodies truncated):

```json
{
  "magic": "SHIELDBK_PLUGIN",
  "handshake_version": 1,
  "core_protocol_versions": [1],
  "control_socket": "/run/user/1000/shieldbk-296453-1/control.sock",
  "server_name": "shieldbk-plugin",
  "client_name": "shieldbk-core",
  "ready_timeout_ms": 30000,
  "tls": {
    "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIBizCCATCgAwIBAgIUY1haLcid…\n-----END CERTIFICATE-----\n",
    "server_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIBozCCAUmgAwIBAgIUMTMrTMjz…\n-----END CERTIFICATE-----\n",
    "server_key_pem": "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCC…\n-----END PRIVATE KEY-----\n"
  }
}
```

| Field | Meaning |
|---|---|
| `magic` | Always `"SHIELDBK_PLUGIN"`. **Check it and fail loudly if it differs** — that is what stops a binary run by hand from hanging forever waiting for something that will never arrive. |
| `handshake_version` | Version of *this envelope*, currently `1`. Distinct from the gRPC protocol version. Refuse a value higher than you understand. |
| `core_protocol_versions` | Every gRPC protocol version the core can speak. Pick the highest one you also support; if the intersection is empty, fail at startup with both lists in the message. |
| `control_socket` | The Unix socket path to listen on. Its directory already exists and is `0700`. |
| `server_name` | The name your server certificate carries (`shieldbk-plugin`). |
| `client_name` | The name the core's client certificate carries (`shieldbk-core`). |
| `ready_timeout_ms` | How long you have to announce yourself before the core gives you up for lost. Currently 30 000. |
| `tls.ca_cert_pem` | The session CA. Use it as your **client certificate verifier root** — a client without a certificate signed by it must be rejected. |
| `tls.server_cert_pem` / `tls.server_key_pem` | Your leaf and its private key. Generated by the core for this run only. |

**The envelope never contains the client key**, only the server bundle. If it
did, a plugin could impersonate the core to another plugin and ask that plugin
for its credentials.

Note what this means for logging: the envelope carries a private key. Do not
print it. The Rust `Bootstrap` and `ServerBundle` types implement `Debug` by
hand, redacted, precisely so that a careless `{:?}` while debugging startup
cannot leak it.

### Step 3 — the `Ready` announcement, on stdout

One line of JSON, written **only after the socket is genuinely accepting
connections**:

```json
{"magic":"SHIELDBK_PLUGIN","protocol_version":1,"capabilities":["source"],"pid":296471}
```

| Field | Meaning |
|---|---|
| `magic` | `"SHIELDBK_PLUGIN"` again. |
| `protocol_version` | The version you negotiated in step 2. The core compares it against its own and refuses a mismatch **before** connecting. |
| `capabilities` | Lowercase strings: `"source"`, `"storage"`, or both. |
| `pid` | Your process id. |

Order matters. The core treats the announcement as a promise that the socket is
already listening and dials it immediately; announcing first and binding
afterwards is a lost race. The Rust SDK polls for the socket file every 10 ms
for up to 2 s before announcing, and fails with
`the control channel never listened on {path} after {waited_ms} ms` rather than
announcing a lie.

**stdout belongs to that one line and to nothing else.** Every log line goes to
**stderr**, which the core relays into its own log, one `tracing::info!` per
line, tagged with the plugin's name. A stray `console.log` / `print()` / `fmt.
Println` corrupts the handshake and the plugin never starts.

If you write nothing (a crash, a missing interpreter, a bad shebang) the core
sees EOF and reports
`the plugin did not announce itself within the startup deadline` — the same
error as a timeout, deliberately, but it arrives immediately.

### Step 4 — the control connection

The core dials `control_socket` with TLS, presenting its client certificate,
requiring your server certificate to be signed by the session CA, and
negotiating **ALPN `h2`**. Everything after this point is ordinary gRPC.

### Termination

`Shutdown` is a normal RPC: reply to it, then exit. The core does **not** send
`SIGTERM`. After the `Shutdown` RPC returns (or its 60 s deadline elapses) it
closes the channel and sends **`SIGKILL` to the plugin's whole process group**,
then reaps it.

So the response has to leave the socket before your process does. In Rust that
is tonic's `GOAWAY`, which waits for in-flight streams; the SDK caps that wait
at 10 s and aborts. Outside Rust, do the equivalent of the worked example:

```js
Shutdown: (_call, done) => {
  done(null, {});
  // The reply has to leave before the process does.
  setTimeout(() => process.exit(0), 50);
},
```

Also handle `SIGTERM` for the case where something other than the core kills the
container. And note the process group: if your plugin spawns children, they die
with you. That is intended — it is what stops a `pg_dump` from outliving a
cancelled backup.

## The TLS names in the envelope

`server_name` and `client_name` exist so that **a plugin outside Rust does not
have to parse a certificate's DER, or know about a Rust constant, to know who to
authorise.** They make the mTLS policy data instead of tribal knowledge.

- `server_name` = `"shieldbk-plugin"` — the SAN and CN in the certificate you
  are given. If your TLS stack wants to know the name it is serving, this is it.
- `client_name` = `"shieldbk-core"` — the name in the certificate the core
  presents. If your stack lets you check the peer's name on top of the CA check,
  check it against this.

If your stack does *not* expose the peer's name — grpc-js does not — nothing is
lost here: the CA is ephemeral, was created seconds ago for this one process,
and signed exactly one client certificate, the core's. Verifying the chain
against that CA already means "this is the core that started me".

What is **not** optional is requiring a client certificate at all. In grpc-js
that is the third argument:

```js
grpc.ServerCredentials.createSsl(
  Buffer.from(envelope.tls.ca_cert_pem),
  [{ private_key: …server_key_pem, cert_chain: …server_cert_pem }],
  true,   // <- checkClientCertificate. Without it the channel is encrypted but open.
);
```

Without it the connection is encrypted and *unauthenticated*: anybody who can
reach the socket gets your configuration, credentials included.

## The data channel

The bulk bytes do not travel over gRPC. Each transfer RPC carries a
`data_socket` path; the plugin **connects to it as a client** and reads or
writes raw bytes.

```proto
message DumpRequest    { string data_socket = 1; }
message RestoreRequest { string data_socket = 1; }
message PutRequest     { string key = 1; string data_socket = 2; }
message GetRequest     { string key = 1; string data_socket = 2; }
```

- **No TLS.** See [`docs/security.md`](../security.md#why-the-data-channel-carries-no-tls).
  In short: both ends are the same user on the same machine inside a `0700`
  directory, so anyone who can open the socket already *is* that user and already
  has the credentials; encrypting would change no threat model and would cost CPU
  on a path that moves hundreds of gigabytes.
- **No framing.** Not a length prefix, not a chunk header — just bytes.
- **Closing the write side is the end-of-stream signal.** There is no other one.
  A dump that never closes its socket is a backup that hangs.
- The socket lives inside the runtime directory the core created **for that
  plugin**, which is the only place that process is guaranteed to be able to
  reach.

Direction per RPC:

| RPC | Who writes | Who closes the write side |
|---|---|---|
| `Source.Dump` | the plugin | **the plugin**, at end of dump |
| `Source.Restore` | the core | the core — and *deliberately not cleanly* if the restore failed |
| `Storage.Put` | the core | the core |
| `Storage.Get` | the plugin | **the plugin**, at end of object |

That fourth row's counterpart matters for a source: on a failed restore the core
abandons the channel instead of shutting it down in order, so **what you see is
a cut, not a clean EOF, and you must not treat what arrived as a complete
dump.**

### Progress

`Dump`, `Restore`, `Put` and `Get` return `stream Progress`:

```proto
message Progress { uint64 bytes = 1; string message = 2; }
```

Emit one every so often — the Rust SDK emits one per MiB moved — and a final one
when the transfer is done. The core uses the **last** `Progress` as the summary
of the operation, so its `message` is what the operator ends up seeing. The core
drains this stream throughout the transfer, and it is also the channel your
*errors* travel on once the response headers have gone out (see trap 2).

Do not buffer unboundedly on this stream: the core applies backpressure, and a
core that is not reading progress is a core that is not reading your data either.

## Three traps for a plugin outside Rust

These are not hypothetical. They are the three things that went wrong while
writing [`examples/command-plugin/`](examples/command-plugin/), each of which
produced an error message that pointed nowhere near its cause. They are also
recorded in the `.proto` itself, next to the messages they affect.

### Trap 1 — ALPN `h2`, or a 403 that looks like a framing bug

gRPC over TLS **is** HTTP/2, and the specification requires both ends to agree
on it through ALPN. Between two `rustls` peers the negotiation can be skipped
without anything visibly breaking, which is why this went unnoticed in a
Rust-only world.

Outside Rust it cannot be skipped. A gRPC server built on Node's or Bun's
`http2` — which is what a plugin in JavaScript, Python or Go ends up using —
hands a connection that did not negotiate `h2` to its **HTTP/1 path**, and
answers the HTTP/2 connection preface with `HTTP/1.0 403 Forbidden`. The client
then reads `HTT` as a frame length and gives up with a protocol/framing error
that says nothing whatsoever about ALPN.

The core now announces `h2` in its `ClientConfig`
(`crates/sb-transport/src/pki.rs`, `const ALPN_H2: &[u8] = b"h2";`) and requires
it in its `ServerConfig`. **Your server must offer `h2` in its ALPN list.** Most
gRPC libraries do this for you when you use their own TLS credentials
constructor — grpc-js's `ServerCredentials.createSsl` does — which is why the
worked example does not have to say anything about it. If you are wiring TLS by
hand, this is the line you will forget.

*Symptom:* the core reports a protocol or framing error immediately after
connecting, and your plugin's log shows an HTTP/1 request arriving.

### Trap 2 — answer first, work afterwards, or you deadlock

From the `.proto`, verbatim:

> **PROTOCOL REQUIREMENT:** the plugin must return the RPC response (the stream
> headers) **BEFORE** it starts writing to the data socket, and do the work in a
> separate task.

The reason is the shape of the pipeline. The core calls the *consumer* first and
the *producer* second, and it waits for each RPC's response headers before
bringing up its own end of the pipe. A plugin that connects to the data socket
and starts writing before it has answered is writing into a socket nobody is
draining yet: the kernel buffer (about 208 KiB) fills, the write blocks, the
response never gets sent, and both processes wait for each other until a deadline
fires.

The trap is that **in most gRPC libraries the response headers are not flushed
until the first message is written**, so the natural implementation — connect,
pump bytes, send progress as you go — deadlocks. The fix is to send the headers
explicitly. In grpc-js:

```js
function transfer(call, operation, run) {
  call.sendMetadata(new grpc.Metadata());   // <- THIS is the answer
  // …only now start the transfer, in a task of its own
  (async () => { … })();
}
```

Other stacks name it `SendHeader` (Go), `send_initial_metadata` (C++/Python), or
similar. The Rust SDK makes this structurally impossible to get wrong:
`progress_stream` spawns the work and returns the `Response` synchronously, so
the RPC body cannot touch the socket first because it never awaits the work.

A consequence worth internalising: **once the headers are out, an error can no
longer be the RPC's status.** It has to travel on the `Progress` stream the core
is already listening on. Anything you *can* detect beforehand — missing
configuration, a bad key, an artifact that does not exist — belongs before the
first write, where it can still be a proper `Status`.

*Symptom:* the backup hangs, then fails on a 30 s or 60 s deadline, with no
error from either side.

### Trap 3 — field names travel exactly as written

`data_socket` is `data_socket` on the wire. Protobuf loaders that camel-case by
default will hand your handler a `dataSocket` and leave `data_socket` empty, so
every transfer arrives with an empty socket path and fails on connect.

In `@grpc/proto-loader`:

```js
protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,   // <- without this, data_socket becomes dataSocket
  longs: String,
  defaults: true,
  oneofs: true,
});
```

The same applies in the other direction: the fields you *return* must be named
as the `.proto` names them — `protocol_version`, `default_value`,
`source_version`, `modified_at`.

*Symptom:* `Dump` is called, but the path you were given is `""` or `undefined`.

## Declaring the configuration schema

`Schema` returns the fields your plugin accepts. The core uses it three ways: to
validate the user's TOML *before* a single value reaches you, to resolve
secrets, and to print `shieldbk plugin docs <name>`.

```proto
message Field {
  string    name          = 1;
  FieldType type          = 2;   // STRING INT BOOL DURATION PATH LIST
  bool      required      = 3;
  bool      secret        = 4;
  string    description   = 5;
  string    default_value = 6;
}
```

`Configure` then delivers `map<string, Value>` where `Value` is a `oneof` of
`string_value`, `int_value`, `bool_value` or `list_value`.

### What `secret: true` actually does

Marking a field secret changes the core's behaviour in three ways:

1. **The configuration file may not contain a literal for it.** Writing
   `password = "hunter2"` is a hard error naming the field and listing the
   accepted alternatives. Only a reference is accepted:
   `{ env = "…" }`, `{ file = "…" }`, `{ file_insecure = "…" }`,
   `{ keyring = "service/user" }`, `{ command = ["prog", "arg"] }`.
2. **The core resolves it and hands you the value, not its origin.** You receive
   a plain `string_value`. You never learn whether it came from a file, a
   variable or a broker — which is exactly why the secret policy can live in one
   auditable place instead of being reinvented, with different criteria, in every
   plugin.
3. **It is never printed.** Not in `plugin docs`, not in a log, not in an error.

The rule is symmetric, and the other half surprises people: **a field you did
*not* mark secret refuses a secret reference.** Resolving one into a value that
then gets treated as ordinary configuration — printed, logged, echoed in a
diagnostic — would leak it.

So: mark a field secret *if and only if* its value is a credential. Marking
`bucket` secret makes it impossible to write down; failing to mark `password`
secret makes it possible to commit.

### What the core validates, and what is left to you

The core checks presence of required fields, and that each value's type matches
the declared `FieldType`. It knows nothing else. Range checks, mutually
exclusive options, "this command list cannot be empty" — those are yours, in
`Configure`, where a bad value can still be rejected with `INVALID_ARGUMENT`
before anything runs.

`Configure` may be called more than once; the last call wins.

### `Preflight` is not `Configure`

`Preflight` is the diagnostic RPC and it must **report** problems, not fail
because of them. A plugin that has not been configured should return a failing
`Check` explaining that, not a `FAILED_PRECONDITION` — `doctor` needs a report,
and an error would truncate it.

Every failing `Check` needs a `remediation`. A preflight that says "it failed"
without saying how to fix it is worth nothing:

```js
{
  name: "dump",
  ok: false,
  detail: "`pg_dump` is not on PATH",
  remediation: "install postgresql-client, or give its absolute path in the target's `dump` field",
}
```

`PreflightResponse.source_version` is for sources: the version of whatever you
sit in front of — the database server, the container runtime, the hypervisor. It
goes into every artifact's manifest and shows up in `doctor` as a check named
`source version`. A source with no such notion (a plain directory) returns the
empty string.

## Example: Rust, with the SDK

The smallest plugin that starts, negotiates and shuts down cleanly is
`crates/sb-plugin-sdk/tests/bin/smoke_plugin.rs` — 49 lines, reproduced here in
full:

```rust
use sb_plugin_sdk::PluginRuntime;
use sb_plugin_sdk::sb_proto::plugin_server::Plugin;
use sb_plugin_sdk::sb_proto::{
    Capability, ConfigureRequest, ConfigureResponse, InfoRequest, InfoResponse, PreflightRequest,
    PreflightResponse, SchemaRequest, SchemaResponse, ShutdownRequest, ShutdownResponse,
};
use sb_plugin_sdk::tonic::{Request, Response, Status};

#[derive(Default)]
struct Minimal;

#[sb_plugin_sdk::tonic::async_trait]
impl Plugin for Minimal {
    async fn info(&self, _: Request<InfoRequest>) -> Result<Response<InfoResponse>, Status> {
        Ok(Response::new(InfoResponse {
            name: "minimal".into(),
            version: "0.1.0".into(),
            protocol_version: sb_plugin_sdk::sb_proto::PROTOCOL_VERSION,
            capabilities: vec![Capability::Source as i32],
        }))
    }
    async fn schema(&self, _: Request<SchemaRequest>) -> Result<Response<SchemaResponse>, Status> {
        Ok(Response::new(SchemaResponse::default()))
    }
    async fn configure(
        &self,
        _: Request<ConfigureRequest>,
    ) -> Result<Response<ConfigureResponse>, Status> {
        Ok(Response::new(ConfigureResponse::default()))
    }
    async fn preflight(
        &self,
        _: Request<PreflightRequest>,
    ) -> Result<Response<PreflightResponse>, Status> {
        Ok(Response::new(PreflightResponse::default()))
    }
    async fn shutdown(
        &self,
        _: Request<ShutdownRequest>,
    ) -> Result<Response<ShutdownResponse>, Status> {
        Ok(Response::new(ShutdownResponse::default()))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    PluginRuntime::new(Minimal).serve().await?;
    Ok(())
}
```

`PluginRuntime::serve()` is the whole handshake: it sets up logging **to
stderr**, reads and validates the `Bootstrap` line, negotiates the protocol
version, builds the TLS server config from the bundle, binds the socket, waits
until it is genuinely listening, writes the `Ready` line, and then serves until
`Shutdown`.

`sb-plugin-sdk` re-exports `sb_proto`, `tonic` and `connect_data`, so the SDK is
the only dependency a plugin needs to declare.

### Adding a data axis

Capabilities are **derived from what you register** — there is no separate
declaration, so a plugin cannot claim a source it does not implement:

```rust
let state = config::State::new(plugin::NAME);
PluginRuntime::new(plugin::MockPlugin::new(state.clone()))
    .with_source(source::MockSource::new(state.clone()))
    .with_storage(storage::MockStorage::new(state))
    .serve()
    .await?;
```

`Configure` only reaches the `Plugin` service, but `Source` and `Storage` are
separate objects. `Configured<T>` is the shared slot that solves it, with the
"not configured yet" error already written:

```rust
async fn dump(&self, request: Request<DumpRequest>) -> Result<Response<Self::DumpStream>, Status> {
    // Anything that can fail up front fails here, while it can still be a Status.
    let config = self.state.resolved()?;
    let socket = request.into_inner().data_socket;

    // progress_stream spawns the work and returns the Response synchronously:
    // trap 2 is structurally impossible.
    Ok(progress_stream(move |mut progress| async move {
        dump(&socket, &config, &mut progress).await
    }))
}
```

Inside the closure, move bytes and call `progress.advance(n)` per chunk (it only
emits when a MiB milestone is crossed) and `progress.finish("dump complete")` at
the end. **Closing the socket is what signals end of stream to the core.**

`plugins/sb-plugin-mock/` is a complete two-axis plugin worth reading end to
end; `plugins/sb-plugin-r2/` is the production-shaped one, with multipart
uploads and a large configuration schema.

## Example: outside Rust

**[`examples/command-plugin/`](examples/command-plugin/)** is a complete,
working `Source` plugin written in Bun/TypeScript. It links against no Rust and
generates no protobuf stubs — `@grpc/proto-loader` reads the core's own
`plugin.proto` at startup.

**[`examples/folder-plugin/`](examples/folder-plugin/)** is the whole cycle in
one TypeScript plugin: a `Source` that tars a folder, a `Storage` that keeps
artifacts in a directory and a `Notifier` that tells a Telegram chat — back up,
store, notify — with `./try-it.sh` running it against a fake Telegram.

```sh
cd docs/plugins/examples/command-plugin
./try-it.sh
```

That script builds `shieldbk` and the mock storage plugin, installs both plugins
into a throwaway `run/` directory, generates an age key, backs up a directory
through `tar`, restores it, and diffs the result against the original byte for
byte. Nothing is written outside `run/`. It needs `bun`, `cargo`, and
`tar`/`diff`/`sha256sum`.

The plugin itself wraps **any pair of commands** — one that writes a serialised
copy to stdout, one that rebuilds it from stdin — which is the entire definition
of a `Source` in this protocol. One generic plugin therefore already covers
`pg_dump`/`pg_restore`, `mysqldump`/`mysql`, `mongodump`/`mongorestore`,
`tar -c`/`tar -x`, `redis-cli --rdb` and `etcdctl snapshot save`:

```toml
[target.source_config]
dump    = ["pg_dump", "--format=custom", "--dbname=app"]
restore = ["pg_restore", "--dbname=app", "--single-transaction"]
```

### The three safety rules it demonstrates

Beyond the three traps above, the file is annotated with three rules that are
about *security*, not about making the protocol work. They are marked `RULE 1`,
`RULE 2` and `RULE 3` in the source.

**1. A command is a list of arguments, never a string.** The schema declares
`dump` and `restore` as `FIELD_TYPE_LIST`, and the list is handed to `Bun.spawn`
unchanged. There is no `shell: true` anywhere in the file and there must never
be one: with a shell in between, a configuration field becomes arbitrary code
execution and a target configured as `db; rm -rf /home` is *valid*
configuration. Splitting a string on spaces has the same problem one step
earlier, which is why the schema declares a `LIST` and not a `STRING`.

**2. A secret never travels in `argv`.** `/proc/<pid>/cmdline` is world-readable
and `ps` prints it, so `--password=hunter2` is visible to every user on the
machine for as long as the command runs. The `password` field is declared
`secret: true`, and the plugin puts the resolved value in the **child's
environment**, under a name the operator chooses via `password_env`. A process's
environment is readable only by its owner. That is not perfect — it is inherited
by children — but it is the best the POSIX process model offers for handing a
secret to a program you did not write.

**3. A data RPC answers first and works afterwards.** Trap 2, in its concrete
form: `call.sendMetadata(new grpc.Metadata())` *is* the answer, and only then
does the transfer start, in a task of its own.

It also demonstrates two smaller things that are easy to get wrong from outside
Rust: draining the child's stderr as it arrives (an unread pipe eventually
blocks the writer) and keeping its tail, because `pg_dump` saying
`permission denied for table users` **is** the whole diagnosis and would
otherwise be lost; and returning `Progress` errors through the stream once the
headers are out.

### What you give up by going generic

`sb-plugin-command`'s `Preflight` can only check that the binary **exists** —
`Bun.which(argv[0])`. It cannot check that its *version* is compatible with
whatever it is going to talk to.

That matters more than it sounds. A `pg_dump` older than the server it dumps
produces an **incomplete dump and does not necessarily fail while doing it**. A
purpose-built `sb-plugin-postgres` would run `SHOW server_version_num`, compare
it against `pg_dump --version`, and turn that into a failing check with a
remedy. The generic wrapper cannot: it does not know that `dump[0]` is a
PostgreSQL client, or that PostgreSQL has that rule at all.

The generic path is the right first step and often the last one. It is not a
replacement for a plugin that understands the thing it is backing up.

## Two honest limits

Both surfaced while writing the worked example. Neither is a bug; both are
places where the guarantee is narrower than it first reads.

### 1. The lockfile hashes the entry file, and nothing else

`shieldbk plugin lock` records the SHA-256 of the file at
`<plugins.dir>/sb-plugin-<name>`. That is the complete extent of it.

For a compiled binary that is the whole plugin, so the guarantee is tight. For
an **interpreted** plugin it is much weaker than it looks:

- `node_modules/` is not hashed. Swapping one transitive dependency changes what
  the plugin does and the lockfile still says `registered`.
- The interpreter is not hashed. Replacing `bun` on `PATH` replaces the plugin.
- Anything the script `import`s or `require`s at runtime is not hashed.

`try-it.sh` symlinks the script into the plugins directory, which is convenient
for trying it out and is **not** what a production install should look like. For
a real installation, compile to a single self-contained executable — for Bun,
`bun build --compile` — so that what the lockfile hashes *is* the plugin.

### 2. Schema defaults are informational

`Field.default_value` is a **string, for documentation**. It is what
`shieldbk plugin docs` prints in the `DEFAULT` column. It is not applied.

When the user omits an optional field, that field is simply **not present** in
the `Configure` map. The core does not synthesise the default; the plugin
applies its own. Nothing in the protocol keeps the two in sync, so a plugin that
declares `default_value: "PGPASSWORD"` and then writes
`get("password_env") ?? "PGPASSWORD_2"` is perfectly legal and silently lies to
everyone reading `plugin docs`.

Two consequences:

- Define the default **once** in your code, and build the `Field` from that same
  constant, so the two cannot drift.
- Do not use `default_value` as a way to make a field required-with-a-fallback.
  If the plugin cannot work without a value, mark the field `required: true` and
  let the core reject the configuration, where the error is precise and arrives
  before anything runs.

The counterpart rule is the one the SDK enforces on purpose: **before
`Configure` there are no silent defaults at all.** `Configured::resolved()`
fails rather than inventing a value, because a dump written to a destination
nobody asked for is worse than a clear error.

## Installing a plugin

```sh
cp sb-plugin-mything ~/.shieldbk/plugins/    # the name IS the lookup rule
shieldbk plugin lock                          # register every binary in that dir
shieldbk plugin list                          # confirm: "mything: registered"
shieldbk plugin docs mything                  # confirm the schema it publishes
shieldbk doctor                               # confirm it starts and preflights
```

`plugin lock` registers **every** `sb-plugin-*` file in `plugins.dir`; it takes
no plugin name. Re-run it after every upgrade — a changed binary is refused
until you do, which is the point:

```
the binary of plugin "mock" (…/plugins/sb-plugin-mock) has changed since it was
registered: the lockfile expected sha256 b9818b9f… and the file has e9f295e6…
If the change is expected (you updated the plugin), register it again with
`shieldbk plugin lock`. If you were not expecting it, do NOT run it: the binary
receives the credentials of your database and of your storage
```

The lockfile is TOML and is meant to be committed and diffed:

```toml
version = 1

[plugins.mock]
sha256 = "b9818b9f1e8328bd7298ac7ac64900bc948d50f38d19ecc40b885920b74bbb4d"
```

`plugin lock`, `plugin list`, `plugin verify` and `plugin docs` all work on a
configuration that has no `[[target]]` at all — which is exactly the state of a
machine that has just installed the plugins and has not decided what to back up
yet. It is also how the container image seals its lockfile at build time; see
[`deploy/README.md`](../../deploy/README.md#the-lockfile-is-sealed-at-build-time).

Be clear-eyed about what registering means: **it is a decision to trust the
plugin's author.** The hash proves the binary has not changed since you looked
at it. It cannot prove the binary was ever trustworthy. A plugin receives your
credentials by construction — see
[`docs/security.md`](../security.md#what-the-lockfile-protects-and-what-it-does-not).

## Checklist

Before you call a plugin done:

- [ ] `Info` returns the right `protocol_version` and the capabilities you
      actually serve.
- [ ] The startup line goes to **stdout**; every log line goes to **stderr**.
- [ ] The `Ready` line is written **after** the socket is accepting connections.
- [ ] `magic` is checked on the way in, and a mismatch fails loudly.
- [ ] Protocol versions are negotiated, and no common version is a startup
      failure with both lists in the message.
- [ ] mTLS **requires** a client certificate signed by the envelope's CA.
- [ ] The TLS server offers ALPN `h2` (trap 1).
- [ ] Every data RPC flushes its response headers before touching the data
      socket (trap 2).
- [ ] Field names are preserved verbatim in both directions (trap 3).
- [ ] The data socket's write side is **closed** at end of stream.
- [ ] Errors after the headers are out travel on the `Progress` stream.
- [ ] Credentials are declared `secret: true`, and never appear in `argv`, a
      log, or an error message.
- [ ] Commands are spawned from a list; there is no shell anywhere.
- [ ] Every failing `Preflight` check has a `remediation`.
- [ ] `Shutdown` replies **before** the process exits, and `SIGTERM` is handled.
- [ ] `shieldbk doctor`, `backup`, `verify` and `restore` all pass against a
      real target — and the restored bytes are compared against the originals.
