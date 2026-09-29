# `sb-plugin-folder` — one plugin, the whole cycle

A working ShieldBackups plugin, written in TypeScript for [Bun](https://bun.sh),
that plays **all three roles** the protocol has:

| role         | what it does here                                                       |
| ------------ | ----------------------------------------------------------------------- |
| **Source**   | streams a folder out as a tar (`Dump`) and extracts one back (`Restore`) |
| **Storage**  | keeps artifacts as files in a directory that plays the bucket            |
| **Notifier** | tells a Telegram chat how a command went                                 |

```toml
[[target]]
name      = "docs"
source    = "folder"
storage   = "folder"
recipient = "age1..."

[target.source_config]
path = "/home/me/documents"

[target.storage_config]
dir = "/mnt/backups"

[[notify]]
plugin = "folder"
on     = "failure"            # or "success" / "always"

[notify.config]
bot_token = { env = "TELEGRAM_BOT_TOKEN" }
chat_id   = "-1001234567890"
```

Back up, store, notify: the whole cycle goes through one file.

## Why it is here

`sb-plugin-command` shows a *Source* outside Rust. This one shows what it left
out:

- **A plugin may implement any subset of the roles.** `Plugin` (Info, Schema,
  Configure, Preflight, Shutdown) is mandatory; `Source`, `Storage` and
  `Notifier` are each optional and are declared in `Info` and in the Ready line
  (`["source","storage","notifier"]`). `plugins/sb-plugin-mock` does the same in
  Rust.
- **Each role runs as its own process, with its own config table.** The example
  above starts the *same binary* three times — for `source_config`, for
  `storage_config` and for `[notify.config]` — and none of them sees the
  others' settings. A plugin therefore has a single `Schema` for all its roles,
  and it cannot say "`path` is required" without demanding `path` from the
  process that only notifies.

  So every field is declared **optional**, and each RPC checks the fields it
  needs when it is called: `FAILED_PRECONDITION` if the plugin was never
  configured, `INVALID_ARGUMENT` naming the field if it was configured without
  the one this role needs. `Preflight` likewise reports only what was
  configured.

## Run it

```sh
./try-it.sh
```

It builds `shieldbk` and this plugin's single-file executable, installs it into
a throwaway `run/` directory, starts a fake Telegram on a loopback port, backs a
folder up, verifies the artifact, restores it and compares the result byte for
byte with the original. It also asserts that the fake received
`✅ shieldbk backup: ok` at `/bot<token>/sendMessage` and that the bot token
appears nowhere in what `shieldbk` printed. Nothing is written outside `run/`.

Requirements: `bun`, `cargo`, `tar`, `diff`.

Unit tests and type check (no network, no `shieldbk`):

```sh
bun install
bun test
bunx tsc --noEmit
```

## Layout

| file                    | what is in it                                                          |
| ----------------------- | ---------------------------------------------------------------------- |
| `sb-plugin-folder.ts`   | the protocol only: handshake, schema, the four services                |
| `folder.ts`             | source and storage: keys, put/get/list/delete, tar, checks             |
| `telegram.ts`           | notifier: config validation, message, the request, failure mapping     |
| `types.ts`              | the few types the modules share                                        |
| `fake-telegram.ts`      | the loopback stand-in for `api.telegram.org` that `try-it.sh` starts   |
| `*.test.ts`             | `bun test`; they call the core functions directly, not through gRPC    |

The logic sits apart from the protocol file because that file reads stdin the
moment it loads, and because a function that takes and returns plain streams
can be tested without a data socket.

## Configuration fields

Run `shieldbk plugin docs folder` to get this from the plugin itself. All are
optional in the schema; the role that needs one refuses to run without it.

| field       | type     | role     | secret | meaning                                                              |
| ----------- | -------- | -------- | ------ | -------------------------------------------------------------------- |
| `path`      | path     | source   | no     | the folder to back up, and to restore into                           |
| `dir`       | path     | storage  | no     | the directory that plays the bucket                                  |
| `bot_token` | string   | notifier | **yes** | bot token from @BotFather                                           |
| `chat_id`   | string   | notifier | no     | numeric id (groups and channels are negative) or `@channelname`      |
| `api_base`  | string   | notifier | no     | Bot API endpoint (default `https://api.telegram.org`); https unless loopback |
| `timeout`   | duration | notifier | no     | how long to wait for Telegram (default `10s`)                        |

Getting a token and a chat id:

1. In Telegram, talk to **@BotFather**, send `/newbot`, and keep the token it
   gives you.
2. Add the bot to the chat (or channel, as an administrator) and send it a
   message.
3. Open `https://api.telegram.org/bot<token>/getUpdates` once and read
   `chat.id` from the reply. Groups and channels have negative ids.

## What it is meant to teach

**1. The Notifier contract.** One unary RPC:
`Notify(NotifyRequest { command, ok, report_json })`. The core calls it after a
command finishes, for each `[[notify]]` block whose `on` matches the outcome.
`report_json` is the very document `--format json` prints, with `ok` and, on
failure, `class`, `code` and `error`. The plugin builds one plain-text line —
`✅ shieldbk backup: ok` or `❌ shieldbk backup FAILED: <error>` — cut to 3500
UTF-16 units without splitting a surrogate pair. There is no `parse_mode`, so
there is nothing to escape.

**2. Best-effort delivery.** When Telegram cannot be told, `Notify` fails with a
status. The core logs it on stderr and carries on: a broken chat never changes
the exit code of a backup. So the plugin has no retries — a notifier that
retried would only keep a finished command waiting.

**3. A secret is a reference, not a value.** `bot_token` is declared
`secret: true`, so the core refuses a literal token in the config file (it would
end up in git) and accepts only `{ env = "..." }`, `{ file = "..." }` and the
like. The core resolves it and hands the plugin the value without its origin.

**4. The token sits in the URL, so it must not leave the process in any string.**
Telegram wants `POST /bot<token>/sendMessage`. A credential in a URL is the
worst case: `fetch` errors, redirects and HTTP libraries all like to quote the
URL. So:

- every failure is mapped to a short fixed sentence — `Telegram answered HTTP
  401`, `could not reach Telegram (timeout|connection refused|tls)` — and the
  error's own text is never used;
- the response body is never read or logged (it can echo the request);
- redirects are not followed (`redirect: "manual"`; a 3xx is a failure), so the
  token cannot be replayed at a URL somebody else chose;
- `api_base` must be https unless the host is loopback, so the token never
  crosses a network in the clear;
- the token must look like a token (`[A-Za-z0-9:_-]+`), so it cannot rewrite the
  URL it is pasted into;
- the timeout is enforced with `AbortSignal.timeout`, and `Preflight` sends
  **no message** and prints nothing derived from the token.

Each of these has a test against a fake Telegram (`Bun.serve` on `127.0.0.1`).

**5. Storage is careful with keys.** A key arrives over the network and ends up
as a path. It is checked **before anything is opened**: no `..`, no absolute or
empty component, no NUL, no backslash. Nothing under the directory is followed
through a symlink, and reads open with `O_NOFOLLOW`. `Put` writes
`<key>.part` and renames it into place only after a clean end of stream, so an
interrupted upload never looks like an artifact; `AbortIncomplete` removes
abandoned `.part` files under a prefix (untouched for a minute, so it cannot
delete one that is still being uploaded) and counts them. `Delete` is
idempotent, and `List` reports `modified_at` as `YYYY-MM-DDTHH:MM:SSZ`.

**6. A command is a list, never a string.** `tar` is spawned as
`["tar", "-C", path, "-cf", "-", "."]` (and `-xf` for `Restore`). There is no
shell anywhere in the file; a folder called `x; rm -rf ~` is just a folder.

**7. A data RPC answers first and works afterwards.** `Dump`, `Restore`, `Put`
and `Get` refuse what can be refused, then flush the response headers with
`sendMetadata` — that call *is* the answer — and only then start the transfer,
in a task of its own. Once the headers are out, errors travel on the `Progress`
stream.

The startup mechanics are exactly those of `sb-plugin-command`: one JSON line on
stdin, mTLS with a mandatory client certificate, one JSON line on stdout once
the socket listens, **every log on stderr**, and `keepCase: true` in
`proto-loader`.

## Installing it for real

The plugin directory holds one file per plugin, named `sb-plugin-<name>`, and
`shieldbk` runs nothing it has not registered with `shieldbk plugin lock`, which
records the file's SHA-256.

That hash covers **the file it points at and nothing else** — not
`node_modules`, not the interpreter, not anything the script imports at run time.
A script in the plugins directory is therefore only as trustworthy as everything
around it. For a real installation, compile it to one self-contained executable
so that what the lockfile hashes *is* the plugin:

```sh
bun install
bun run build                  # bun build --compile sb-plugin-folder.ts --outfile sb-plugin-folder
cp sb-plugin-folder ~/.shieldbk/plugins/
shieldbk plugin lock           # re-run after every upgrade
shieldbk plugin docs folder
shieldbk doctor
```

The build embeds the core's own `plugin.proto`, so the executable needs nothing
next to it. It is large (Bun's runtime is inside); that is the price of a single
file.

Registering a plugin is a decision to trust its author: it receives your bot
token, and — as the storage — your artifacts. Read it first; it is a few hundred
lines.
