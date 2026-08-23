# `sb-plugin-command` — a ShieldBackups plugin outside Rust

A working `Source` plugin, written in [Bun](https://bun.sh), that wraps **any
pair of commands**: one that writes a serialized copy of something to stdout,
and one that rebuilds it from stdin.

```toml
[[target]]
name      = "app"
source    = "command"
storage   = "mock"
recipient = "age1..."

[target.source_config]
dump    = ["pg_dump", "--format=custom", "--dbname=app"]
restore = ["pg_restore", "--dbname=app", "--single-transaction"]
```

That covers `pg_dump`/`pg_restore`, `mysqldump`/`mysql`,
`mongodump`/`mongorestore`, `tar -c`/`tar -x`, `redis-cli --rdb`,
`etcdctl snapshot save` and any in-house tool that behaves the same way.

## Why it is here

ShieldBackups runs every plugin as a separate process that speaks gRPC over a
Unix socket with mTLS. The point of paying that price is that a plugin can be
written in any language, by somebody who does not know Rust. This directory is
where that claim is checked: `sb-plugin-command` is a complete plugin in about
350 lines of JavaScript, it links against no Rust and it generates no protobuf
stubs — `@grpc/proto-loader` reads the core's own `plugin.proto` at startup.

## Run it

```sh
./try-it.sh
```

It builds `shieldbk` and the mock storage plugin, installs both plugins into a
throwaway `run/` directory, generates an age key, backs up a directory through
`tar`, restores it, and compares the result byte for byte with the original.
Nothing is written outside `run/`.

Requirements: `bun`, `cargo`, and the usual `tar`/`diff`/`sha256sum`.

## What it is meant to teach

**1. A command is a list of arguments, never a string.** The schema declares
`dump` and `restore` as `LIST`, and `Bun.spawn` receives that list unchanged.
There is no `shell: true` anywhere in the file and there must never be one: with
a shell in between, a configuration field becomes arbitrary code execution and a
target called `db; rm -rf /home` is valid configuration. Splitting a string on
spaces has the same problem one step earlier.

**2. A secret never travels in `argv`.** `/proc/<pid>/cmdline` is world-readable
and `ps` prints it, so `--password=hunter2` is visible to every user on the
machine for as long as the command runs. The `password` field is declared
`secret: true`, which makes the core refuse a literal value in the configuration
file — it accepts only a reference (`{ env = "..." }`, `{ file = "..." }`,
`{ command = [...] }`), resolves it itself, and hands the plugin the value
without its origin. The plugin puts it in the child's **environment**, under the
name given by `password_env`.

**3. A data RPC answers first and works afterwards.** `Dump` and `Restore`
return a stream of `Progress`, and the core waits for that stream's response
headers before bringing up its own end of the pipeline. A plugin that connects
to the data socket and starts writing before answering deadlocks the backup. In
grpc-js the headers are not sent until something is written, so the plugin
flushes them explicitly with `sendMetadata` — that call *is* the answer — and
only then starts the transfer, in a task of its own.

Two more things the file shows, because they are easy to get wrong from outside
Rust:

- **stdout belongs to the handshake.** The core reads exactly one JSON line from
  it. Every log line goes to stderr, which the core relays into its own log. A
  stray `console.log` breaks startup.
- **`keepCase: true` in `proto-loader`.** Without it, `data_socket` silently
  becomes `dataSocket`, the field stops matching the `.proto`, and every
  transfer arrives with an empty socket path.

## Configuration fields

Run `shieldbk plugin docs command` to get this from the plugin itself:

| field          | type     | required | secret | meaning                                        |
| -------------- | -------- | -------- | ------ | ---------------------------------------------- |
| `dump`         | list     | yes      | no     | command that writes the copy to stdout         |
| `restore`      | list     | no       | no     | command that rebuilds from stdin               |
| `workdir`      | path     | no       | no     | directory the commands run in                  |
| `password`     | string   | no       | yes    | handed to the child through the environment    |
| `password_env` | string   | no       | no     | variable it is placed in (default `PGPASSWORD`) |
| `timeout`      | duration | no       | no     | how long a command may run (`0s` = no limit)   |

## Installing it for real

The plugin directory holds one file per plugin, named `sb-plugin-<name>`.
`shieldbk` runs nothing it has not registered with `shieldbk plugin lock`, which
records the binary's SHA-256.

For a script, that hash covers the **entry file only**, not `node_modules` nor
the interpreter. `try-it.sh` symlinks this script into the plugins directory,
which is convenient for trying it out and is not what a production install
should look like: there, prefer `bun build --compile` so that what the lockfile
hashes is one self-contained executable.
