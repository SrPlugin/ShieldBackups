#!/usr/bin/env bun
/**
 * sb-plugin-folder — one ShieldBackups plugin that does the whole cycle, in
 * TypeScript: it can be the **source** (a folder, as a tar), the **storage**
 * (a directory playing the bucket) and the **notifier** (a Telegram message).
 *
 *     [[target]]
 *     name    = "docs"
 *     source  = "folder"
 *     storage = "folder"
 *     recipient = "age1..."
 *
 *     [target.source_config]
 *     path = "/home/me/documents"
 *
 *     [target.storage_config]
 *     dir = "/mnt/backups"
 *
 *     [[notify]]
 *     plugin = "folder"
 *     on     = "failure"
 *
 *     [notify.config]
 *     bot_token = { env = "TELEGRAM_BOT_TOKEN" }
 *     chat_id   = "-1001234567890"
 *
 * ## Why it exists
 *
 * It is the second worked example of a plugin outside Rust, and it shows the
 * other half of the contract that `sb-plugin-command` does not: **a plugin may
 * implement any subset of the three roles**, the way `plugins/sb-plugin-mock`
 * does in Rust. Above, the same binary is started three times — once as the
 * source, once as the storage, once as the notifier — and each process gets
 * its own config table. The logic lives in `folder.ts` (source and storage)
 * and `telegram.ts` (notifier); this file is only the protocol.
 *
 * ## One schema, three roles
 *
 * `Schema` is one list for the whole plugin, so it cannot say "`path` is
 * required" without also demanding `path` from the process that only notifies.
 * Every field is therefore declared optional, and each RPC checks the fields
 * *it* needs when it is called: `FAILED_PRECONDITION` when the plugin was never
 * configured, `INVALID_ARGUMENT` naming the field when it was configured
 * without the one this role needs.
 *
 * ## How the startup works
 *
 * Identical to `sb-plugin-command`, and for the same reasons: ONE line of JSON
 * arrives on stdin, the gRPC server comes up on the given socket with mTLS, and
 * only then ONE line of JSON goes to stdout. stdout belongs to that line;
 * **every log goes to stderr**, and no log line contains the bot token.
 *
 * ## The rules this file is here to teach
 *
 *   - A data RPC **answers first and works afterwards** (`transfer`).
 *   - A command is a **list**, never a string: `tar` is spawned without a shell.
 *   - A credential that has to sit in a URL **never appears in any string that
 *     leaves the process** (see `telegram.ts`).
 *   - Notification is **best-effort**: it fails with a status, never retries,
 *     and the core never lets it change a command's exit code.
 */

import net from "node:net";

import grpc from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";

import * as folder from "./folder";
import {
  DEFAULT_API_BASE,
  DEFAULT_TIMEOUT,
  NotifyError,
  type NotifyRequest,
  type Settings,
  notify,
  readSettings,
  telegramChecks,
} from "./telegram";
import { type Check, ConfigError, type RawValue } from "./types";
// The core's own file, embedded into the executable by `bun build --compile`
// and resolved to a real path when run as a script. Either way the plugin
// speaks the very `.proto` the core was built from.
import PROTO_PATH from "../../../../crates/sb-proto/proto/shieldbk/v1/plugin.proto" with { type: "file" };

const NAME = "folder";
const VERSION = "0.1.0";
const PROTOCOL_VERSION = 1;
const HANDSHAKE_MAGIC = "SHIELDBK_PLUGIN";
/** How often a transfer reports progress back to the core. */
const PROGRESS_INTERVAL_MS = 2000;

/** Everything this plugin says goes to stderr. See the note about stdout above. */
const log = (...parts: string[]): void => console.error(`[${NAME}]`, ...parts);

// ---------------------------------------------------------------------------
// The protocol definition, loaded at runtime
// ---------------------------------------------------------------------------

const definition = protoLoader.loadSync(PROTO_PATH, {
  // Field names must travel exactly as the `.proto` writes them
  // (`data_socket`, `report_json`); the default camel-casing breaks that.
  keepCase: true,
  longs: String,
  defaults: true,
  oneofs: true,
});
const v1 = (grpc.loadPackageDefinition(definition)["shieldbk"] as grpc.GrpcObject)["v1"] as grpc.GrpcObject;
const serviceOf = (name: string): grpc.ServiceDefinition => (v1[name] as grpc.ServiceClientConstructor).service;

// ---------------------------------------------------------------------------
// Configuration schema
// ---------------------------------------------------------------------------

interface Field {
  name: string;
  type: "FIELD_TYPE_STRING" | "FIELD_TYPE_PATH" | "FIELD_TYPE_DURATION";
  required: boolean;
  secret: boolean;
  description: string;
  default_value: string;
}

/** Every field is optional: see "One schema, three roles" above. */
const field = (f: Omit<Field, "required" | "secret" | "default_value"> & Partial<Field>): Field => ({
  required: false,
  secret: false,
  default_value: "",
  ...f,
});

/**
 * `shieldbk plugin docs folder` prints this table. The defaults come from the
 * same constants the code applies, so the documentation cannot drift from the
 * behaviour: the core does not apply `default_value` itself.
 */
const SCHEMA: Field[] = [
  field({ name: "path", type: "FIELD_TYPE_PATH", description: "Source role: the folder to back up and restore into." }),
  field({ name: "dir", type: "FIELD_TYPE_PATH", description: "Storage role: the directory that plays the bucket." }),
  field({
    name: "bot_token",
    type: "FIELD_TYPE_STRING",
    // Declared secret, so the core refuses a literal token in the config file
    // (it would end up in git) and only accepts a reference such as
    // `{ env = "TELEGRAM_BOT_TOKEN" }`, resolved by the core itself.
    secret: true,
    description: "Notifier role: bot token from @BotFather. Sits in the request URL, so it is never logged or echoed.",
  }),
  field({
    name: "chat_id",
    type: "FIELD_TYPE_STRING",
    // A string, not an int: supergroups and channels have negative ids and a
    // public channel is addressed as `@name`.
    description: "Notifier role: chat to write to, a numeric id (groups and channels are negative) or @channelname.",
  }),
  field({
    name: "api_base",
    type: "FIELD_TYPE_STRING",
    description: "Notifier role: Bot API endpoint. Must be https unless the host is loopback (for tests).",
    default_value: DEFAULT_API_BASE,
  }),
  field({
    name: "timeout",
    type: "FIELD_TYPE_DURATION",
    description: "Notifier role: how long to wait for Telegram before giving up.",
    default_value: DEFAULT_TIMEOUT,
  }),
];

const TELEGRAM_FIELDS = ["bot_token", "chat_id", "api_base", "timeout"];

// ---------------------------------------------------------------------------
// Configuration state
// ---------------------------------------------------------------------------

interface State {
  path: string | undefined;
  dir: string | undefined;
  telegram: Settings | undefined;
}

/** Set by `Configure`. While it is null, every role's RPCs are refused. */
let state: State | null = null;

/** A refusal with the gRPC code it should travel as. */
class StatusError extends Error {
  constructor(
    readonly code: grpc.status,
    message: string,
  ) {
    super(message);
  }
}

/** The one place that turns anything thrown into a status. */
function toStatus(error: unknown): { code: grpc.status; details: string } {
  if (error instanceof StatusError) return { code: error.code, details: error.message };
  if (error instanceof folder.KeyError) return { code: grpc.status.INVALID_ARGUMENT, details: error.message };
  if (error instanceof folder.MissingError) return { code: grpc.status.NOT_FOUND, details: error.message };
  return { code: grpc.status.INTERNAL, details: error instanceof Error ? error.message : "unexpected failure" };
}

/**
 * What a role needs, at the moment it is used. Unconfigured is
 * `FAILED_PRECONDITION`; configured without this field is `INVALID_ARGUMENT`
 * and says which one.
 */
function need<K extends keyof State>(name: K, fields: string): NonNullable<State[K]> {
  if (!state) throw new StatusError(grpc.status.FAILED_PRECONDITION, "the plugin has not been configured yet");
  const value = state[name];
  if (value === undefined) {
    throw new StatusError(grpc.status.INVALID_ARGUMENT, `${fields} not set: this role needs it in its config table`);
  }
  return value;
}

/** The protocol's `Value`, as proto-loader hands it over (`oneofs: true`). */
interface WireValue {
  kind?: string;
  string_value?: string;
  int_value?: string | number;
  bool_value?: boolean;
  list_value?: { values: string[] };
}

function plain(value: WireValue): RawValue | undefined {
  switch (value.kind) {
    case "string_value":
      return value.string_value;
    case "int_value":
      return Number(value.int_value);
    case "bool_value":
      return value.bool_value;
    case "list_value":
      return value.list_value?.values;
    default:
      return undefined;
  }
}

// ---------------------------------------------------------------------------
// The data channel
// ---------------------------------------------------------------------------

/**
 * Connects to the raw Unix socket the core opened for this transfer. No TLS and
 * no framing; closing the write side is what signals end of stream.
 */
function connectData(path: string): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(path);
    socket.once("connect", () => resolve(socket));
    socket.once("error", reject);
  });
}

type Count = (bytes: number) => void;

/**
 * RULE: answer the RPC first, do the work afterwards.
 *
 * The core waits for the **response headers** of a `Progress` stream before it
 * brings up its own end of the pipeline, so a plugin that connects and starts
 * writing first deadlocks the transfer. grpc-js sends headers only with the
 * first write, so they are flushed explicitly: `sendMetadata` *is* the answer.
 *
 * Everything that can be refused is refused in `prepare`, before that, where
 * it can still be a proper status. `prepare` returns the work itself. Once the
 * headers are out the only channel an error can still travel on is the stream.
 */
function transfer<Req extends { data_socket: string }>(
  call: grpc.ServerWritableStream<Req, unknown>,
  operation: string,
  prepare: (request: Req, connect: () => Promise<net.Socket>) => (count: Count) => Promise<void>,
): void {
  let run: (count: Count) => Promise<void>;
  try {
    const socketPath = call.request.data_socket;
    if (!socketPath) throw new StatusError(grpc.status.INVALID_ARGUMENT, "`data_socket` is empty");
    run = prepare(call.request, () => connectData(socketPath));
  } catch (error) {
    call.emit("error", toStatus(error));
    return;
  }

  call.sendMetadata(new grpc.Metadata());

  let bytes = 0;
  const ticker = setInterval(() => call.write({ bytes, message: operation }), PROGRESS_INTERVAL_MS);
  run((n) => {
    bytes += n;
  }).then(
    () => {
      clearInterval(ticker);
      call.write({ bytes, message: `${operation} finished` });
      call.end();
      log(`${operation}: ${bytes} bytes`);
    },
    (error: unknown) => {
      clearInterval(ticker);
      const status = toStatus(error);
      log(`${operation} failed: ${status.details}`);
      call.emit("error", status);
    },
  );
}

/** Runs `work` on the data socket, and cuts the socket if it fails. */
async function withSocket(
  connect: () => Promise<net.Socket>,
  work: (socket: net.Socket) => Promise<void>,
): Promise<void> {
  const socket = await connect();
  try {
    await work(socket);
  } catch (error) {
    socket.destroy();
    throw error;
  }
}

// ---------------------------------------------------------------------------
// The services
// ---------------------------------------------------------------------------

/** A unary RPC whose body may throw or be async; every failure becomes a status. */
function unary<Req, Res>(body: (request: Req) => Res | Promise<Res>): grpc.handleUnaryCall<Req, Res> {
  return (call, done) => {
    Promise.resolve()
      .then(() => body(call.request))
      .then(
        (response) => done(null, response),
        (error: unknown) => done(toStatus(error)),
      );
  };
}

const pluginService: grpc.UntypedServiceImplementation = {
  Info: unary(() => ({
    name: NAME,
    version: VERSION,
    protocol_version: PROTOCOL_VERSION,
    capabilities: ["CAPABILITY_SOURCE", "CAPABILITY_STORAGE", "CAPABILITY_NOTIFIER"],
  })),

  Schema: unary(() => ({ fields: SCHEMA })),

  Configure: unary((request: { config?: Record<string, WireValue> }) => {
    const raw: Record<string, RawValue | undefined> = {};
    for (const [key, value] of Object.entries(request.config ?? {})) raw[key] = plain(value);
    try {
      // The notifier's fields are validated together, and only if any is present:
      // a process that is only the source has none of them.
      const telegram = TELEGRAM_FIELDS.some((f) => raw[f] !== undefined) ? readSettings(raw) : undefined;
      state = { ...folder.readFolders(raw), telegram };
    } catch (error) {
      // A ConfigError's text is fixed and value-free. Anything else is a bug
      // whose text could hold anything, so it is not forwarded.
      const details = error instanceof ConfigError ? error.message : "invalid configuration";
      throw new StatusError(grpc.status.INVALID_ARGUMENT, details);
    }
    // The token has no branch in this file where it could be logged, and
    // `api_base` is reduced to scheme and host.
    log(
      `configured: path=${state.path ?? "-"} dir=${state.dir ?? "-"}`,
      state.telegram
        ? `telegram chat_id=${state.telegram.chatId} api_base=${new URL(state.telegram.apiBase).origin}`
        : "telegram -",
    );
    return {};
  }),

  /** Reports what is relevant to what was configured, and sends nothing. */
  Preflight: unary(() => {
    const checks: Check[] = [];
    if (state?.path) checks.push(...folder.sourceChecks(state.path));
    if (state?.dir) checks.push(...folder.storageChecks(state.dir));
    if (state?.telegram) checks.push(...telegramChecks(state.telegram));
    if (checks.length === 0) {
      checks.push({
        name: "configuration",
        ok: false,
        detail: state
          ? "none of `path`, `dir` or the Telegram settings is configured"
          : "the plugin has not received its configuration yet",
        remediation: "give this role its fields: `path`, `dir`, or `bot_token` and `chat_id`",
      });
    }
    return { ok: checks.every((c) => c.ok), checks, source_version: "" };
  }),

  Shutdown: unary(() => {
    // The reply has to leave before the process does.
    setTimeout(() => process.exit(0), 50);
    return {};
  }),
};

type DataRequest = { data_socket: string };
type Stream<Req> = grpc.ServerWritableStream<Req, unknown>;

const sourceService: grpc.UntypedServiceImplementation = {
  /** Source → core: `tar -C <path> -cf - .` becomes the byte stream. */
  Dump: (call: Stream<DataRequest>) =>
    transfer(call, "dump", (_request, connect) => {
      const path = need("path", "`path`");
      const problem = folder.unreadable(path);
      if (problem) throw new StatusError(grpc.status.FAILED_PRECONDITION, problem);
      return (count) => withSocket(connect, (socket) => folder.dump(path, socket, count));
    }),

  /** Core → source: the byte stream is extracted with `tar -C <path> -xf -`. */
  Restore: (call: Stream<DataRequest>) =>
    transfer(call, "restore", (_request, connect) => {
      const path = need("path", "`path`");
      return (count) => withSocket(connect, (socket) => folder.restore(path, socket, count));
    }),
};

const storageService: grpc.UntypedServiceImplementation = {
  Put: (call: Stream<DataRequest & { key: string }>) =>
    transfer(call, "put", ({ key }, connect) => {
      const dir = need("dir", "`dir`");
      // Refused before the headers go out, while it can still be a status.
      folder.keyPath(dir, key);
      return (count) => withSocket(connect, (socket) => folder.put(dir, key, socket, count));
    }),

  Get: (call: Stream<DataRequest & { key: string }>) =>
    transfer(call, "get", ({ key }, connect) => {
      const dir = need("dir", "`dir`");
      // "It is not there" must be told apart from "it was cut off halfway".
      folder.locate(dir, key);
      return (count) => withSocket(connect, (socket) => folder.get(dir, key, socket, count));
    }),

  List: unary((request: { prefix: string }) => ({ artifacts: folder.list(need("dir", "`dir`"), request.prefix) })),

  Delete: unary((request: { key: string }) => {
    folder.remove(need("dir", "`dir`"), request.key);
    return {};
  }),

  AbortIncomplete: unary((request: { prefix: string }) => ({
    aborted: folder.abortIncomplete(need("dir", "`dir`"), request.prefix),
  })),
};

const notifierService: grpc.UntypedServiceImplementation = {
  Notify: unary(async (request: NotifyRequest) => {
    const telegram = need("telegram", "`bot_token` and `chat_id`");
    try {
      await notify(telegram, request);
    } catch (error) {
      // Only fixed sentences from telegram.ts reach the log and the status.
      const details = error instanceof NotifyError ? error.message : "unexpected failure";
      log(`${request.command}: ${details}`);
      throw new StatusError(grpc.status.UNAVAILABLE, details);
    }
    log(`${request.command}: sent`);
    return {};
  }),
};

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

interface Envelope {
  magic: string;
  core_protocol_versions: number[];
  control_socket: string;
  tls: { ca_cert_pem: string; server_cert_pem: string; server_key_pem: string };
}

/** Reads the single JSON line the core writes to stdin, which it then closes. */
async function readBootstrap(): Promise<Envelope> {
  const text = await Bun.stdin.text();
  const line = (text.split("\n", 1)[0] ?? "").trim();
  if (!line) throw new Error("nothing arrived on stdin");
  const envelope = JSON.parse(line) as Envelope;
  if (envelope.magic !== HANDSHAKE_MAGIC) throw new Error("the envelope is not a shieldbk one");
  if (!envelope.core_protocol_versions?.includes(PROTOCOL_VERSION)) {
    throw new Error(
      `no protocol version in common: the core speaks ${envelope.core_protocol_versions}, this plugin ${PROTOCOL_VERSION}`,
    );
  }
  return envelope;
}

function listen(envelope: Envelope): Promise<grpc.Server> {
  const server = new grpc.Server();
  // All three roles on one socket; the core only calls the ones it needs.
  server.addService(serviceOf("Plugin"), pluginService);
  server.addService(serviceOf("Source"), sourceService);
  server.addService(serviceOf("Storage"), storageService);
  server.addService(serviceOf("Notifier"), notifierService);

  // mTLS with the session's own material. The `true` makes a client
  // certificate mandatory: without it the channel is encrypted but open to
  // anybody who can reach the socket, and this process holds the bot token.
  const credentials = grpc.ServerCredentials.createSsl(
    Buffer.from(envelope.tls.ca_cert_pem),
    [
      {
        private_key: Buffer.from(envelope.tls.server_key_pem),
        cert_chain: Buffer.from(envelope.tls.server_cert_pem),
      },
    ],
    true,
  );

  return new Promise((resolve, reject) => {
    server.bindAsync(`unix:${envelope.control_socket}`, credentials, (error) =>
      error ? reject(error) : resolve(server),
    );
  });
}

/** The announcement. One line, on stdout, once the socket is really listening. */
function announce(): void {
  process.stdout.write(
    `${JSON.stringify({
      magic: HANDSHAKE_MAGIC,
      protocol_version: PROTOCOL_VERSION,
      // The same order and spelling the Rust SDK announces.
      capabilities: ["source", "storage", "notifier"],
      pid: process.pid,
    })}\n`,
  );
}

try {
  const envelope = await readBootstrap();
  await listen(envelope);
  // The core takes the announcement as a promise that the socket already
  // accepts connections, and dials it immediately.
  announce();
  log(`listening on ${envelope.control_socket}`);
} catch (error) {
  log(`could not start: ${error instanceof Error ? error.message : "unknown error"}`);
  process.exit(1);
}

process.on("SIGTERM", () => process.exit(0));
