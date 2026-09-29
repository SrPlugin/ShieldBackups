/**
 * The source and storage roles of `sb-plugin-folder`, with no gRPC in sight.
 *
 *   - **Source**: a folder is streamed out as a tar (`Dump`) and rebuilt from
 *     one (`Restore`). `tar` does the work; this file only pipes it.
 *   - **Storage**: a directory plays the part of a bucket, as
 *     `plugins/sb-plugin-mock` does in Rust.
 *
 * The functions take and return plain Node streams, so the tests can push a
 * tar from `Dump` into `Restore` without a data socket in between.
 *
 * ## Why the storage half is careful
 *
 * An artifact key arrives over the network and ends up as a filesystem path,
 * which is exactly where one `..` stops being a detail. So a key is checked
 * **before anything is opened**, and nothing under the directory is ever
 * followed through a symlink.
 */

import {
  accessSync,
  constants,
  createReadStream,
  createWriteStream,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  type Stats,
} from "node:fs";
import { dirname, join } from "node:path";
import { Readable, Transform, type Writable } from "node:stream";
import { pipeline } from "node:stream/promises";

import { type Check, type RawConfig, textField } from "./types";

/** An `INVALID_ARGUMENT`-style refusal; the protocol layer decides the code. */
export class KeyError extends Error {}
/** A key that names nothing (`NOT_FOUND`). */
export class MissingError extends Error {}

/** Suffix of an upload in progress. A key may not end with it. */
export const PART = ".part";
/** How old a `.part` must be before `AbortIncomplete` treats it as abandoned. */
export const STALE_PART_MS = 60_000;
/** How much of tar's stderr is kept to explain a failure. */
const STDERR_KEPT_BYTES = 8192;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * `path` (source) and `dir` (storage). Each role runs in its own process with
 * its own config table, so a process usually has only one of them; each RPC
 * checks the one it needs when it is called.
 */
export function readFolders(raw: RawConfig): { path: string | undefined; dir: string | undefined } {
  return { path: textField(raw, "path"), dir: textField(raw, "dir") };
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/**
 * Turns a key into a path inside `dir`, or throws.
 *
 * Only `a/b/c.age` shapes pass: no empty segment (which rules out a leading or
 * trailing `/` and `//`), no `.` or `..`, no NUL, no backslash (a Windows-style
 * separator is a component on the machine that reads the file back), and no
 * `.part` suffix, which belongs to uploads in progress. Then every component
 * that already exists must be a real file or directory: a symlink in the
 * middle of a key would carry a write outside `dir`.
 *
 * Limit: checked at the time of use, not atomically. Someone who can write
 * into `dir` *while* a request runs can still swap a component for a symlink;
 * `dir` is meant to be owned by the plugin's user alone.
 */
export function keyPath(dir: string, key: string): string {
  const refuse = (why: string): never => {
    throw new KeyError(`the key is not acceptable: ${why}`);
  };
  if (!key) return refuse("it is empty");
  if (key.includes("\0")) return refuse("it contains a NUL");
  if (key.includes("\\")) return refuse("it contains a backslash");
  if (key.endsWith(PART)) return refuse(`it ends in \`${PART}\`, which is reserved`);
  const parts = key.split("/");
  if (parts.some((p) => p === "" || p === "." || p === "..")) {
    return refuse("it is absolute or has an empty, `.` or `..` component");
  }

  let current = dir;
  for (const part of parts) {
    current = join(current, part);
    const found = lstatOrNull(current);
    if (!found) break; // nothing below a missing component can be a symlink
    if (found.isSymbolicLink()) return refuse("it goes through a symbolic link");
  }
  return join(dir, ...parts);
}

function lstatOrNull(path: string): Stats | null {
  try {
    return lstatSync(path);
  } catch (error) {
    // ENOTDIR: a file sits where a directory would have to be. Nothing is there.
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return null;
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------------

/** A pass-through that counts the bytes crossing it. */
function counting(onBytes: (n: number) => void): Transform {
  return new Transform({
    transform(chunk: Buffer, _encoding, done) {
      onBytes(chunk.length);
      done(null, chunk);
    },
  });
}

/**
 * Stores `source` under `key`.
 *
 * The bytes go to `<key>.part` and are renamed into place only once the stream
 * ended cleanly, so an upload that is cut halfway never looks like an artifact:
 * a truncated backup that lists fine is how a restore fails months later.
 *
 * Limit: two concurrent puts of the same key clobber each other's `.part`.
 * The core never does that; a unique suffix would fix it if one ever did.
 */
export async function put(
  dir: string,
  key: string,
  source: Readable,
  onBytes: (n: number) => void = () => {},
): Promise<void> {
  const dest = keyPath(dir, key);
  const part = dest + PART;
  mkdirSync(dirname(dest), { recursive: true });
  // A leftover from an earlier crash goes first; `wx` then refuses to open
  // anything that appears in its place, a symlink included.
  rmSync(part, { force: true });
  try {
    await pipeline(source, counting(onBytes), createWriteStream(part, { flags: "wx", mode: 0o600, flush: true }));
    renameSync(part, dest);
  } catch (error) {
    rmSync(part, { force: true });
    throw error;
  }
}

/** Checks that `key` names a stored file and returns its path. Nothing is opened. */
export function locate(dir: string, key: string): string {
  const path = keyPath(dir, key);
  if (!lstatOrNull(path)?.isFile()) throw new MissingError(`the artifact \`${key}\` does not exist`);
  return path;
}

/** Streams the artifact `key` into `sink`, which is ended when the file is. */
export async function get(
  dir: string,
  key: string,
  sink: Writable,
  onBytes: (n: number) => void = () => {},
): Promise<void> {
  const path = locate(dir, key);
  // O_NOFOLLOW: if the file was swapped for a symlink since `locate`, open fails.
  const file = createReadStream(path, { fd: openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW) });
  await pipeline(file, counting(onBytes), sink);
}

export interface Artifact {
  key: string;
  size: number;
  modified_at: string;
}

/**
 * `2026-08-21T09:30:00Z`: RFC-3339, UTC, exactly twenty characters. The
 * `.proto` fixes the format, fractions included, because targets that answer
 * differently stop being comparable (`…:15Z` sorts after `…:15.983Z`). Empty
 * when the date is unusable: an invented one could decide what retention
 * deletes.
 */
export function rfc3339(ms: number): string {
  const date = new Date(ms);
  const year = date.getUTCFullYear();
  if (Number.isNaN(year) || year < 1000 || year > 9999) return "";
  return `${date.toISOString().slice(0, 19)}Z`;
}

/**
 * Artifacts whose key starts with `prefix`, sorted by key. A directory that
 * does not exist yet is an empty store, not an error. Symlinks and in-progress
 * uploads are not artifacts and are skipped.
 */
export function list(dir: string, prefix: string): Artifact[] {
  const found: Artifact[] = [];
  walk(dir, "", (key, _path, stat) => {
    if (!key.endsWith(PART) && key.startsWith(prefix)) {
      found.push({ key, size: stat.size, modified_at: rfc3339(stat.mtimeMs) });
    }
  });
  return found.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

function walk(root: string, below: string, visit: (key: string, path: string, stat: Stats) => void): void {
  let entries;
  try {
    entries = readdirSync(join(root, below), { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  for (const entry of entries) {
    const key = below ? `${below}/${entry.name}` : entry.name;
    if (entry.isDirectory()) walk(root, key, visit);
    else if (entry.isFile()) visit(key, join(root, key), lstatSync(join(root, key)));
  }
}

/**
 * Deletes `key`. Deleting what is already gone succeeds: that is the result
 * that was asked for, and a retention pass that retries must not fail for
 * having succeeded.
 */
export function remove(dir: string, key: string): void {
  const path = keyPath(dir, key);
  if (lstatOrNull(path)) rmSync(path, { force: true }); // `force` covers a race with ENOENT
}

/**
 * Removes abandoned `.part` files under `prefix` and returns how many. Only
 * those untouched for `minAgeMs`: a `.part` that changed a moment ago belongs
 * to an upload that is still running, and deleting it would fail that backup.
 */
export function abortIncomplete(dir: string, prefix: string, minAgeMs: number = STALE_PART_MS): number {
  let aborted = 0;
  walk(dir, "", (key, path, stat) => {
    if (key.endsWith(PART) && key.startsWith(prefix) && Date.now() - stat.mtimeMs >= minAgeMs) {
      rmSync(path, { force: true });
      aborted += 1;
    }
  });
  return aborted;
}

// ---------------------------------------------------------------------------
// The tar source
// ---------------------------------------------------------------------------

/**
 * Runs `tar` with an argument **list**: there is no shell in between, so a
 * folder called `x; rm -rf ~` is just a folder. Returns the child and a
 * function that waits for it and throws, with the tail of its stderr, if it
 * did not succeed.
 */
function tar(argv: string[], stdin: "ignore" | ReadableStream, stdout: "pipe" | "ignore") {
  const child = Bun.spawn({ cmd: ["tar", ...argv], stdin, stdout, stderr: "pipe" });
  // An unread stderr pipe eventually blocks the writer, so drain it as it
  // arrives and keep the tail: "Cannot open: Permission denied" is the whole
  // diagnosis.
  let tail = "";
  const draining = (async () => {
    for await (const chunk of child.stderr) {
      tail = (tail + Buffer.from(chunk).toString("utf8")).slice(-STDERR_KEPT_BYTES);
    }
  })();
  return {
    child,
    async settle(): Promise<void> {
      const code = await child.exited;
      await draining;
      if (code !== 0) {
        const detail = tail.trim().split("\n").slice(-3).join(" / ");
        throw new Error(`tar exited with code ${code}${detail ? `: ${detail}` : ""}`);
      }
    },
  };
}

/** Whether `path` is a directory this process can read, as a message or `null`. */
export function unreadable(path: string): string | null {
  try {
    if (!statSync(path).isDirectory()) return `${path} is not a directory`;
    accessSync(path, constants.R_OK | constants.X_OK);
    return null;
  } catch (error) {
    return `${path}: ${(error as NodeJS.ErrnoException).code ?? "cannot be read"}`;
  }
}

/** Writes a tar of the contents of `path` into `sink`, which is ended after. */
export async function dump(path: string, sink: Writable, onBytes: (n: number) => void = () => {}): Promise<void> {
  const command = tar(["-C", path, "-cf", "-", "."], "ignore", "pipe");
  try {
    // `stdout` is always a stream here: it was spawned with `"pipe"`.
    await pipeline(Readable.fromWeb(command.child.stdout!), counting(onBytes), sink);
    await command.settle();
  } catch (error) {
    command.child.kill("SIGKILL");
    throw error;
  }
}

/** Extracts the tar read from `source` into `path`, which is created if needed. */
export async function restore(path: string, source: Readable, onBytes: (n: number) => void = () => {}): Promise<void> {
  mkdirSync(path, { recursive: true });
  const counted = source.pipe(counting(onBytes));
  const command = tar(["-C", path, "-xf", "-"], Readable.toWeb(counted) as ReadableStream, "ignore");
  try {
    await command.settle();
  } catch (error) {
    source.destroy();
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------

export function sourceChecks(path: string): Check[] {
  const problem = unreadable(path);
  return [
    problem
      ? { name: "source folder", ok: false, detail: problem, remediation: "point `path` at an existing directory this user can read" }
      : { name: "source folder", ok: true, detail: `${path} is readable`, remediation: "" },
    Bun.which("tar")
      ? { name: "tar", ok: true, detail: "tar is on PATH", remediation: "" }
      : { name: "tar", ok: false, detail: "`tar` is not on PATH", remediation: "install tar" },
  ];
}

/** Creates `dir` if it is missing, like the mock storage: an empty store is valid. */
export function storageChecks(dir: string): Check[] {
  try {
    mkdirSync(dir, { recursive: true });
    accessSync(dir, constants.W_OK);
    return [{ name: "storage directory", ok: true, detail: `${dir} is writable`, remediation: "" }];
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code ?? "unknown error";
    return [
      {
        name: "storage directory",
        ok: false,
        detail: `${dir} is not writable (${code})`,
        remediation: "create it by hand or point `dir` at a path this user can write to",
      },
    ];
  }
}
