import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Readable } from "node:stream";

import * as folder from "./folder";
import { ConfigError } from "./types";

let root: string;
let store: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "sb-folder-"));
  store = join(root, "store");
  mkdirSync(store);
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

/** Collects a stream into a string. */
async function drain(stream: Readable): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString();
}

/** Every file under `dir`, relative, sorted: what is *really* on disk. */
function tree(dir: string): string[] {
  return (readdirSync(dir, { recursive: true }) as string[]).sort();
}

describe("keys", () => {
  test("a normal key lands inside the directory", () => {
    expect(folder.keyPath(store, "app/2026/08/x.age")).toBe(join(store, "app/2026/08/x.age"));
  });

  test("keys that escape or confuse are refused before anything is opened", () => {
    const bad = [
      "",
      "..",
      "../outside",
      "a/../../outside",
      "a/./b",
      "/etc/passwd",
      "a//b",
      "a/",
      "a\\b",
      "..\\outside",
      "a\0b",
      "x.age.part",
    ];
    for (const key of bad) {
      expect(() => folder.keyPath(store, key), JSON.stringify(key)).toThrow(folder.KeyError);
    }
    // Refused means nothing was touched.
    expect(tree(root)).toEqual(["store"]);
  });

  test("a symlink inside the directory is not followed out of it", () => {
    const outside = join(root, "outside");
    mkdirSync(outside);
    writeFileSync(join(outside, "secret"), "s3cret");
    symlinkSync(outside, join(store, "link")); // a directory link
    symlinkSync(join(outside, "secret"), join(store, "file-link")); // a file link

    expect(() => folder.keyPath(store, "link/new.age")).toThrow(folder.KeyError);
    expect(() => folder.keyPath(store, "file-link")).toThrow(folder.KeyError);
    expect(() => folder.locate(store, "file-link")).toThrow(folder.KeyError);
    expect(folder.list(store, "")).toEqual([]);
    expect(readdirSync(outside)).toEqual(["secret"]);
  });

  test("put, get and delete all refuse a bad key", async () => {
    await expect(folder.put(store, "../x", Readable.from(["a"]))).rejects.toThrow(folder.KeyError);
    await expect(folder.get(store, "../x", new PassThrough())).rejects.toThrow(folder.KeyError);
    expect(() => folder.remove(store, "../x")).toThrow(folder.KeyError);
    expect(tree(root)).toEqual(["store"]);
  });
});

describe("storage", () => {
  test("what is put comes back byte for byte, with nested keys", async () => {
    const data = Buffer.from(Array.from({ length: 300_000 }, (_, i) => i % 251));
    let counted = 0;
    await folder.put(store, "app/2026/a.age", Readable.from([data.subarray(0, 1000), data.subarray(1000)]), (n) => (counted += n));
    expect(counted).toBe(data.length);

    const out = new PassThrough();
    const read = drain(out);
    await folder.get(store, "app/2026/a.age", out);
    expect(Buffer.from(await read, "latin1").length).toBe(data.length);
    expect(readFileSync(join(store, "app/2026/a.age")).equals(data)).toBe(true);
  });

  test("a put that fails halfway leaves no artifact and no .part", async () => {
    const broken = new Readable({
      read() {
        this.push("half of a backup");
        this.destroy(new Error("the data channel was cut"));
      },
    });
    await expect(folder.put(store, "app/x.age", broken)).rejects.toThrow("cut");
    expect(folder.list(store, "")).toEqual([]);
    expect(tree(store)).toEqual(["app"]); // the directory, and nothing in it
  });

  test("a failed put does not damage the artifact that was already there", async () => {
    await folder.put(store, "x.age", Readable.from(["good"]));
    const broken = new Readable({
      read() {
        this.destroy(new Error("cut"));
      },
    });
    await expect(folder.put(store, "x.age", broken)).rejects.toThrow();
    expect(readFileSync(join(store, "x.age"), "utf8")).toBe("good");
  });

  test("the artifact appears only once the upload finished", async () => {
    const gate = new PassThrough();
    const uploading = folder.put(store, "x.age", gate);
    gate.write("partial");
    await Bun.sleep(50);
    expect(folder.list(store, "")).toEqual([]); // the .part is not an artifact
    expect(existsSync(join(store, "x.age.part"))).toBe(true);
    gate.end();
    await uploading;
    expect(folder.list(store, "").map((a) => a.key)).toEqual(["x.age"]);
    expect(existsSync(join(store, "x.age.part"))).toBe(false);
  });

  test("getting what is not there is a MissingError, before anything streams", async () => {
    expect(() => folder.locate(store, "nope.age")).toThrow(folder.MissingError);
    const sink = new PassThrough();
    await expect(folder.get(store, "nope.age", sink)).rejects.toThrow(folder.MissingError);
    expect(sink.writableEnded).toBe(false);
  });

  test("list is sorted, filtered by prefix and walks subdirectories", async () => {
    for (const key of ["b/2.age", "a/b/1.age", "a/0.age", "c.age"]) {
      await folder.put(store, key, Readable.from(["xx"]));
    }
    expect(folder.list(store, "").map((a) => a.key)).toEqual(["a/0.age", "a/b/1.age", "b/2.age", "c.age"]);
    expect(folder.list(store, "a/").map((a) => a.key)).toEqual(["a/0.age", "a/b/1.age"]);
    expect(folder.list(store, "a/")[0]?.size).toBe(2);
  });

  test("listing a directory that does not exist is an empty store", () => {
    expect(folder.list(join(root, "never-created"), "")).toEqual([]);
  });

  test("modified_at is RFC-3339 UTC, twenty characters, no fraction", async () => {
    await folder.put(store, "x.age", Readable.from(["x"]));
    // 1 771 234 200 = 2026-02-16T09:30:00Z, with a fraction on the file's mtime.
    utimesSync(join(store, "x.age"), 1_771_234_200.987, 1_771_234_200.987);
    const [artifact] = folder.list(store, "");
    expect(artifact?.modified_at).toBe("2026-02-16T09:30:00Z");
    expect(artifact?.modified_at).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  });

  test("an unusable date is the empty string, never an invented one", () => {
    expect(folder.rfc3339(Number.NaN)).toBe("");
    expect(folder.rfc3339(8.64e15)).toBe("");
    expect(folder.rfc3339(-8.64e15)).toBe("");
  });

  test("delete is idempotent", async () => {
    await folder.put(store, "a/x.age", Readable.from(["x"]));
    folder.remove(store, "a/x.age");
    expect(folder.list(store, "")).toEqual([]);
    folder.remove(store, "a/x.age"); // already gone
    folder.remove(store, "never/existed.age"); // parent missing too
    await folder.put(store, "f.age", Readable.from(["x"]));
    folder.remove(store, "f.age/deeper"); // a file where a directory would be
    expect(folder.list(store, "").map((a) => a.key)).toEqual(["f.age"]);
  });

  test("abortIncomplete removes stale .part files under the prefix and counts them", () => {
    mkdirSync(join(store, "a"));
    mkdirSync(join(store, "b"));
    for (const name of ["a/old.age.part", "a/older.age.part", "b/other.age.part", "a/keep.age"]) {
      writeFileSync(join(store, name), "x");
    }
    const longAgo = Date.now() / 1000 - 3600;
    for (const name of ["a/old.age.part", "a/older.age.part", "b/other.age.part"]) {
      utimesSync(join(store, name), longAgo, longAgo);
    }
    writeFileSync(join(store, "a/fresh.age.part"), "still uploading");

    expect(folder.abortIncomplete(store, "a/")).toBe(2);
    expect(tree(store)).toEqual(["a", "a/fresh.age.part", "a/keep.age", "b", "b/other.age.part"]);
    expect(folder.abortIncomplete(store, "a/")).toBe(0);
    expect(folder.abortIncomplete(store, "", -1)).toBe(2); // no grace at all: the fresh one and b/ too
  });
});

describe("source", () => {
  test("a folder dumped as tar and restored is byte for byte the same", async () => {
    const from = join(root, "from");
    mkdirSync(join(from, "sub/deeper"), { recursive: true });
    writeFileSync(join(from, "notes.txt"), "the quick brown fox\n");
    writeFileSync(join(from, "sub/deeper/blob.bin"), Buffer.from(Array.from({ length: 500_000 }, (_, i) => (i * 7) % 256)));
    writeFileSync(join(from, "a name; with $(odd) chars.txt"), "no shell in the way");

    const wire = new PassThrough();
    let out = 0;
    let inn = 0;
    const to = join(root, "to");
    await Promise.all([folder.dump(from, wire, (n) => (out += n)), folder.restore(to, wire, (n) => (inn += n))]);

    expect(out).toBeGreaterThan(500_000);
    expect(inn).toBe(out);
    expect(tree(to)).toEqual(tree(from));
    for (const file of ["notes.txt", "sub/deeper/blob.bin", "a name; with $(odd) chars.txt"]) {
      expect(readFileSync(join(to, file)).equals(readFileSync(join(from, file)))).toBe(true);
    }
  });

  test("restore creates the target folder if it is missing", async () => {
    const from = join(root, "from");
    mkdirSync(from);
    writeFileSync(join(from, "x"), "x");
    const wire = new PassThrough();
    await Promise.all([folder.dump(from, wire), folder.restore(join(root, "a/b/c"), wire)]);
    expect(readFileSync(join(root, "a/b/c/x"), "utf8")).toBe("x");
  });

  test("dumping a folder that cannot be read fails with tar's explanation", async () => {
    const wire = new PassThrough();
    wire.resume();
    await expect(folder.dump(join(root, "missing"), wire)).rejects.toThrow(/tar exited/);
  });

  test("restoring something that is not a tar fails", async () => {
    await expect(folder.restore(join(root, "to"), Readable.from(["this is not a tar archive at all\n".repeat(50)]))).rejects.toThrow(/tar exited/);
  });

  test("unreadable() names the problem and accepts a real directory", () => {
    expect(folder.unreadable(root)).toBeNull();
    expect(folder.unreadable(join(root, "missing"))).not.toBeNull();
    writeFileSync(join(root, "file"), "x");
    expect(folder.unreadable(join(root, "file"))).toContain("not a directory");
  });
});

describe("configuration and preflight", () => {
  test("path and dir are optional, and when present cannot be empty", () => {
    expect(folder.readFolders({})).toEqual({ path: undefined, dir: undefined });
    expect(folder.readFolders({ path: " /data ", dir: "/b" })).toEqual({ path: "/data", dir: "/b" });
    expect(() => folder.readFolders({ path: "  " })).toThrow(ConfigError);
    expect(() => folder.readFolders({ dir: "" })).toThrow(ConfigError);
  });

  test("checks report the folder and the store, with a remedy when they fail", () => {
    expect(folder.sourceChecks(root).every((c) => c.ok)).toBe(true);
    const bad = folder.sourceChecks(join(root, "missing"));
    expect(bad[0]?.ok).toBe(false);
    expect(bad[0]?.remediation).not.toBe("");

    expect(folder.storageChecks(join(root, "new/store"))[0]?.ok).toBe(true);
    writeFileSync(join(root, "blocker"), "x");
    const blocked = folder.storageChecks(join(root, "blocker/inside"))[0];
    expect(blocked?.ok).toBe(false);
    expect(blocked?.remediation).not.toBe("");
  });
});
