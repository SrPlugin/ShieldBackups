import { afterAll, beforeEach, describe, expect, test } from "bun:test";

import {
  MAX_TEXT_UNITS,
  NotifyError,
  type NotifyRequest,
  type Settings,
  apiBaseProblem,
  buildText,
  describeUnreachable,
  durationMs,
  notify,
  readSettings,
  telegramChecks,
  truncate,
} from "./telegram";
import { ConfigError } from "./types";

// A token shaped like a real one. Every test that could leak it looks for this.
const TOKEN = "123456789:AAE-secret_token_value";

const good = { bot_token: TOKEN, chat_id: "-100123" };
const failed: NotifyRequest = {
  command: "backup",
  ok: false,
  report_json: JSON.stringify({ ok: false, class: "storage", code: "E_STORE", error: "disk full" }),
};
const succeeded: NotifyRequest = { command: "backup", ok: true, report_json: '{"ok":true}' };

describe("message", () => {
  test("a success is one short line", () => {
    expect(buildText(succeeded)).toBe("✅ shieldbk backup: ok");
  });

  test("a failure carries the error from the report", () => {
    expect(buildText(failed)).toBe("❌ shieldbk backup FAILED: disk full");
  });

  test("a failure without an error falls back to code, class, then a placeholder", () => {
    const text = (report: string) => buildText({ command: "verify", ok: false, report_json: report });
    expect(text('{"code":"E_X","class":"y"}')).toBe("❌ shieldbk verify FAILED: E_X");
    expect(text('{"class":"y"}')).toBe("❌ shieldbk verify FAILED: y");
    expect(text("{}")).toBe("❌ shieldbk verify FAILED: no details in the report");
    expect(text("not json")).toBe("❌ shieldbk verify FAILED: no details in the report");
    expect(text("null")).toBe("❌ shieldbk verify FAILED: no details in the report");
  });

  test("a long text is cut to the limit and marked", () => {
    const text = buildText({ ...failed, report_json: JSON.stringify({ error: "x".repeat(10_000) }) });
    expect(text.length).toBe(MAX_TEXT_UNITS);
    expect(text.endsWith("…")).toBe(true);
  });

  test("truncation never splits a surrogate pair", () => {
    // "😀" is two UTF-16 units. Put one across every possible boundary.
    for (const prefix of ["a".repeat(8), "a".repeat(9)]) {
      const cut = truncate(`${prefix}😀😀😀`, 10);
      expect(cut.length).toBeLessThanOrEqual(10);
      expect(cut.endsWith("…")).toBe(true);
      // A lone surrogate would make the string ill-formed.
      expect(cut.isWellFormed()).toBe(true);
    }
    expect(truncate("short", 10)).toBe("short");
  });
});

describe("api_base", () => {
  test("https is accepted anywhere", () => {
    expect(apiBaseProblem("https://api.telegram.org")).toBeNull();
    expect(apiBaseProblem("https://proxy.example.com/telegram")).toBeNull();
  });

  test("plain http is accepted only for loopback", () => {
    for (const ok of ["http://127.0.0.1:8080", "http://localhost:9", "http://[::1]:1", "http://127.1.2.3"]) {
      expect(apiBaseProblem(ok)).toBeNull();
    }
    for (const bad of ["http://api.telegram.org", "http://10.0.0.5", "http://127.0.0.1.evil.com", "ftp://x", "nope"]) {
      expect(apiBaseProblem(bad)).not.toBeNull();
    }
  });

  test("the refusal does not echo the value", () => {
    expect(apiBaseProblem(`http://evil.example/${TOKEN}`)).not.toContain(TOKEN);
    expect(apiBaseProblem(TOKEN)).not.toContain(TOKEN);
  });
});

describe("configuration", () => {
  test("defaults apply", () => {
    expect(readSettings(good)).toEqual({
      botToken: TOKEN,
      chatId: "-100123",
      apiBase: "https://api.telegram.org",
      timeoutMs: 10_000,
    });
  });

  test("overrides apply and a trailing slash is dropped", () => {
    const s = readSettings({ ...good, api_base: "http://127.0.0.1:5/", timeout: "250ms" });
    expect(s.apiBase).toBe("http://127.0.0.1:5");
    expect(s.timeoutMs).toBe(250);
  });

  test("required fields cannot be empty or missing", () => {
    expect(() => readSettings({ chat_id: "1" })).toThrow(ConfigError);
    expect(() => readSettings({ bot_token: "  ", chat_id: "1" })).toThrow(ConfigError);
    expect(() => readSettings({ bot_token: TOKEN })).toThrow(ConfigError);
  });

  test("a token that could rewrite the URL is refused, without being quoted", () => {
    for (const bad of ["123:abc/../x", "123:abc?x=1", "123:abc#", "12 3"]) {
      const error = (() => {
        try {
          readSettings({ ...good, bot_token: bad });
        } catch (e) {
          return e as Error;
        }
      })();
      expect(error).toBeInstanceOf(ConfigError);
      expect(error?.message).not.toContain(bad);
    }
  });

  test("a bad api_base or timeout is refused", () => {
    expect(() => readSettings({ ...good, api_base: "http://example.com" })).toThrow(ConfigError);
    expect(() => readSettings({ ...good, timeout: "soon" })).toThrow(ConfigError);
    expect(() => readSettings({ ...good, timeout: "0s" })).toThrow(ConfigError);
  });

  test("durations", () => {
    expect(durationMs("1h")).toBe(3_600_000);
    expect(durationMs("2m")).toBe(120_000);
    expect(() => durationMs("10")).toThrow(ConfigError);
  });
});

describe("failure mapping", () => {
  test("each failure becomes a fixed sentence", () => {
    const named = (name: string, code?: string) => Object.assign(new Error(`GET https://x/bot${TOKEN}`), { name, code });
    expect(describeUnreachable(named("TimeoutError"))).toBe("could not reach Telegram (timeout)");
    expect(describeUnreachable(named("TypeError", "ConnectionRefused"))).toBe("could not reach Telegram (connection refused)");
    expect(describeUnreachable(named("TypeError", "UNKNOWN_CERTIFICATE_VERIFICATION_ERROR"))).toBe("could not reach Telegram (tls)");
    expect(describeUnreachable(named("TypeError", "ENOTFOUND"))).toBe("could not reach Telegram (network error)");
    expect(describeUnreachable(undefined)).toBe("could not reach Telegram (network error)");
  });

  test("the error's own text, URL and token included, is never used", () => {
    const hostile = new Error(`connect failed for https://api.telegram.org/bot${TOKEN}/sendMessage`);
    expect(describeUnreachable(hostile)).not.toContain(TOKEN);
  });
});

describe("preflight", () => {
  const settings: Settings = readSettings(good);

  test("reports the configuration as complete without touching the token", () => {
    const checks = telegramChecks(settings);
    expect(checks.every((c) => c.ok)).toBe(true);
    expect(JSON.stringify(checks)).not.toContain(TOKEN);
    expect(JSON.stringify(checks)).not.toContain("/bot");
  });

  test("names loopback http honestly", () => {
    const checks = telegramChecks({ ...settings, apiBase: "http://127.0.0.1:1" });
    expect(checks[1]?.detail).toContain("loopback");
  });
});

// ---------------------------------------------------------------------------
// Against a fake Telegram on loopback
// ---------------------------------------------------------------------------

interface Seen {
  method: string;
  path: string;
  contentType: string | null;
  body: unknown;
}

let seen: Seen[] = [];
/** What the fake answers next; tests set it. */
let reply: (path: string) => Response | Promise<Response> = () => Response.json({ ok: true });

const fake = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  async fetch(request) {
    const text = await request.text();
    const path = new URL(request.url).pathname;
    seen.push({
      method: request.method,
      path,
      contentType: request.headers.get("content-type"),
      body: text ? JSON.parse(text) : null,
    });
    return reply(path);
  },
});
afterAll(() => fake.stop(true));

const settings = (over: Partial<Settings> = {}): Settings => ({
  botToken: TOKEN,
  chatId: "12345",
  apiBase: `http://127.0.0.1:${fake.port}`,
  timeoutMs: 2000,
  ...over,
});

/** Runs `notify` and returns the error it threw. */
async function failure(s: Settings, request: NotifyRequest = failed): Promise<Error> {
  try {
    await notify(s, request);
  } catch (error) {
    return error as Error;
  }
  throw new Error("notify was expected to fail");
}

beforeEach(() => {
  seen = [];
  reply = () => Response.json({ ok: true });
});

describe("notify against a fake Telegram", () => {
  test("posts JSON to /bot<token>/sendMessage with chat_id and text only", async () => {
    await notify(settings(), failed);
    expect(seen).toHaveLength(1);
    const [request] = seen;
    expect(request?.method).toBe("POST");
    expect(request?.path).toBe(`/bot${TOKEN}/sendMessage`);
    expect(request?.contentType).toContain("application/json");
    expect(request?.body).toEqual({ chat_id: "12345", text: "❌ shieldbk backup FAILED: disk full" });
  });

  test("a path prefix in api_base is kept", async () => {
    await notify(settings({ apiBase: `http://127.0.0.1:${fake.port}/relay` }), succeeded);
    expect(seen[0]?.path).toBe(`/relay/bot${TOKEN}/sendMessage`);
  });

  for (const status of [401, 500]) {
    test(`HTTP ${status} is an error without the token or the body`, async () => {
      reply = () =>
        new Response(`{"description":"bad token ${TOKEN}"}`, { status });
      const error = await failure(settings());
      expect(error).toBeInstanceOf(NotifyError);
      expect(error.message).toBe(`Telegram answered HTTP ${status}`);
      expect(error.message).not.toContain(TOKEN);
      expect(String(error.stack)).not.toContain(TOKEN);
    });
  }

  test("a redirect is not followed and counts as a failure", async () => {
    reply = (path) =>
      path === "/landed" ? Response.json({ ok: true }) : new Response(null, { status: 302, headers: { location: "/landed" } });
    const error = await failure(settings());
    expect(error.message).toBe("Telegram answered HTTP 302");
    expect(seen.map((s) => s.path)).toEqual([`/bot${TOKEN}/sendMessage`]);
  });

  test("a slow server times out, and the message says so without the token", async () => {
    reply = async () => {
      await Bun.sleep(1500);
      return Response.json({ ok: true });
    };
    const started = performance.now();
    const error = await failure(settings({ timeoutMs: 150 }));
    expect(performance.now() - started).toBeLessThan(1200);
    expect(error.message).toBe("could not reach Telegram (timeout)");
    expect(error.message).not.toContain(TOKEN);
  });

  test("a closed port is 'connection refused' without the token", async () => {
    // Stop a second server to get a port that was just free.
    const dead = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response("") });
    const apiBase = `http://127.0.0.1:${dead.port}`;
    dead.stop(true);
    const error = await failure(settings({ apiBase }));
    expect(error.message).toBe("could not reach Telegram (connection refused)");
    expect(error.message).not.toContain(TOKEN);
  });

  test("whatever the transport throws, its text does not get through", async () => {
    const leaky = (async () => {
      throw new TypeError(`fetch failed: https://api.telegram.org/bot${TOKEN}/sendMessage`);
    }) as unknown as typeof fetch;
    const error = await notify(settings(), failed, leaky).then(
      () => new Error("expected a failure"),
      (e: Error) => e,
    );
    expect(error).toBeInstanceOf(NotifyError);
    expect(error.message).not.toContain(TOKEN);
  });
});
