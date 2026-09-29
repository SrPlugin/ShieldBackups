/**
 * The notifier role of `sb-plugin-folder`: everything that knows about Telegram
 * and nothing about gRPC — validating the configuration, building the message
 * and sending it.
 *
 * It lives apart from the protocol code so that it can be imported and tested
 * without starting a plugin (the entry file reads stdin at load time).
 *
 * ## The one rule of this file
 *
 * **The bot token never leaves this module in any string.** Telegram wants it
 * in the URL path (`/bot<token>/sendMessage`), which is the worst place for a
 * credential: `fetch` errors, redirects and HTTP libraries all like to quote the
 * URL. So nothing here ever forwards an error's own text. Every failure is
 * mapped to one of a few fixed sentences, and the response body is never read.
 */

import { type Check, ConfigError, type RawConfig } from "./types";

export const DEFAULT_API_BASE = "https://api.telegram.org";
export const DEFAULT_TIMEOUT = "10s";
/** Telegram rejects messages over 4096 characters; stay well below it. */
export const MAX_TEXT_UNITS = 3500;

export interface Settings {
  readonly botToken: string;
  readonly chatId: string;
  /** Without a trailing slash. */
  readonly apiBase: string;
  readonly timeoutMs: number;
}

export interface NotifyRequest {
  readonly command: string;
  readonly ok: boolean;
  readonly report_json: string;
}

/** A failure whose message is fixed text and safe to log, return and print. */
export class NotifyError extends Error {}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** `"30s"`, `"5m"`, `"250ms"` → milliseconds. */
export function durationMs(text: string): number {
  const match = /^(\d+)(ms|s|m|h)$/.exec(text.trim());
  if (!match) throw new ConfigError("`timeout` must look like 10s, 500ms or 1m");
  const units = { ms: 1, s: 1000, m: 60_000, h: 3_600_000 } as const;
  const unit = match[2] as keyof typeof units;
  return Number(match[1]) * units[unit];
}

/** Loopback is the one place plain http is harmless: nothing crosses a wire. */
function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "[::1]" || /^127(\.\d{1,3}){3}$/.test(hostname);
}

/**
 * Whether `api_base` may be used, as an error message or `null` when it may.
 *
 * The token travels in the path of every request, so plain http to anything
 * but this machine would put it on the wire in the clear. Loopback is allowed
 * only so that the tests can run against a fake Telegram. The message does not
 * echo the value: someone may have pasted the token into it.
 */
export function apiBaseProblem(apiBase: string): string | null {
  let url: URL;
  try {
    url = new URL(apiBase);
  } catch {
    return "`api_base` is not a valid URL";
  }
  if (url.protocol === "https:") return null;
  if (url.protocol === "http:" && isLoopback(url.hostname)) return null;
  return "`api_base` must be https:// (plain http is accepted only for loopback hosts)";
}

/**
 * Turns the map the core sent into settings. The core has checked types and
 * resolved the secret; what is left is what only this plugin knows.
 */
export function readSettings(raw: RawConfig): Settings {
  const text = (name: string): string => {
    const value = raw[name];
    return typeof value === "string" ? value.trim() : "";
  };

  const botToken = text("bot_token");
  if (!botToken) throw new ConfigError("`bot_token` cannot be empty");
  // The token is pasted into a URL path. Refusing anything a token never
  // contains also refuses `/`, `?` and `#`, which would rewrite that URL.
  if (!/^[A-Za-z0-9:_-]+$/.test(botToken)) {
    throw new ConfigError("`bot_token` has characters a Telegram bot token never contains");
  }

  const chatId = text("chat_id");
  if (!chatId) throw new ConfigError("`chat_id` cannot be empty");

  const apiBase = (text("api_base") || DEFAULT_API_BASE).replace(/\/+$/, "");
  const problem = apiBaseProblem(apiBase);
  if (problem) throw new ConfigError(problem);

  const timeoutMs = durationMs(text("timeout") || DEFAULT_TIMEOUT);
  if (timeoutMs === 0) throw new ConfigError("`timeout` cannot be zero: a hung notifier must end");

  return { botToken, chatId, apiBase, timeoutMs };
}

// ---------------------------------------------------------------------------
// The message
// ---------------------------------------------------------------------------

/**
 * Cuts `text` to at most `max` UTF-16 units, ending in `…`, without splitting
 * a surrogate pair: half an emoji is not valid text and Telegram would refuse
 * the whole message. (Counting UTF-16 units also keeps it under Telegram's own
 * limit in the worst case, which counting code points would not.)
 */
export function truncate(text: string, max: number = MAX_TEXT_UNITS): string {
  if (text.length <= max) return text;
  let cut = max - 1;
  const last = text.charCodeAt(cut - 1);
  if (last >= 0xd800 && last <= 0xdbff) cut -= 1;
  return `${text.slice(0, cut)}…`;
}

/** The failure text out of the command's JSON report, or a placeholder. */
function failureDetail(reportJson: string): string {
  try {
    const report: unknown = JSON.parse(reportJson);
    if (typeof report === "object" && report !== null) {
      const { error, code, class: kind } = report as Record<string, unknown>;
      for (const candidate of [error, code, kind]) {
        if (typeof candidate === "string" && candidate.trim()) return candidate.trim();
      }
    }
  } catch {
    // Not JSON: the verdict alone still makes a useful message.
  }
  return "no details in the report";
}

/** One line, plus the error when the command failed. Plain text on purpose. */
export function buildText(request: NotifyRequest): string {
  const text = request.ok
    ? `✅ shieldbk ${request.command}: ok`
    : `❌ shieldbk ${request.command} FAILED: ${failureDetail(request.report_json)}`;
  return truncate(text);
}

// ---------------------------------------------------------------------------
// Sending it
// ---------------------------------------------------------------------------

/**
 * Maps whatever `fetch` threw to a fixed sentence. The error's own message is
 * deliberately never used: it may contain the URL, and the URL contains the
 * token.
 */
export function describeUnreachable(error: unknown): string {
  const { name, code } = (error ?? {}) as { name?: unknown; code?: unknown };
  const why =
    name === "TimeoutError" || name === "AbortError"
      ? "timeout"
      : code === "ConnectionRefused" || code === "ECONNREFUSED"
        ? "connection refused"
        : typeof code === "string" && /CERT|SSL|TLS/i.test(code)
          ? "tls"
          : "network error";
  return `could not reach Telegram (${why})`;
}

/**
 * Sends one message. Throws a {@link NotifyError} with a fixed message on any
 * failure; resolves only when Telegram answered 2xx. `send` is a parameter so
 * tests can substitute the transport, though they mostly use a real local one.
 */
export async function notify(
  settings: Settings,
  request: NotifyRequest,
  send: typeof fetch = fetch,
): Promise<void> {
  let response: Response;
  try {
    response = await send(`${settings.apiBase}/bot${settings.botToken}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: settings.chatId, text: buildText(request) }),
      // A redirect is never followed: the target could be anywhere, and the
      // request carries the token. Any 3xx is a failure below.
      redirect: "manual",
      signal: AbortSignal.timeout(settings.timeoutMs),
    });
  } catch (error) {
    throw new NotifyError(describeUnreachable(error));
  }

  // The body is never read (it can echo the request) and never logged; just
  // release the connection.
  await response.body?.cancel().catch(() => undefined);

  if (response.status < 200 || response.status > 299) {
    throw new NotifyError(`Telegram answered HTTP ${response.status}`);
  }
}

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------

/**
 * What `shieldbk doctor` shows for this role. It sends **no message**: a
 * diagnostic that pings a chat every time somebody runs it would train people to
 * mute the chat. So it can only say the configuration is complete, and it says
 * nothing that derives from the token — not the token, not the URL it goes into.
 */
export function telegramChecks(settings: Settings): Check[] {
  const scheme = settings.apiBase.startsWith("https:") ? "https" : "http (loopback only)";
  return [
    { name: "telegram", ok: true, detail: "`bot_token` and `chat_id` are set", remediation: "" },
    { name: "telegram api_base", ok: true, detail: `\`api_base\` uses ${scheme}`, remediation: "" },
  ];
}
