/**
 * A stand-in for api.telegram.org, for try-it.sh: it answers every request
 * with `{"ok":true}` and appends what it received, one JSON object per line,
 * to a file the script inspects afterwards.
 *
 *     bun fake-telegram.ts <port-file> <log-file>
 *
 * It listens on loopback only and picks its own port, which it writes to
 * <port-file> once it is accepting connections.
 */
import { appendFileSync, writeFileSync } from "node:fs";

const [portFile, logFile] = process.argv.slice(2);
if (!portFile || !logFile) {
  console.error("usage: bun fake-telegram.ts <port-file> <log-file>");
  process.exit(2);
}

const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  async fetch(request) {
    const body: unknown = await request.json().catch(() => null);
    appendFileSync(logFile, `${JSON.stringify({ path: new URL(request.url).pathname, body })}\n`);
    return Response.json({ ok: true, result: {} });
  },
});
writeFileSync(portFile, String(server.port));
