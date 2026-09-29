#!/usr/bin/env bash
#
# Runs the whole cycle through this one plugin: back up a folder (source ->
# `folder`), keep the encrypted artifact in a directory (storage -> `folder`),
# and tell a fake Telegram how it went (notifier -> `folder`). Then verifies the
# artifact, restores it, and compares the restored folder with the original
# byte for byte.
#
# It builds `shieldbk`, the plugin's single-file executable, installs it into a
# throwaway directory under `run/`, starts a fake Telegram on a loopback port,
# and checks that
#   * the fake received the message, at `/bot<token>/sendMessage`, and
#   * the bot token appears nowhere in anything `shieldbk` printed.
# Nothing is written outside `run/`.
#
#     ./try-it.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
RUN="$HERE/run"

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
fail() { printf '\n\033[1;31mFAILED: %s\033[0m\n' "$1" >&2; exit 1; }

for tool in bun cargo diff grep; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

# The core hands the plugin a minimal environment and keeps only PATH from its
# own. `tar` has to be reachable through it: the plugin spawns it.
PATH="$(dirname "$(command -v bun)"):$PATH"
export PATH

step "Building shieldbk"
cargo build --manifest-path "$ROOT/Cargo.toml" -p sb-cli
SHIELDBK="$ROOT/target/debug/shieldbk"

step "Building the plugin's single-file executable"
# The lockfile hashes the file it points at and nothing else, so what gets
# installed must be one self-contained executable, not a script plus node_modules.
(cd "$HERE" && bun install --frozen-lockfile && bun run build)

step "Preparing a throwaway world under run/"
rm -rf "$RUN"
mkdir -p "$RUN/plugins" "$RUN/storage" "$RUN/data"
cp "$HERE/sb-plugin-folder" "$RUN/plugins/sb-plugin-folder"

# The data to back up: a megabyte of noise, so that nothing can pass the
# comparison by accident, plus files with awkward names (no shell is involved).
head -c 1048576 /dev/urandom > "$RUN/data/blob.bin"
printf 'the quick brown fox\n' > "$RUN/data/notes.txt"
mkdir -p "$RUN/data/sub dir"
printf 'x\n' > "$RUN/data/sub dir/a name; with \$(odd) chars.txt"

step "Starting a fake Telegram on a loopback port"
bun "$HERE/fake-telegram.ts" "$RUN/fake.port" "$RUN/fake.jsonl" &
FAKE_PID=$!
trap 'kill "$FAKE_PID" 2>/dev/null || true' EXIT
for _ in $(seq 100); do [ -s "$RUN/fake.port" ] && break; sleep 0.1; done
[ -s "$RUN/fake.port" ] || fail "the fake Telegram did not start"
PORT="$(cat "$RUN/fake.port")"
echo "fake Telegram: http://127.0.0.1:$PORT"
: > "$RUN/fake.jsonl"

# A made-up token. It only ever lives in this variable: the configuration file
# holds a reference to it, never the value.
export TELEGRAM_BOT_TOKEN="123456789:AAE-try-it-not-a-real-token"

step "Generating an age key"
"$SHIELDBK" keygen --output "$RUN/key.age" >/dev/null
RECIPIENT="$(sed -n 's/^# public key: //p' "$RUN/key.age")"
echo "recipient: $RECIPIENT"

step "Writing the configuration"
cat > "$RUN/config.toml" <<TOML
[plugins]
dir      = "$RUN/plugins"
lockfile = "$RUN/plugins.lock"

# One plugin, three roles: the same binary is started once for the source,
# once for the storage and once for the notifier, each with its own table.
[[target]]
name      = "docs"
source    = "folder"
storage   = "folder"
recipient = "$RECIPIENT"

[target.source_config]
path = "$RUN/data"

[target.storage_config]
dir = "$RUN/storage"

[[notify]]
plugin = "folder"
on     = "always"

[notify.config]
# A reference, not a value: bot_token is a secret field, so the core refuses a
# literal here and resolves this itself.
bot_token = { env = "TELEGRAM_BOT_TOKEN" }
chat_id   = "12345"
# Plain http is accepted only because this is loopback.
api_base  = "http://127.0.0.1:$PORT"
TOML
cat "$RUN/config.toml"

# Everything shieldbk prints, on either stream, is also appended to
# output.log, which is searched for the token at the end. The last stdout is
# kept apart in last.stdout, for the commands whose JSON is read.
# `HOME` is redirected so that nothing lands in the real one.
shieldbk() {
  local rc=0
  HOME="$RUN" "$SHIELDBK" --config "$RUN/config.toml" "$@" \
    >"$RUN/last.stdout" 2>"$RUN/last.stderr" || rc=$?
  cat "$RUN/last.stdout"
  cat "$RUN/last.stderr" >&2
  cat "$RUN/last.stdout" "$RUN/last.stderr" >> "$RUN/output.log"
  return "$rc"
}

step "Registering the plugin binary (shieldbk runs nothing it has not locked)"
shieldbk plugin lock

step "What the plugin says it accepts: shieldbk plugin docs folder"
shieldbk plugin docs folder

step "Diagnosis: shieldbk doctor (sends no message)"
shieldbk doctor

step "Backup"
shieldbk --format json backup
KEY="$(bun -e 'console.log(JSON.parse(await Bun.stdin.text()).targets[0].artifact_key)' < "$RUN/last.stdout")"
echo "artifact: $KEY"

step "Checking that the fake Telegram was told"
bun -e '
  const [file, token] = process.argv.slice(1);
  const seen = (await Bun.file(file).text()).trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const hit = seen.find((m) => m.body?.text === "✅ shieldbk backup: ok");
  if (!hit) { console.error("no ok message for the backup; the fake saw:", JSON.stringify(seen)); process.exit(1); }
  if (hit.path !== `/bot${token}/sendMessage`) { console.error("unexpected path", hit.path); process.exit(1); }
  if (hit.body.chat_id !== "12345") { console.error("unexpected chat_id", hit.body.chat_id); process.exit(1); }
  console.log("received:", JSON.stringify(hit.body));
' "$RUN/fake.jsonl" "$TELEGRAM_BOT_TOKEN" || fail "the notification did not arrive as expected"

step "Checking the artifact against its manifest: shieldbk verify docs"
shieldbk verify docs

step "Restore into the original place, after moving the original aside"
mv "$RUN/data" "$RUN/data.orig"
shieldbk restore docs "$KEY" --identity "$RUN/key.age"

step "Comparing the restored folder with the original"
diff -r "$RUN/data.orig" "$RUN/data"

step "Checking that the bot token appears nowhere in shieldbk's output"
if grep -qF "$TELEGRAM_BOT_TOKEN" "$RUN/output.log"; then
  fail "the bot token leaked into shieldbk's output (see run/output.log)"
fi
echo "not found in $(wc -l < "$RUN/output.log") lines of output"

printf '\n\033[1;32mThe whole cycle worked through one plugin: backed up, stored, notified, restored byte for byte.\033[0m\n'
