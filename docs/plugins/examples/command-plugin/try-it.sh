#!/usr/bin/env bash
#
# Runs a real backup and a real restore through this plugin, and checks that
# what comes back is byte for byte what went in.
#
# It builds `shieldbk` and the mock storage plugin, installs both plugins into a
# throwaway directory under `run/`, generates an age key, writes a configuration
# that backs up a directory with `tar`, and then compares the restored tree
# against the original. Nothing is written outside `run/`.
#
#     ./try-it.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
RUN="$HERE/run"

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

for tool in bun cargo tar diff sha256sum; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

# The core hands the plugin a minimal environment and keeps only PATH from its
# own. `bun` has to be reachable through it or the plugin's shebang fails.
PATH="$(dirname "$(command -v bun)"):$PATH"
export PATH

step "Building shieldbk and the mock storage plugin"
cargo build --manifest-path "$ROOT/Cargo.toml" -p sb-cli -p sb-plugin-mock
SHIELDBK="$ROOT/target/debug/shieldbk"

step "Installing this plugin's dependencies"
(cd "$HERE" && bun install --frozen-lockfile)

step "Preparing a throwaway world under run/"
rm -rf "$RUN"
mkdir -p "$RUN/plugins" "$RUN/storage" "$RUN/source" "$RUN/restored"

cp "$ROOT/target/debug/sb-plugin-mock" "$RUN/plugins/sb-plugin-mock"
# A symlink is enough: Bun resolves the script's real path, so `node_modules`
# and `plugin.proto` are still found next to the original file.
ln -s "$HERE/sb-plugin-command" "$RUN/plugins/sb-plugin-command"

# The data to back up: a megabyte of noise, so that nothing can pass the
# comparison by accident, plus an ordinary text file.
head -c 1048576 /dev/urandom > "$RUN/source/blob.bin"
printf 'the quick brown fox\n' > "$RUN/source/notes.txt"

step "Generating an age key"
# `shieldbk` has no `keygen` command, and `age-keygen` may not be installed:
# this writes an X25519 identity in age's own format so the example can run on
# its own. A real installation uses `age-keygen -o key.age`.
cat > "$RUN/keygen.js" <<'KEYGEN'
import { generateKeyPairSync } from "node:crypto";

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const polymod = (values) => {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk;
};
const expand = (hrp) => [
  ...[...hrp].map((c) => c.charCodeAt(0) >>> 5),
  0,
  ...[...hrp].map((c) => c.charCodeAt(0) & 31),
];
const to5bit = (bytes) => {
  const out = [];
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out.push((acc >>> bits) & 31);
    }
  }
  if (bits > 0) out.push((acc << (5 - bits)) & 31);
  return out;
};
const bech32 = (hrp, bytes) => {
  const data = to5bit(bytes);
  const checksum = polymod([...expand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ 1;
  const tail = [0, 1, 2, 3, 4, 5].map((i) => (checksum >>> (5 * (5 - i))) & 31);
  return hrp + "1" + [...data, ...tail].map((d) => CHARSET[d]).join("");
};

const { publicKey, privateKey } = generateKeyPairSync("x25519");
// The raw 32 bytes sit at the end of both DER encodings.
const pub = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
const sec = privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32);

const recipient = bech32("age", pub);
const identity = bech32("age-secret-key-", sec).toUpperCase();
await Bun.write(process.argv[2], `# public key: ${recipient}\n${identity}\n`);
console.log(recipient);
KEYGEN
RECIPIENT="$(bun "$RUN/keygen.js" "$RUN/key.age")"
chmod 600 "$RUN/key.age"
rm "$RUN/keygen.js"
echo "recipient: $RECIPIENT"

step "Writing the configuration"
cat > "$RUN/config.toml" <<TOML
[plugins]
dir      = "$RUN/plugins"
lockfile = "$RUN/plugins.lock"

[[target]]
name      = "app"
source    = "command"
storage   = "mock"
recipient = "$RECIPIENT"

# The command is a list, never a string: there is no shell in between, so
# nothing here can be turned into an injection.
[target.source_config]
dump    = ["tar", "-C", "$RUN/source", "-cf", "-", "."]
restore = ["tar", "-C", "$RUN/restored", "-xf", "-"]
timeout = "5m"

[target.storage_config]
dir = "$RUN/storage"
TOML
cat "$RUN/config.toml"

# `HOME` is redirected so that nothing lands in the real one.
shieldbk() { HOME="$RUN" "$SHIELDBK" --config "$RUN/config.toml" "$@"; }

step "Registering the plugin binaries (shieldbk runs nothing it has not locked)"
shieldbk plugin lock

step "What the plugin says it accepts: shieldbk plugin docs command"
shieldbk plugin docs command

step "Diagnosis: shieldbk doctor"
shieldbk doctor

step "Backup"
KEY="$(shieldbk --format json backup |
  bun -e 'console.log(JSON.parse(await Bun.stdin.text()).targets[0].artifact_key)')"
echo "artifact: $KEY"

step "Checking the artifact against its manifest: shieldbk verify app"
shieldbk verify app

step "Restore"
shieldbk restore app "$KEY" --identity "$RUN/key.age"

step "Comparing the restored tree with the original"
diff -r "$RUN/source" "$RUN/restored"
( cd "$RUN/source"   && find . -type f | sort | xargs sha256sum ) > "$RUN/before.sha"
( cd "$RUN/restored" && find . -type f | sort | xargs sha256sum ) > "$RUN/after.sha"
diff "$RUN/before.sha" "$RUN/after.sha"
cat "$RUN/after.sha"

printf '\n\033[1;32mThe full cycle worked: what was restored is byte for byte what was backed up.\033[0m\n'
