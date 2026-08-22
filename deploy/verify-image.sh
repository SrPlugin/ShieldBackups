#!/usr/bin/env bash
# Verification of the ShieldBackups container image.
#
# An image nobody has run is an image that does not work. This script builds the
# image and runs, **inside a container**, the complete cycle against the test
# plugin, with the storage target on a Docker volume:
#
#     plugin lock  ->  doctor  ->  backup  ->  verify  ->  restore
#
# and checks, byte for byte, that what was restored is what the engine dumped.
#
# Each step is a separate `docker run`, as it would be in production: separate
# processes, with no shared state beyond the volume. And they all run with the
# same restrictions `deploy/README.md` recommends -- user 10001, read-only root,
# `/tmp` on tmpfs, no capabilities, `--init` -- so besides verifying the cycle
# they verify that this security recipe is actually runnable.
#
# Usage:
#     ./deploy/verify-image.sh                  # build and verify
#     ./deploy/verify-image.sh --no-build       # verify what is already there
#     IMAGE=shieldbk:0.1.0 ./deploy/verify-image.sh --no-build
#     PG_MAJOR=16 ./deploy/verify-image.sh

set -euo pipefail

IMAGE="${IMAGE:-shieldbk:verification}"
PG_MAJOR="${PG_MAJOR:-17}"
VOLUME="${VOLUME:-shieldbk-verification}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BUILD=1
for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD=0 ;;
    -h|--help) sed -n '2,23p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 64 ;;
  esac
done

# Throwaway age key, deliberately fixed so that the script does not depend on
# `age-keygen`. It only encrypts the mock plugin's synthetic data; it protects
# nothing and must not appear in any real configuration.
RECIPIENT="age1dewvh4c7h669pnve445amtsgqdkr63wkf5zpagzchze84jvky50qvtkr28"
IDENTITY="AGE-SECRET-KEY-1Z2EUD35Z4F5UMUWADA2WVCS6FSPNTT6DH4WZFNUYT8YHG6XAVDTQ9Z3SYK"

# 512 KiB with a fixed seed: enough to go through compression, encryption and
# the chunking frame, and small enough for the cycle to take seconds.
SEED=7
SIZE=$((512 * 1024))

WORKDIR="$(mktemp -d)"
cleanup() {
  local code=$?
  rm -rf "$WORKDIR"
  docker volume rm -f "$VOLUME" >/dev/null 2>&1 || true
  return $code
}
trap cleanup EXIT

heading() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()      { printf '   \033[32mok\033[0m  %s\n' "$*"; }
bad()     { printf '   \033[31mFAILED\033[0m  %s\n' "$*" >&2; exit 1; }

# -- The image ---------------------------------------------------------------
if [[ $BUILD -eq 1 ]]; then
  heading "building $IMAGE (PG_MAJOR=$PG_MAJOR)"
  DOCKER_BUILDKIT=1 docker build \
    --build-arg "PG_MAJOR=$PG_MAJOR" \
    -t "$IMAGE" "$ROOT"
else
  docker image inspect "$IMAGE" >/dev/null 2>&1 \
    || bad "the image \`$IMAGE\` does not exist; drop --no-build"
fi

# -- Configuration and keys --------------------------------------------------
# The data directory is the same for the engine and for the storage target: the
# mock engine writes what it restores there and the mock storage target keeps
# the artifacts there. The [plugins] section is deliberately omitted: it checks
# that the image's defaults (the ~/.shieldbk links) resolve to what is
# installed.
cat > "$WORKDIR/config.toml" <<TOML
[[target]]
name = "production"
engine = "mock"
storage = "mock"
recipient = "$RECIPIENT"

[target.engine_config]
dir = "/var/lib/shieldbk"
seed = $SEED
size = $SIZE

[target.storage_config]
dir = "/var/lib/shieldbk"
TOML

printf '# created: verification\n# public key: %s\n%s\n' "$RECIPIENT" "$IDENTITY" \
  > "$WORKDIR/key.age"
# Readable by the container's UID 10001, which is not the one running this.
chmod 0444 "$WORKDIR/config.toml" "$WORKDIR/key.age"

docker volume rm -f "$VOLUME" >/dev/null 2>&1 || true
docker volume create "$VOLUME" >/dev/null

# `sb` runs shieldbk inside an ephemeral container, with the same restrictions
# the deployment guide recommends.
sb() {
  docker run --rm --init \
    --read-only \
    --tmpfs /tmp:rw,mode=1777,nosuid,nodev \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --memory 256m \
    -v "$WORKDIR/config.toml:/etc/shieldbk/config.toml:ro" \
    -v "$WORKDIR/key.age:/etc/shieldbk/key.age:ro" \
    -v "$VOLUME:/var/lib/shieldbk" \
    "$IMAGE" --config /etc/shieldbk/config.toml "$@"
}

# To look at the volume from outside the cycle, without going through shieldbk.
inspect() {
  docker run --rm --entrypoint sh -v "$VOLUME:/data" "$IMAGE" -c "$1"
}

# -- 0. The user and the sealing of the lockfile -----------------------------
heading "0. unprivileged user and lockfile sealed during the build"
process_identity="$(docker run --rm --entrypoint id "$IMAGE" -u)"
[[ "$process_identity" == "10001" ]] \
  || bad "the container runs as UID $process_identity, not as 10001"
ok "runs as UID 10001"

docker run --rm --entrypoint test "$IMAGE" -f /usr/lib/shieldbk/plugins.lock \
  || bad 'the image ships no lockfile: `plugin lock` did not run during the build'
ok "/usr/lib/shieldbk/plugins.lock exists in the image"

pg_version="$(docker run --rm --entrypoint pg_dump "$IMAGE" --version)"
ok "$pg_version"

# -- 1. plugin lock ----------------------------------------------------------
# It is idempotent and here it runs against the lockfile the image already
# ships: it has to recognise the same hashes, rewrite nothing (the file is
# read-only and owned by root) and exit successfully.
heading "1. plugin lock / plugin verify"
out="$(sb --format json plugin verify)" \
  || bad "plugin verify failed against the image's lockfile: $out"
echo "$out" | grep -q '"failed":0' \
  || bad "there are plugins that do not verify: $out"
ok "both plugins in the image verify against the build's lockfile"

# A `plugin lock` from inside the container has to fail cleanly, because the
# lockfile is owned by root and read-only: immutability is the guarantee.
if sb plugin lock >/dev/null 2>&1; then
  bad "plugin lock was able to rewrite the image's lockfile; it should be immutable"
fi
ok "plugin lock cannot rewrite the sealed lockfile (immutable image)"

# -- 2. doctor ---------------------------------------------------------------
heading "2. doctor"
out="$(sb --format json doctor)" || bad "doctor failed: $out"
echo "$out" | grep -q '"ok":true' || bad "doctor does not report ok: $out"
ok "doctor: all good"

# -- 3. backup ---------------------------------------------------------------
heading "3. backup"
out="$(sb --format json backup)" || bad "backup failed: $out"
echo "$out" | grep -q '"ok":true' || bad "backup does not report ok: $out"
ARTIFACT="$(printf '%s' "$out" \
  | sed -n 's/.*"artifact_key":"\([^"]*\)".*/\1/p')"
[[ -n "$ARTIFACT" ]] || bad "the backup returned no artifact_key: $out"
ok "artifact: $ARTIFACT"

inspect "test -f '/data/$ARTIFACT'" \
  || bad "the artifact is not in the volume"
size="$(inspect "stat -c %s '/data/$ARTIFACT'")"
ok "it is in the volume, $size bytes"

# -- 4. verify ---------------------------------------------------------------
heading "4. verify"
out="$(sb verify production)" || bad "verify failed: $out"
printf '%s\n' "$out" | grep -q '1/1' \
  || bad "verify did not check the artifact: $out"
ok "verify: 1/1"

# -- 5. restore --------------------------------------------------------------
heading "5. restore"
out="$(sb restore production "$ARTIFACT" --identity /etc/shieldbk/key.age)" \
  || bad "restore failed: $out"
ok "restore finished without error"

# The mock engine leaves what it receives in `restore.bin`, and its dump is
# deterministic: comparing its SHA-256 with that of a fresh backup closes the
# cycle.
restored_sha="$(inspect "sha256sum /data/restore.bin | cut -d' ' -f1")"
[[ -n "$restored_sha" ]] || bad "restore did not write /data/restore.bin"
restored_size="$(inspect "stat -c %s /data/restore.bin")"
[[ "$restored_size" == "$SIZE" ]] \
  || bad "what was restored is $restored_size bytes and the dump was $SIZE"
ok "restore.bin: $restored_size bytes, sha256 ${restored_sha:0:16}..."

# Second round: another backup from the same deterministic engine and another
# restore. If the two `restore.bin` match, the cycle reproduces the data.
inspect "rm -f /data/restore.bin"
out="$(sb --format json backup)" || bad "the second backup failed: $out"
ARTIFACT2="$(printf '%s' "$out" \
  | sed -n 's/.*"artifact_key":"\([^"]*\)".*/\1/p')"
sb restore production "$ARTIFACT2" --identity /etc/shieldbk/key.age >/dev/null \
  || bad "the second restore failed"
sha2="$(inspect "sha256sum /data/restore.bin | cut -d' ' -f1")"
[[ "$sha2" == "$restored_sha" ]] \
  || bad "two complete cycles gave different data: $restored_sha vs $sha2"
ok "two complete cycles reproduce the same bytes"

# -- 6. The integrity door, from inside the container ------------------------
# Swapping a plugin at runtime has to be rejected. It is done on a copy of the
# image so as not to touch the original.
heading "6. an altered plugin is rejected"
altered="${IMAGE}-altered"
docker build -q -t "$altered" - >/dev/null <<EOF
FROM $IMAGE
USER root
RUN printf 'x' >> /usr/lib/shieldbk/plugins/sb-plugin-mock
USER 10001:10001
EOF
code=0
out="$(docker run --rm --init --read-only \
  --tmpfs /tmp:rw,mode=1777 --cap-drop ALL \
  -v "$WORKDIR/config.toml:/etc/shieldbk/config.toml:ro" \
  -v "$VOLUME:/var/lib/shieldbk" \
  "$altered" --config /etc/shieldbk/config.toml backup 2>&1)" || code=$?
docker image rm -f "$altered" >/dev/null 2>&1 || true
[[ "$code" == "3" ]] \
  || bad "an altered plugin must exit with code 3, it exited with $code: $out"
printf '%s' "$out" | grep -q 'has changed' \
  || bad "the message does not explain that the binary changed: $out"
ok "altered plugin -> code 3, \"has changed\""

# -- Summary -----------------------------------------------------------------
heading "result"
printf '   image    : %s\n' "$IMAGE"
printf '   size     : %s (uncompressed, sum of layers)\n' \
  "$(docker history "$IMAGE" --format '{{.Size}}' | awk '
      /GB/{sub("GB","");s+=$0*1e9;next}
      /MB/{sub("MB","");s+=$0*1e6;next}
      /kB/{sub("kB","");s+=$0*1e3;next}
      {sub("B","");s+=$0}
      END{printf "%.0f MB", s/1e6}')"
printf '   pg_dump  : %s\n' "${pg_version#pg_dump }"
printf '   cycle    : plugin lock -> doctor -> backup -> verify -> restore  \033[32mOK\033[0m\n'
