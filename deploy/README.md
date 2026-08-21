# Running ShieldBackups in a container

`shieldbk` is a one-shot program: it starts, takes a backup, and exits with a
status code. It has no daemon, no scheduler and no state of its own. That makes
it a natural fit for a Kubernetes `CronJob`, a systemd timer, or a plain
`docker run` from cron.

Two properties matter for sizing and for how you wire it up:

* **Memory is constant in the size of the database.** A 2 GiB backup uses about
  30 MiB of RSS across the core process and its plugins. Eight times the data
  costs 1.02x the memory. Nothing is buffered end to end; the dump is streamed
  through compression and encryption straight into the object store.
* **Plugins are separate processes, and they are hash-verified before they are
  executed.** `shieldbk` refuses to run a plugin binary whose SHA-256 does not
  match the lockfile, because a plugin is handed your database and storage
  credentials. Inside the image this is already done for you — see
  [The lockfile is sealed at build time](#the-lockfile-is-sealed-at-build-time).

---

## Table of contents

- [Building the image](#building-the-image)
- [What is inside](#what-is-inside)
- [The lockfile is sealed at build time](#the-lockfile-is-sealed-at-build-time)
- [Quick start with `docker run`](#quick-start-with-docker-run)
- [Docker Compose](#docker-compose)
- [Kubernetes `CronJob`](#kubernetes-cronjob)
- [Four things that will bite you](#four-things-that-will-bite-you)
  - [1. Mounted secrets are world-readable by default](#1-mounted-secrets-are-world-readable-by-default)
  - [2. Zombie processes when `shieldbk` is PID 1](#2-zombie-processes-when-shieldbk-is-pid-1)
  - [3. `pg_dump` must be at least as new as the server](#3-pg_dump-must-be-at-least-as-new-as-the-server)
  - [4. The keyring secret provider does not work in a container](#4-the-keyring-secret-provider-does-not-work-in-a-container)
- [Sizing: how much memory and CPU to give it](#sizing-how-much-memory-and-cpu-to-give-it)
- [Exit codes and alerting](#exit-codes-and-alerting)
- [Verifying the image](#verifying-the-image)

---

## Building the image

```bash
# Default: PostgreSQL client 17.
docker build -t shieldbk:0.1.0 .

# Pick the pg_dump major version explicitly. See section 3 below — this is not
# a cosmetic choice.
docker build --build-arg PG_MAJOR=16 -t shieldbk:0.1.0-pg16 .
```

Build arguments:

| Argument        | Default    | Purpose |
|-----------------|------------|---------|
| `PG_MAJOR`      | `17`       | Major version of `postgresql-client` installed. Valid: `13`–`18` (whatever the PGDG repository carries). |
| `RUST_VERSION`  | `1.92`     | Pinned by `rust-toolchain.toml`. Change both together. |
| `DEBIAN_SUITE`  | `bookworm` | Base suite for both the builder and the runtime stage. |

Tag your images with the client version you built (`shieldbk:0.1.0-pg16`).
"Which `pg_dump` is in there" is the single most common cause of a silently
broken backup, and the tag is the cheapest place to record the answer.

### Why `debian:bookworm-slim` and not distroless or Alpine

The image has to carry `pg_dump`, and its major version has to be selectable.
That one requirement decides the base:

* **distroless** has no package manager. Shipping a PostgreSQL client means
  hand-copying `pg_dump` plus its whole library closure — libpq, OpenSSL, LDAP,
  SASL, GSSAPI, Kerberos, com_err, keyutils, zlib, lz4, zstd. That closure
  changes with every PostgreSQL major and every Debian point release, and when
  it breaks it breaks in production, not in CI.
* **Alpine + musl** does have `postgresql*-client`, but *the available major is
  pinned by the Alpine release*: choosing PostgreSQL 15 would mean freezing
  Alpine 3.18 forever. That is exactly the degree of freedom we need. On top of
  that, `aws-lc-sys` (pulled in by rustls through the S3 SDK) and `ring` are
  awkward to build against musl, and musl's allocator behaves poorly under the
  multi-threaded, allocate-and-free pattern of the R2 multipart uploader.
* **`debian:bookworm-slim` + the official PGDG apt repository** gives
  `postgresql-client-13` through `-18` on a stable, security-patched base.

For the same reason the binaries are **not** statically linked: a static build
buys nothing when the image needs a package manager and a dynamically linked
`pg_dump` anyway.

Final image size with `PG_MAJOR=17`: **≈ 190 MB uncompressed**, **≈ 61 MB
compressed** (what an image pull actually transfers). Where it goes:

| Layer | Size |
|---|---|
| `debian:bookworm-slim` base | 85 MB |
| `postgresql-client-17` + `ca-certificates` | 73 MB |
| `shieldbk` (stripped) | 12 MB |
| `sb-plugin-r2` (stripped) | 15 MB |
| `sb-plugin-mock` (stripped) | 5.4 MB |

Two thirds of the image is the PostgreSQL client and the Debian base — the
price of being able to choose the `pg_dump` version. Dropping
`sb-plugin-mock` from a production image saves 5.4 MB; it is kept here because
it is what `deploy/verificar-imagen.sh` exercises.

## What is inside

| Path | Contents |
|------|----------|
| `/usr/local/bin/shieldbk` | The CLI. It is the image `ENTRYPOINT`. |
| `/usr/lib/shieldbk/plugins/` | `sb-plugin-r2`, `sb-plugin-mock`. Owned by root, mode `0555`. |
| `/usr/lib/shieldbk/plugins.lock` | Generated during the build. Mode `0444`, root-owned. |
| `/etc/shieldbk/config.toml` | **Not shipped.** Mount your configuration here. |
| `/home/shieldbk/.shieldbk/` | Symlinks to the three paths above, so `shieldbk`'s built-in defaults resolve without you repeating them in the config. |
| `/usr/bin/pg_dump` | From `postgresql-client-$PG_MAJOR`. |

The container runs as **UID/GID 10001** (`shieldbk`), a system user with no
shell. `HOME` is `/home/shieldbk`.

Because `/home/shieldbk/.shieldbk/config.toml` is a symlink to
`/etc/shieldbk/config.toml`, mounting your configuration at
`/etc/shieldbk/config.toml` is enough — no `--config` flag needed. The examples
below pass `--config` anyway, because being explicit in a scheduled job that
runs unattended at 3 a.m. is worth four extra words.

A minimal configuration:

```toml
# The [plugins] section is optional inside this image: the defaults already
# point at /usr/lib/shieldbk/plugins and /usr/lib/shieldbk/plugins.lock.
# Set it only if you mount your own plugin directory.
# [plugins]
# dir = "/usr/lib/shieldbk/plugins"
# lockfile = "/usr/lib/shieldbk/plugins.lock"

[[target]]
name = "produccion"
engine = "postgres"
storage = "r2"
recipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

[target.engine_config]
host = "db.internal"
port = 5432
database = "app"
user = "backup"
# Secret fields never take a literal value. See section 1.
password = { file = "/run/secrets/db_password" }

[target.storage_config]
account_id = "0123456789abcdef0123456789abcdef"
bucket = "backups"
access_key_id = { env = "R2_ACCESS_KEY_ID" }
secret_access_key = { file = "/run/secrets/r2_secret" }
```

The five secret providers are `{ env = "VAR" }`, `{ file = "/path" }`,
`{ file_insecure = "/path" }`, `{ keyring = "service/user" }` and
`{ command = ["prog", "arg"] }`. In a container you will use `env` or `file` —
see section 4.

## The lockfile is sealed at build time

`shieldbk plugin lock` runs **inside the `docker build`**, immediately after the
freshly compiled plugin binaries are copied into the image.

Outside a container the hash check is an installation chore: somebody has to
remember to run `plugin lock`, and to re-run it after every plugin upgrade. It
is the kind of step that gets skipped, and a skipped `plugin lock` means the
first `backup` fails with exit code 3 at 3 a.m.

Inside the image the relationship inverts, and **the container strengthens the
guarantee instead of getting in its way**:

* The image is immutable, so hash and binary are pinned together and travel
  under the image digest. There is no window in which they can drift.
* Verification is real from the very first run, with nobody having to remember
  anything.
* A plugin swapped at runtime — a volume mounted over `/usr/lib/shieldbk/plugins`,
  a `docker cp` into a running container, a compromised sidecar — is detected
  and rejected before it is ever executed, and before it is handed a single
  credential.

The build also runs `shieldbk plugin verify` right after, so a build that
produced an unusable lockfile fails at build time rather than in production.

If you mount your own plugin directory, you own the lockfile too: run
`shieldbk plugin lock` yourself against that directory and mount the resulting
lockfile read-only.

## Quick start with `docker run`

```bash
docker run --rm --init \
  --read-only \
  --tmpfs /tmp:rw,mode=1777,nosuid,nodev \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 256m --cpus 1 \
  -v "$PWD/config.toml:/etc/shieldbk/config.toml:ro" \
  -v "$PWD/secrets:/run/secrets:ro" \
  -e R2_ACCESS_KEY_ID \
  shieldbk:0.1.0 \
  --config /etc/shieldbk/config.toml backup
```

Note `--init` and the writable `/tmp`. Both are explained below.

Check the setup before you schedule it:

```bash
docker run --rm --init -v "$PWD/config.toml:/etc/shieldbk/config.toml:ro" \
  shieldbk:0.1.0 --config /etc/shieldbk/config.toml --format json doctor
```

## Docker Compose

`shieldbk` exits when it is done, so it is a `restart: "no"` one-shot service.
Compose has no scheduler; drive it from cron or systemd with
`docker compose run --rm backup`.

```yaml
services:
  backup:
    image: shieldbk:0.1.0
    # Reaps orphaned children if shieldbk ends up as PID 1. See section 2.
    init: true
    restart: "no"
    read_only: true
    tmpfs:
      - /tmp:mode=1777,nosuid,nodev
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    user: "10001:10001"
    mem_limit: 256m
    cpus: 1.0
    environment:
      R2_ACCESS_KEY_ID: ${R2_ACCESS_KEY_ID:?set R2_ACCESS_KEY_ID}
      TZ: Europe/Madrid
    volumes:
      - ./config.toml:/etc/shieldbk/config.toml:ro
    secrets:
      - db_password
      - r2_secret
    command: ["--config", "/etc/shieldbk/config.toml", "backup"]

secrets:
  db_password:
    file: ./secrets/db_password
  r2_secret:
    file: ./secrets/r2_secret
```

**Compose secrets land in `/run/secrets/<name>` with mode `0444`, which
`shieldbk` rejects.** Compose gives you `uid`/`gid`/`mode` on the *secret
reference* to fix that:

```yaml
    secrets:
      - source: db_password
        target: db_password
        uid: "10001"
        gid: "10001"
        mode: 0400
```

If your Compose version ignores those keys (support has been uneven for
file-backed secrets outside Swarm), use `{ file_insecure = "..." }` in the
configuration instead, and accept the warning it prints.

## Kubernetes `CronJob`

Complete and applyable. Adjust the image, the schedule and the secret names.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: shieldbk-config
data:
  config.toml: |
    [[target]]
    name = "produccion"
    engine = "postgres"
    storage = "r2"
    recipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

    [target.engine_config]
    host = "postgres.default.svc.cluster.local"
    port = 5432
    database = "app"
    user = "backup"
    password = { file = "/run/secrets/shieldbk/db_password" }

    [target.storage_config]
    account_id = "0123456789abcdef0123456789abcdef"
    bucket = "backups"
    access_key_id = { file = "/run/secrets/shieldbk/r2_access_key_id" }
    secret_access_key = { file = "/run/secrets/shieldbk/r2_secret_access_key" }
---
apiVersion: v1
kind: Secret
metadata:
  name: shieldbk-secrets
type: Opaque
stringData:
  db_password: "change-me"
  r2_access_key_id: "change-me"
  r2_secret_access_key: "change-me"
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: shieldbk-produccion
spec:
  schedule: "17 3 * * *"
  timeZone: "Europe/Madrid"
  concurrencyPolicy: Forbid          # a backup must never race itself
  startingDeadlineSeconds: 3600
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 7          # keep failures around long enough to read
  jobTemplate:
    spec:
      backoffLimit: 2
      activeDeadlineSeconds: 10800   # 3 h; a hung backup should fail, not hang
      ttlSecondsAfterFinished: 604800
      template:
        metadata:
          labels:
            app.kubernetes.io/name: shieldbk
        spec:
          restartPolicy: Never
          # Safety net for orphaned plugin processes; see section 2.
          shareProcessNamespace: true
          automountServiceAccountToken: false
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            runAsGroup: 10001
            fsGroup: 10001
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: shieldbk
              image: shieldbk:0.1.0-pg16     # major must be >= the server's
              imagePullPolicy: IfNotPresent
              args:
                - "--config"
                - "/etc/shieldbk/config.toml"
                - "backup"
              securityContext:
                allowPrivilegeEscalation: false
                readOnlyRootFilesystem: true
                privileged: false
                capabilities:
                  drop: ["ALL"]
              env:
                - name: TZ
                  value: "Europe/Madrid"
              resources:
                requests:
                  cpu: "250m"
                  memory: "128Mi"
                limits:
                  # 30 MiB base + 256 MiB for the R2 multipart uploader,
                  # rounded up. See "Sizing" below before you lower this.
                  cpu: "2"
                  memory: "512Mi"
              volumeMounts:
                - name: config
                  mountPath: /etc/shieldbk
                  readOnly: true
                - name: secrets
                  mountPath: /run/secrets/shieldbk
                  readOnly: true
                # readOnlyRootFilesystem is on, and shieldbk needs a writable
                # temp dir for its plugin control sockets. This is mandatory.
                - name: tmp
                  mountPath: /tmp
          volumes:
            - name: config
              configMap:
                name: shieldbk-config
            - name: secrets
              secret:
                secretName: shieldbk-secrets
                # THE IMPORTANT LINE. Without it Kubernetes mounts these files
                # 0644 and shieldbk refuses to read them. See section 1.
                defaultMode: 0400
            - name: tmp
              emptyDir:
                medium: Memory
                sizeLimit: 64Mi
```

Two lines in there are load-bearing and easy to drop when someone trims the
manifest: `defaultMode: 0400` on the secret volume, and the `tmp` `emptyDir`.
Without the first, every run fails with exit code 2. Without the second, every
run fails as soon as it tries to start a plugin.

---

## Four things that will bite you

### 1. Mounted secrets are world-readable by default

`shieldbk` refuses to read a `{ file = "..." }` secret if **any** group or
other permission bit is set (`0o077`). `0600`, `0400` and `0700` pass; `0640`,
`0644` and `0444` do not. The error is explicit:

```
el archivo de secreto «/run/secrets/db_password» tiene permisos 0444 y es
accesible para el grupo o para otros; corrígelo con «chmod 600
/run/secrets/db_password», o usa `file_insecure` si lo monta un orquestador
```

That check exists because a secrets file readable by every process in the
machine is not a secret. Both orchestrators violate it out of the box:

| Platform | Default mode of a mounted secret |
|----------|----------------------------------|
| Docker / Compose `secrets:` | `0444` |
| Kubernetes `secret` volume  | `0644` |

**Preferred fix — control the mount.** On Kubernetes, `defaultMode: 0400` on
the volume (or `mode: 0400` per item under `items:`). On Compose, `mode: 0400`
plus `uid`/`gid` on the secret reference. This is not a workaround; `0400` is
what a mounted credential should have been all along, and it costs one line.

```yaml
            - name: secrets
              secret:
                secretName: shieldbk-secrets
                defaultMode: 0400
```

Note that `defaultMode` on a Kubernetes secret volume interacts with `fsGroup`:
`fsGroup` sets group *ownership*, it does not add group permission bits, so
`0400` + `runAsUser: 10001` still works only because the projected files are
owned by the running UID. Keep `runAsUser` and `fsGroup` consistent, as in the
manifest above.

**Escape hatch — when you do not control the mount.** Some platforms
(managed CI runners, certain CSI secret drivers, Nomad, older Compose) project
secrets with a fixed mode you cannot change. For those, use
`file_insecure`:

```toml
password = { file_insecure = "/run/secrets/db_password" }
```

It reads the same file and skips the permission check, logging a warning:

```
secreto leído sin comprobar permisos (`file_insecure`); prefiere
`defaultMode: 0400` en el volumen que lo monta
```

It relaxes the permission check and nothing else — a missing or unreadable file
is still a hard error. Use it when the mount is genuinely out of your hands,
not to silence the message.

A third option, when the secret is small and the platform is awkward, is
`{ env = "VAR" }` plus a `secretKeyRef`. Environment variables are visible in
`/proc/self/environ` and in `docker inspect`, so they are a step down from a
`0400` file — but they are a step up from a `0644` one.

### 2. Zombie processes when `shieldbk` is PID 1

Every plugin runs as a child process, in its own process group. On the normal
path `shieldbk` kills the whole group and reaps it, so nothing is left behind —
including when a backup fails or is cancelled.

PID 1 is still a special job. The first process in a PID namespace inherits
every orphaned process in that namespace and is responsible for reaping them;
if it does not, they accumulate as zombies for the lifetime of the container.
`shieldbk` is a one-shot CLI, not an init system: it reaps *its own* children,
it does not adopt and reap arbitrary orphans.

In practice the exposure is small, because the process tree is
`shieldbk → plugin` and nothing daemonises. It becomes real when a plugin
spawns its own helper — `pg_dump` under a future PostgreSQL plugin is exactly
that shape — and is killed abruptly, e.g. by the container's memory limit.

Give yourself the safety net; it is free:

```bash
docker run --init ...          # tini as PID 1, reaps orphans
```

```yaml
services:
  backup:
    init: true
```

```yaml
spec:
  template:
    spec:
      shareProcessNamespace: true   # the pause container becomes PID 1
```

On Kubernetes, `shareProcessNamespace: true` makes the infrastructure
("pause") container PID 1 for the whole pod, and pause is a proper reaper. The
trade-off is that containers in the pod can then see and signal each other's
processes; for a single-container backup job that costs nothing. If your policy
forbids it, an alternative is an explicit `tini`/`dumb-init` entrypoint, or
simply accepting the risk — for a `Job` the pod is torn down when the process
exits, so zombies live at most as long as the run.

### 3. `pg_dump` must be at least as new as the server

**A `pg_dump` older than the server it dumps produces an incomplete dump, and
does not necessarily fail while doing it.** Newer PostgreSQL versions add
catalog objects and syntax that an older client does not know how to
serialise. An image built with `postgresql-client-15` cannot back up a
PostgreSQL 16 server. The rule is one-directional:

| Image `PG_MAJOR` | Server 15 | Server 16 | Server 17 |
|------------------|-----------|-----------|-----------|
| 15               | ok        | **no**    | **no**    |
| 16               | ok        | ok        | **no**    |
| 17               | ok        | ok        | ok        |

Newer clients against older servers are supported and are the safe default.
When in doubt, build with the highest `PG_MAJOR` you have, or match the server
exactly.

Choose the tag deliberately:

```bash
# Find the server's major:
psql -h db.internal -U backup -Atc 'SHOW server_version_num'   # e.g. 160004 -> 16

docker build --build-arg PG_MAJOR=16 -t shieldbk:0.1.0-pg16 .
```

Check what actually shipped in an image:

```bash
docker run --rm --entrypoint pg_dump shieldbk:0.1.0-pg16 --version
# pg_dump (PostgreSQL) 16.x
```

Then **encode the answer in the tag** and in the manifest, so an image bump
cannot silently downgrade the client.

On the `doctor` side, be aware of what exists today: `doctor` reports the
server version as an informational check named `versión de la fuente`, taken
from the engine plugin's preflight response. The automatic comparison against
the local `pg_dump` — a failing check with a remedy — is part of the PostgreSQL
plugin, which is not in this repository yet. Until it lands, the table above
and the tag are your check. Run `doctor` before you schedule anything, and read
the reported server version against the `pg_dump --version` you just printed.

Kubernetes makes it easy to get this wrong when the database is upgraded and
the CronJob is not. Put the client major in a label or annotation on the
CronJob and review it as part of any database upgrade runbook.

### 4. The keyring secret provider does not work in a container

`{ keyring = "service/user" }` talks to the Secret Service API over D-Bus.
A container has no session bus, no `gnome-keyring`/`kwallet` daemon, and no
unlocked login session, so the lookup fails. This is not something to work
around — a per-user desktop credential store has no meaning in a scheduled,
unattended job.

Use `env` or `file` instead:

```toml
# Preferred: a file, mounted 0400.
secret_access_key = { file = "/run/secrets/shieldbk/r2_secret_access_key" }

# Acceptable: an environment variable, from a secretKeyRef or --env-file.
access_key_id = { env = "R2_ACCESS_KEY_ID" }
```

`{ command = [...] }` also works in a container and is the right answer when
you have a real secret broker: it runs an argv (no shell, so no injection) and
takes the first line of stdout. `["vault", "read", "-field=password", "..."]`
is a fine choice — as long as the broker's own credential is itself mounted as
a `0400` file, and the broker binary is in the image.

---

## Sizing: how much memory and CPU to give it

Measured numbers, not guesses:

| Component | Memory |
|---|---|
| Core + one engine plugin + one storage plugin | **≈ 30 MiB RSS**, flat in database size (2 GiB dump: 30 MiB; 8x the data: 1.02x the memory) |
| Each additional concurrent target (`--jobs N`) | **+ ≈ 20 MiB** |
| R2 multipart uploader, per upload in flight | **`part_size_mb` x `concurrency` = 64 MiB x 4 = 256 MiB by default** |

That last row is the one that catches people out. It is **not** included in the
30 MiB figure: those measurements were taken against the mock storage plugin,
which writes each artifact in a single call and never chunks. The R2 plugin
buffers each part in memory while it uploads, and it keeps `concurrency` parts
in flight, so its ceiling is the product of the two. Anyone uploading to R2 has
to add it.

So, for a single target going to R2 with the defaults:

```
30 MiB  (core + plugins)
256 MiB (R2 multipart ceiling)
─────────
286 MiB  ->  request 128Mi, limit 512Mi
```

With `--jobs 3` against R2, all three uploading at once:

```
30 + 2*20 + 3*256 = 838 MiB  ->  limit 1Gi, and consider lowering part_size_mb
```

To trade memory for a lower maximum object size, tune the R2 plugin:

```toml
[target.storage_config]
part_size_mb = 16     # default 64; minimum 5
concurrency = 2       # default 4; range 1..=256
max_object_gb = 160   # default 640
```

`part_size_mb x 10 000` (the S3 part limit) must cover `max_object_gb`, and the
plugin refuses a configuration where it does not, telling you the minimum. With
16 MiB x 2 the uploader ceiling drops to 32 MiB and the whole job fits
comfortably in 128 MiB — at the cost of a 160 GB per-object limit and more
round trips.

**CPU.** zstd compression is the hot path and it is single-threaded per target.
`requests: 250m` is enough to make progress; `limits: "2"` leaves room for the
compressor plus the uploader's TLS without throttling a nightly job into the
morning. Raising `--jobs` raises the useful CPU limit roughly linearly.

**Disk.** None. `shieldbk` streams; it does not stage the dump on local disk.
The only writable directory it needs is a temp dir for the plugin control
sockets — a 64 MiB in-memory `emptyDir` on `/tmp` is generous.

## Exit codes and alerting

```
0   success
2   configuration error   — the TOML, a secret, or an age recipient
3   plugin error          — missing, unregistered, altered, or crashed plugin
4   operation error       — the backup itself failed: database, network, storage
```

These are stable and they are meant to be routed differently, because the
people who fix them are different people:

| Code | What happened | Who should be paged | Retry? |
|---|---|---|---|
| 2 | Someone changed the config, or a secret rotated and the reference is stale | Whoever owns the manifest | **No.** Retrying will fail identically. |
| 3 | A plugin binary is missing or its hash does not match | Platform / security | **No.** A hash mismatch after a hash was sealed at build time means the image was tampered with, or a volume is shadowing the plugin directory. Investigate before rerunning. |
| 4 | The database was unreachable, the dump failed, the upload failed | On-call | **Yes**, with backoff. This is the transient class. |

`backoffLimit: 2` in the manifest above retries everything twice, which is the
right default for 4 and merely noisy for 2 and 3. If you want to stop retrying
non-transient failures, wrap the command:

```yaml
              command: ["/bin/sh", "-c"]
              args:
                - |
                  shieldbk --config /etc/shieldbk/config.toml backup
                  code=$?
                  case $code in
                    0) exit 0 ;;
                    2|3) echo "non-transient failure ($code), not retrying" >&2
                         exit 0 ;;   # Job succeeds; alert on the log instead
                    *) exit $code ;;
                  esac
```

(Exiting 0 to defeat `backoffLimit` means the `Job` reports success, so you
must alert on the log line. Only do this if your alerting reads logs.)

For machine-readable output, `--format json` prints a single JSON object on
stdout. Logs go to stderr, so the two never mix even with `-vv`. On success:

```json
{"ok":true,"targets":[{"name":"produccion","artifact_key":"produccion/2026/08/21/produccion-20260821T233123Z-postgres.dump.zst.age"}]}
```

On failure the same object carries `ok:false` plus `clase` (`"config"`,
`"plugin"` or `"operacion"` — the string form of the exit code) and `error`:

```json
{"ok":false,"clase":"plugin","error":"el binario del plugin «postgres» ha cambiado desde que se registró..."}
```

A failing report still contains everything it managed to produce, which is what
makes a `doctor` run readable even when it exits 4.

```bash
docker run --rm --init ... shieldbk:0.1.0 \
  --config /etc/shieldbk/config.toml --format json backup \
  | jq -r 'if .ok then .targets[].artifact_key else "\(.clase): \(.error)" end'
```

A `doctor` run that finds problems exits **4** and still prints its full report,
so a scheduled `doctor` is a usable liveness check for the whole configuration:

```bash
docker run --rm --init ... shieldbk:0.1.0 \
  --config /etc/shieldbk/config.toml --format json doctor
```

## Verifying the image

`deploy/verificar-imagen.sh` builds the image and runs the complete cycle
inside a container against the mock plugin, with the destination on a Docker
volume:

```
plugin lock -> doctor -> backup -> verify -> restore
```

It checks that the restored bytes match the ones the engine produced, and it
runs as the unprivileged user with a read-only root filesystem, so it also
proves that the `--read-only` + `/tmp` `tmpfs` combination from the examples
above actually works.

```bash
./deploy/verificar-imagen.sh                # build, then verify
./deploy/verificar-imagen.sh --sin-construir  # verify an existing image
IMAGEN=shieldbk:0.1.0 ./deploy/verificar-imagen.sh --sin-construir
```

Run it in CI after any change to the `Dockerfile`, to the plugin startup path,
or to the secret resolver. An image nobody has run is an image that does not
work.
