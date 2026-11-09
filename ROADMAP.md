# Roadmap

Features that could be added to take `shieldbk` from "a tool that works" to
something a company can adopt, audit and scale. None of this is built yet;
the list is ordered by how much value each item delivers for how much change
it demands.

Everything here respects the design as it stands: one process, one job, then
exit; dumps that never touch local disk; encryption before anything leaves the
process; plugins as separate binaries behind gRPC + mTLS.

## Table of contents

- [Tier 1 — what an auditor or a CTO asks for first](#tier-1--what-an-auditor-or-a-cto-asks-for-first)
- [Tier 2 — more sources and destinations](#tier-2--more-sources-and-destinations)
- [Tier 3 — scale](#tier-3--scale)
- [Tier 4 — trust and distribution](#tier-4--trust-and-distribution)
- [Deliberately not planned](#deliberately-not-planned)
- [Suggested order](#suggested-order)

## Tier 1 — what an auditor or a CTO asks for first

### Ransomware protection with Object Lock (WORM)

Upload artifacts with an S3 Object Lock retention period (R2 bucket locks
behave the same way), so that nobody can delete or overwrite them for N days
— not even someone holding the storage credentials.

- **Why:** attackers go for the backups first. "Stolen credentials still cannot
  delete your backups" is the sentence a security team wants to hear.
- **Builds on:** the R2 plugin; `prune` has to skip objects still under lock
  and report them rather than fail.

### Metrics

A Prometheus textfile or Pushgateway export: last successful backup timestamp,
duration, artifact size, exit code — per target.

- **Why:** the dangerous failure is the backup that silently *did not run*.
  Only something outside the process notices an absence, and it needs a signal
  to watch.
- **Builds on:** the JSON report every command already produces. Alerts
  themselves are done: `[[notify]]` blocks hand that report to any `Notifier`
  plugin (webhook, Slack, Discord, Telegram, a dead-man's-switch ping).

## Tier 2 — more sources and destinations

### Restore drills in a throwaway container

`shieldbk drill` already restores into a scratch database on a server you point it
at. The other half of the original idea is a **disposable container**: the plugin
runs `docker run postgres:N`, restores there and removes it, so a backup host with
no PostgreSQL server can still prove its backups restore.

- **Why:** the scratch-database mode needs a server and a role with `CREATEDB`;
  a container needs only Docker. It is also full isolation.
- **Cost:** the container's major version has to match the dump's, and the
  plugin needs the Docker socket. It is a new mode of the existing `Drill`
  service — no protocol change — selected by a plugin field such as `drill_mode`.

### Generic S3 storage plugin

The R2 plugin already talks to storage through `aws-sdk-s3` with a
configurable endpoint and is tested against MinIO. Generalising it to AWS S3,
MinIO, Backblaze B2, Wasabi and any other S3-compatible store is mostly
configuration: region handling, addressing style and storage class.

### New source plugins

| Source | Wraps | Notes |
|---|---|---|
| MySQL / MariaDB | `mysqldump` / `mariadb-dump` | `--single-transaction` for InnoDB consistency |
| MongoDB | `mongodump --archive` | Streams to stdout, fits the pipeline as is |
| Redis | `redis-cli --rdb` | RDB snapshot |
| SQLite | `sqlite3 .backup` | Needs a temp file; the one source that would |
| Directories | tar stream | The generic case |
| Docker volumes | tar via a helper container | Common in self-hosted setups |

Each new source should also implement the `Drill` service, so `shieldbk drill`
works for it from day one: `Provision`/`Check`/`Teardown` are small next to a
dump, and a source that cannot prove its backups restore is only half a backup
tool.

### Point-in-time recovery for PostgreSQL

Archive the WAL continuously (as `archive_command` or through
`pg_receivewal`) next to periodic base backups, so a restore can target a
specific timestamp instead of the last dump.

- **Why:** a nightly dump means losing up to a day of data. PITR brings that
  down to minutes. This is what separates a professional database backup
  from a hobbyist one.
- **Cost:** the largest item in this tier — it introduces a long-running
  receiver, which the one-shot design has to accommodate.

### Replication to a second destination (3-2-1)

`shieldbk storage copy SOURCE_TARGET DEST_TARGET`: copy the ciphertext as is
to another store — another provider, another region. No decryption needed;
the hash in the manifest proves the copy is intact.

## Tier 3 — scale

### Resumable multipart uploads and bandwidth limits

- Resume an interrupted upload of a large dump instead of starting over.
- `--bandwidth-limit` so a backup does not saturate a production link during
  business hours.

- **Why:** at hundreds of gigabytes, a network blip at 90% costs hours.

### Content-defined chunking and deduplication

Split the stream into content-defined chunks, store each chunk once, and
make an artifact a list of chunk references — the model of restic and borg.
Storage savings of 10–50x on large, slowly-changing data.

- **Open question:** the README currently tells people with that workload to
  use restic or borg, and the artifact format is built around a single
  encrypted stream. Doing this means a new artifact format and a change of
  positioning. It is the biggest technical differentiator on this list and
  also the biggest change — a candidate for its own phase, not a feature.

## Tier 4 — trust and distribution

### Key management

- Multiple recipients per target (age supports this natively): an ops key and
  an offline escrow key, so losing one person's key does not lose the
  backups.
- Key rotation: new artifacts go to the new key; old ones stay readable with
  the old identity.
- Identities from HashiCorp Vault or a cloud KMS instead of a file on disk.

### Signed, reproducible releases

- Release binaries signed with cosign, plus an SBOM.
- Packages: Homebrew, `.deb`/`.rpm`, a published container image.
- A Helm chart on top of the existing Kubernetes `CronJob` in
  [`deploy/README.md`](deploy/README.md).

- **Why:** enterprise procurement checks provenance before it checks
  features.

## Deliberately not planned

- **A built-in scheduler or daemon.** cron, systemd timers and Kubernetes
  `CronJob` already do this better, and the one-shot design keeps the failure
  surface small.
- **A web dashboard or multi-tenant server.** Only worth it if the project
  becomes a hosted service; until then, metrics in the tools teams already
  run (Prometheus, Grafana) are the better answer.

## Suggested order

1. Metrics
2. Generic S3 plugin
3. Object Lock

These are small, sit on top of what already exists, and cover two of the three
questions a company asks first: *can it be deleted, and will we know when it
fails?* The third, *can it be restored?*, is answered by `shieldbk drill`.
Chunking and deduplication are the large bet for a later phase.
