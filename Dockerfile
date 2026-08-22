# syntax=docker/dockerfile:1.7

# ShieldBackups container image.
#
# -- Why this final base: `debian:*-slim` -------------------------------------
#
# The image has to ship `pg_dump`, and its major version has to be selectable (a
# `pg_dump` 15 against a 16 server produces an incomplete dump **without
# failing**). That settles the base on its own:
#
#   * `distroless` has no package manager. Putting a PostgreSQL client in it
#     means copying `pg_dump` and its library tree by hand -- libpq, ssl, ldap,
#     sasl, gssapi, krb5, com_err, keyutils, zlib, lz4, zstd... -- which changes
#     with every PostgreSQL major version and with every Debian update. It
#     breaks silently and in production. Discarded.
#   * `alpine` + musl does have `postgresql*-client`, but **the available major
#     version is fixed by the Alpine release**: choosing PostgreSQL 15 would
#     force freezing Alpine 3.18. That is exactly the degree of freedom we need.
#     Besides, `aws-lc-sys` (rustls, via the S3 SDK) and `ring` compile badly or
#     slowly against musl, and musl's allocator penalises workloads with several
#     threads and a lot of allocation/deallocation, which is exactly what the
#     multipart chunker does. Discarded.
#   * `debian:bookworm-slim` + the official PGDG repository gives
#     `postgresql-client-{13..18}` on a stable base, with security patches and
#     with glibc. `--build-arg PG_MAJOR=` picks the version.
#
# For the same reason it is **not compiled statically**: a static binary saves
# nothing here, because the image needs a package manager and a dynamically
# linked `pg_dump` anyway.

ARG RUST_VERSION=1.92
ARG DEBIAN_SUITE=bookworm
# PostgreSQL major version whose client gets installed. **Must be >= that of the
# server being backed up.** See `deploy/README.md`.
ARG PG_MAJOR=17


# -----------------------------------------------------------------------------
# Stage 0: build base with `cargo-chef`.
#
# Layer ordering is what this stage is about. Without `cargo-chef`, a `COPY . .`
# followed by `cargo build` invalidates the whole layer on every one-line code
# change and recompiles the ~500 dependencies of the tree (the AWS SDK and
# `aws-lc-sys` alone take several minutes). `cargo-chef` splits the problem: the
# "recipe" is a summary of the manifests and of `Cargo.lock`, and only changes
# when the dependencies change.
# -----------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-${DEBIAN_SUITE} AS chef

# `cmake` is required by `aws-lc-sys`, which comes in through rustls via the S3
# SDK. `protoc` is NOT needed: `sb-proto/build.rs` uses the one shipped by
# `protoc-bin-vendored`.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends cmake

WORKDIR /app
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo install cargo-chef --locked --version ^0.1


# -----------------------------------------------------------------------------
# Stage 1: the recipe. It depends on the code, but its *output* only changes if
# the dependencies change, so the next stage does get cached.
# -----------------------------------------------------------------------------
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json


# -----------------------------------------------------------------------------
# Stage 2: compilation.
# -----------------------------------------------------------------------------
FROM chef AS builder

# Only the recipe. As long as `Cargo.lock` and the manifests do not change, this
# layer and the `cook` that follows it come from the cache even if half the
# project has been rewritten.
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo chef cook --release --workspace --recipe-path recipe.json

# Now the code itself. A change here recompiles the workspace's nine crates and
# nothing else.
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo build --release --workspace \
      --bin shieldbk --bin sb-plugin-r2 --bin sb-plugin-mock

# `strip` by hand rather than touching the workspace's `[profile.release]`: the
# symbols are still in `target/` for local debugging, and only those of the copy
# that travels in the image go away.
RUN strip /app/target/release/shieldbk \
          /app/target/release/sb-plugin-r2 \
          /app/target/release/sb-plugin-mock


# -----------------------------------------------------------------------------
# Stage 3: the final image.
# -----------------------------------------------------------------------------
FROM debian:${DEBIAN_SUITE}-slim AS runtime

ARG DEBIAN_SUITE
ARG PG_MAJOR

LABEL org.opencontainers.image.title="shieldbk" \
      org.opencontainers.image.description="End-to-end encrypted database backups" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/sebastianrcheikh/ShieldBackups"

# `ca-certificates` is not optional: without it the R2 plugin does not validate
# Cloudflare's certificate and every upload fails.
#
# `gnupg` and `curl` only serve to register the PGDG repository and go away in
# the same `RUN`, so that they do not remain in the layer.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg; \
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
      | gpg --dearmor -o /usr/share/keyrings/pgdg.gpg; \
    echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt ${DEBIAN_SUITE}-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends "postgresql-client-${PG_MAJOR}"; \
    apt-get purge -y --auto-remove curl gnupg; \
    rm -rf /var/lib/apt/lists/*; \
    pg_dump --version

# Unprivileged user. A fixed, high UID so that a Kubernetes `runAsUser` can
# repeat it and so that it does not clash with any system user.
RUN groupadd --system --gid 10001 shieldbk \
 && useradd --system --uid 10001 --gid 10001 \
            --home-dir /home/shieldbk --create-home --shell /usr/sbin/nologin shieldbk

# The plugins go in a system directory, owned by root and with no write
# permission for anybody else. That is half of the integrity guarantee; the
# other half is the lockfile generated further down.
COPY --from=builder --chown=root:root --chmod=0555 \
     /app/target/release/shieldbk /usr/local/bin/shieldbk
COPY --from=builder --chown=root:root --chmod=0555 \
     /app/target/release/sb-plugin-r2   /usr/lib/shieldbk/plugins/sb-plugin-r2
COPY --from=builder --chown=root:root --chmod=0555 \
     /app/target/release/sb-plugin-mock /usr/lib/shieldbk/plugins/sb-plugin-mock

# -- `plugin lock` during the build -------------------------------------------
#
# Before starting a plugin, `shieldbk` checks its SHA-256 against the lockfile.
# Outside a container that is an installation step somebody has to run and
# repeat every time they update a binary.
#
# Inside the container the relationship is inverted and **the container
# reinforces the guarantee instead of getting in its way**: the image is
# immutable, the three binaries have just been compiled in this very build, and
# the lockfile is sealed here, over exactly those bytes. From this point on the
# hash and the binary travel together, signed by the image's digest. Any start
# -- the first one included -- really verifies, without anybody having to
# remember anything, and a plugin swapped at runtime (a volume mounted on top, a
# `docker cp`) is detected and rejected on the first `backup`.
#
# The configuration here is throwaway and only says where the plugins are: the
# `plugin` commands need no `[[target]]`.
RUN set -eux; \
    printf '%s\n' \
      '[plugins]' \
      'dir = "/usr/lib/shieldbk/plugins"' \
      'lockfile = "/usr/lib/shieldbk/plugins.lock"' \
      > /tmp/lock.toml; \
    shieldbk --config /tmp/lock.toml --format json plugin lock; \
    shieldbk --config /tmp/lock.toml plugin verify; \
    rm -f /tmp/lock.toml; \
    chmod 0444 /usr/lib/shieldbk/plugins.lock; \
    chown root:root /usr/lib/shieldbk/plugins.lock

# `shieldbk` looks by default for
# `~/.shieldbk/{config.toml,plugins,plugins.lock}`. These links make the
# defaults point at what the image installs, so that a deployment only has to
# mount its configuration at `/etc/shieldbk/config.toml` and not repeat the
# `[plugins]` section. The directory belongs to root: the `shieldbk` user cannot
# change where they point.
RUN set -eux; \
    mkdir -p /etc/shieldbk /home/shieldbk/.shieldbk; \
    ln -s /usr/lib/shieldbk/plugins      /home/shieldbk/.shieldbk/plugins; \
    ln -s /usr/lib/shieldbk/plugins.lock /home/shieldbk/.shieldbk/plugins.lock; \
    ln -s /etc/shieldbk/config.toml      /home/shieldbk/.shieldbk/config.toml; \
    chown -R root:root /home/shieldbk/.shieldbk; \
    chmod 0755 /home/shieldbk/.shieldbk

# Data directory of the unprivileged user. It exists in the image -- and not
# only in the volume -- so that a named volume mounted here inherits its owner:
# Docker copies the owner and permissions of the image's directory, and without
# this the volume would be born as root and the process could not write to it.
RUN install -d -o 10001 -g 10001 -m 0750 /var/lib/shieldbk

# The core creates the control sockets in `XDG_RUNTIME_DIR` if it exists and, if
# not, in the system's temporary directory. In a container there is no
# `XDG_RUNTIME_DIR`, so **`/tmp` has to be writable**: with
# `readOnlyRootFilesystem: true` an `emptyDir` has to be mounted there. It is
# declared explicitly so that it is not a surprise.
ENV XDG_RUNTIME_DIR=/tmp \
    HOME=/home/shieldbk \
    PATH=/usr/local/bin:/usr/bin:/bin

USER 10001:10001
WORKDIR /home/shieldbk

ENTRYPOINT ["/usr/local/bin/shieldbk"]
CMD ["--help"]
