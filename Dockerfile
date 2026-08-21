# syntax=docker/dockerfile:1.7

# Imagen de contenedor de ShieldBackups.
#
# ── Por qué esta base final: `debian:*-slim` ─────────────────────────────────
#
# La imagen tiene que traer `pg_dump`, y su versión mayor tiene que poder
# elegirse (un `pg_dump` 15 contra un servidor 16 produce un volcado incompleto
# **sin fallar**). Eso decide la base por sí solo:
#
#   • `distroless` no tiene gestor de paquetes. Meter un cliente de PostgreSQL
#     significa copiar a mano `pg_dump` y su árbol de bibliotecas —libpq, ssl,
#     ldap, sasl, gssapi, krb5, com_err, keyutils, zlib, lz4, zstd…—, que cambia
#     con cada versión mayor de PostgreSQL y con cada actualización de Debian.
#     Se rompe en silencio y en producción. Se descarta.
#   • `alpine` + musl sí tiene `postgresql*-client`, pero **la versión mayor
#     disponible la fija la release de Alpine**: elegir PostgreSQL 15 obligaría
#     a congelar Alpine 3.18. Es justo el grado de libertad que necesitamos.
#     Además `aws-lc-sys` (rustls, vía el SDK de S3) y `ring` compilan mal o
#     lento contra musl, y el asignador de musl penaliza cargas con varios hilos
#     y mucha reserva/liberación, que es exactamente lo que hace el troceador
#     multipart. Se descarta.
#   • `debian:bookworm-slim` + el repositorio oficial PGDG da
#     `postgresql-client-{13..18}` sobre una base estable, con parches de
#     seguridad y con glibc. `--build-arg PG_MAJOR=` elige la versión.
#
# Por lo mismo **no se compila estático**: el binario estático no ahorra nada
# aquí, porque la imagen necesita un gestor de paquetes y un `pg_dump` enlazado
# dinámicamente de todas formas.

ARG RUST_VERSION=1.92
ARG DEBIAN_SUITE=bookworm
# Versión mayor de PostgreSQL cuyo cliente se instala. **Debe ser >= la del
# servidor que se respalda.** Ver `deploy/README.md`.
ARG PG_MAJOR=17


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 0: base de compilación con `cargo-chef`.
#
# El orden de capas es el asunto de esta etapa. Sin `cargo-chef`, un `COPY . .`
# seguido de `cargo build` invalida la capa entera con cada cambio de una línea
# de código y recompila las ~500 dependencias del árbol (el SDK de AWS y
# `aws-lc-sys` solos son varios minutos). `cargo-chef` separa el problema: la
# «receta» es un resumen de los manifiestos y del `Cargo.lock`, y solo cambia
# cuando cambian las dependencias.
# ─────────────────────────────────────────────────────────────────────────────
FROM rust:${RUST_VERSION}-${DEBIAN_SUITE} AS chef

# `cmake` lo exige `aws-lc-sys`, que entra por rustls a través del SDK de S3.
# `protoc` NO hace falta: `sb-proto/build.rs` usa el que trae
# `protoc-bin-vendored`.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends cmake

WORKDIR /app
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo install cargo-chef --locked --version ^0.1


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 1: la receta. Depende del código, pero su *salida* solo cambia si
# cambian las dependencias, así que la etapa siguiente sí cachea.
# ─────────────────────────────────────────────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path receta.json


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 2: compilación.
# ─────────────────────────────────────────────────────────────────────────────
FROM chef AS builder

# Solo la receta. Mientras el `Cargo.lock` y los manifiestos no cambien, esta
# capa y el `cook` que le sigue salen de la caché aunque se haya reescrito medio
# proyecto.
COPY --from=planner /app/receta.json receta.json
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo chef cook --release --workspace --recipe-path receta.json

# Ahora sí el código. Un cambio aquí recompila los nueve crates del workspace y
# nada más.
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo build --release --workspace \
      --bin shieldbk --bin sb-plugin-r2 --bin sb-plugin-mock

# `strip` a mano en vez de tocar el `[profile.release]` del workspace: los
# símbolos siguen estando en `target/` para depurar en local, y solo se van los
# de la copia que viaja en la imagen.
RUN strip /app/target/release/shieldbk \
          /app/target/release/sb-plugin-r2 \
          /app/target/release/sb-plugin-mock


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 3: la imagen final.
# ─────────────────────────────────────────────────────────────────────────────
FROM debian:${DEBIAN_SUITE}-slim AS runtime

ARG DEBIAN_SUITE
ARG PG_MAJOR

LABEL org.opencontainers.image.title="shieldbk" \
      org.opencontainers.image.description="Backups de bases de datos cifrados de extremo a extremo" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/sebastianrcheikh/ShieldBackups"

# `ca-certificates` no es opcional: sin él el plugin de R2 no valida el
# certificado de Cloudflare y toda subida falla.
#
# `gnupg` y `curl` solo sirven para dar de alta el repositorio PGDG y se van en
# el mismo `RUN`, para que no queden en la capa.
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

# Usuario sin privilegios. UID fijo y alto para que un `runAsUser` de Kubernetes
# pueda repetirlo y para que no choque con ningún usuario del sistema.
RUN groupadd --system --gid 10001 shieldbk \
 && useradd --system --uid 10001 --gid 10001 \
            --home-dir /home/shieldbk --create-home --shell /usr/sbin/nologin shieldbk

# Los plugins van en un directorio del sistema, propiedad de root y sin permiso
# de escritura para nadie más. Esa es la mitad de la garantía de integridad; la
# otra mitad es el lockfile que se genera más abajo.
COPY --from=builder --chown=root:root --chmod=0555 \
     /app/target/release/shieldbk /usr/local/bin/shieldbk
COPY --from=builder --chown=root:root --chmod=0555 \
     /app/target/release/sb-plugin-r2   /usr/lib/shieldbk/plugins/sb-plugin-r2
COPY --from=builder --chown=root:root --chmod=0555 \
     /app/target/release/sb-plugin-mock /usr/lib/shieldbk/plugins/sb-plugin-mock

# ── `plugin lock` durante el build ───────────────────────────────────────────
#
# Antes de arrancar un plugin, `shieldbk` comprueba su SHA-256 contra el
# lockfile. Fuera del contenedor eso es un paso de instalación que alguien tiene
# que ejecutar y repetir cada vez que actualiza un binario.
#
# Dentro del contenedor la relación se invierte y **el contenedor refuerza la
# garantía en vez de estorbarla**: la imagen es inmutable, los tres binarios se
# acaban de compilar en esta misma construcción, y el lockfile se sella aquí,
# sobre exactamente esos bytes. A partir de este punto el hash y el binario
# viajan juntos, firmados por el digest de la imagen. Cualquier arranque —el
# primero incluido— verifica de verdad, sin que nadie tenga que acordarse de
# nada, y un plugin sustituido en caliente (un volumen montado encima, un
# `docker cp`) se detecta y se rechaza en el primer `backup`.
#
# La configuración de aquí es de usar y tirar y solo dice dónde están los
# plugins: los comandos de `plugin` no necesitan ningún `[[target]]`.
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

# `shieldbk` busca por defecto `~/.shieldbk/{config.toml,plugins,plugins.lock}`.
# Estos enlaces hacen que los valores por defecto apunten a lo que la imagen
# instala, de modo que un despliegue solo tenga que montar su configuración en
# `/etc/shieldbk/config.toml` y no repetir la sección `[plugins]`. El directorio
# es de root: el usuario `shieldbk` no puede cambiar a dónde apuntan.
RUN set -eux; \
    mkdir -p /etc/shieldbk /home/shieldbk/.shieldbk; \
    ln -s /usr/lib/shieldbk/plugins      /home/shieldbk/.shieldbk/plugins; \
    ln -s /usr/lib/shieldbk/plugins.lock /home/shieldbk/.shieldbk/plugins.lock; \
    ln -s /etc/shieldbk/config.toml      /home/shieldbk/.shieldbk/config.toml; \
    chown -R root:root /home/shieldbk/.shieldbk; \
    chmod 0755 /home/shieldbk/.shieldbk

# Directorio de datos del usuario sin privilegios. Existe en la imagen —y no
# solo en el volumen— para que un volumen con nombre montado aquí herede su
# propietario: Docker copia dueño y permisos del directorio de la imagen, y sin
# esto el volumen nacería de root y el proceso no podría escribir en él.
RUN install -d -o 10001 -g 10001 -m 0750 /var/lib/shieldbk

# El núcleo crea los sockets de control en `XDG_RUNTIME_DIR` si existe y, si no,
# en el temporal del sistema. En un contenedor no hay `XDG_RUNTIME_DIR`, así que
# **`/tmp` tiene que poder escribirse**: con `readOnlyRootFilesystem: true` hay
# que montar ahí un `emptyDir`. Se declara explícito para que no sea una
# sorpresa.
ENV XDG_RUNTIME_DIR=/tmp \
    HOME=/home/shieldbk \
    PATH=/usr/local/bin:/usr/bin:/bin

USER 10001:10001
WORKDIR /home/shieldbk

ENTRYPOINT ["/usr/local/bin/shieldbk"]
CMD ["--help"]
