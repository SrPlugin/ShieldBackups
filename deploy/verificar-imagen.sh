#!/usr/bin/env bash
# Verificación de la imagen de contenedor de ShieldBackups.
#
# Una imagen que nadie ha ejecutado es una imagen que no funciona. Este script
# construye la imagen y ejecuta **dentro de un contenedor** el ciclo completo
# contra el plugin de pruebas, con el destino en un volumen de Docker:
#
#     plugin lock  ->  doctor  ->  backup  ->  verify  ->  restore
#
# y comprueba, byte a byte, que lo restaurado es lo que el motor volcó.
#
# Cada paso es un `docker run` distinto, como lo sería en producción: procesos
# separados, sin estado compartido más que el volumen. Y todos corren con las
# mismas restricciones que recomienda `deploy/README.md` —usuario 10001, raíz de
# solo lectura, `/tmp` en tmpfs, sin capacidades, `--init`—, así que además de
# verificar el ciclo verifican que esa receta de seguridad es ejecutable.
#
# Uso:
#     ./deploy/verificar-imagen.sh                    # construye y verifica
#     ./deploy/verificar-imagen.sh --sin-construir    # verifica lo que ya hay
#     IMAGEN=shieldbk:0.1.0 ./deploy/verificar-imagen.sh --sin-construir
#     PG_MAJOR=16 ./deploy/verificar-imagen.sh

set -euo pipefail

IMAGEN="${IMAGEN:-shieldbk:verificacion}"
PG_MAJOR="${PG_MAJOR:-17}"
VOLUMEN="${VOLUMEN:-shieldbk-verificacion}"
RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CONSTRUIR=1
for arg in "$@"; do
  case "$arg" in
    --sin-construir) CONSTRUIR=0 ;;
    -h|--help) sed -n '2,26p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "opción desconocida: $arg" >&2; exit 64 ;;
  esac
done

# Clave age de usar y tirar, fija a propósito para que el script no dependa de
# `age-keygen`. Solo cifra los datos sintéticos del plugin mock; no protege
# nada y no debe aparecer en ninguna configuración real.
RECIPIENTE="age1dewvh4c7h669pnve445amtsgqdkr63wkf5zpagzchze84jvky50qvtkr28"
IDENTIDAD="AGE-SECRET-KEY-1Z2EUD35Z4F5UMUWADA2WVCS6FSPNTT6DH4WZFNUYT8YHG6XAVDTQ9Z3SYK"

# 512 KiB con una semilla fija: suficiente para que pasen compresión, cifrado y
# marco de troceado, y lo bastante pequeño para que el ciclo dure segundos.
SEMILLA=7
TAMANO=$((512 * 1024))

TRABAJO="$(mktemp -d)"
limpiar() {
  local codigo=$?
  rm -rf "$TRABAJO"
  docker volume rm -f "$VOLUMEN" >/dev/null 2>&1 || true
  return $codigo
}
trap limpiar EXIT

titulo() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()     { printf '   \033[32mok\033[0m  %s\n' "$*"; }
malo()   { printf '   \033[31mFALLO\033[0m  %s\n' "$*" >&2; exit 1; }

# ── La imagen ────────────────────────────────────────────────────────────────
if [[ $CONSTRUIR -eq 1 ]]; then
  titulo "construyendo $IMAGEN (PG_MAJOR=$PG_MAJOR)"
  DOCKER_BUILDKIT=1 docker build \
    --build-arg "PG_MAJOR=$PG_MAJOR" \
    -t "$IMAGEN" "$RAIZ"
else
  docker image inspect "$IMAGEN" >/dev/null 2>&1 \
    || malo "la imagen «$IMAGEN» no existe; quita --sin-construir"
fi

# ── Configuración y claves ───────────────────────────────────────────────────
# El directorio de datos es el mismo para el motor y para el destino: el motor
# mock escribe ahí lo restaurado y el destino mock guarda ahí los artefactos.
# La sección [plugins] se omite a propósito: comprueba que los valores por
# defecto de la imagen (los enlaces de ~/.shieldbk) resuelven a lo instalado.
cat > "$TRABAJO/config.toml" <<TOML
[[target]]
name = "produccion"
engine = "mock"
storage = "mock"
recipient = "$RECIPIENTE"

[target.engine_config]
dir = "/var/lib/shieldbk"
seed = $SEMILLA
size = $TAMANO

[target.storage_config]
dir = "/var/lib/shieldbk"
TOML

printf '# created: verificación\n# public key: %s\n%s\n' "$RECIPIENTE" "$IDENTIDAD" \
  > "$TRABAJO/clave.age"
# Legible por el UID 10001 del contenedor, que no es el de quien ejecuta esto.
chmod 0444 "$TRABAJO/config.toml" "$TRABAJO/clave.age"

docker volume rm -f "$VOLUMEN" >/dev/null 2>&1 || true
docker volume create "$VOLUMEN" >/dev/null

# `sb` ejecuta shieldbk dentro de un contenedor efímero, con las mismas
# restricciones que recomienda la guía de despliegue.
sb() {
  docker run --rm --init \
    --read-only \
    --tmpfs /tmp:rw,mode=1777,nosuid,nodev \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --memory 256m \
    -v "$TRABAJO/config.toml:/etc/shieldbk/config.toml:ro" \
    -v "$TRABAJO/clave.age:/etc/shieldbk/clave.age:ro" \
    -v "$VOLUMEN:/var/lib/shieldbk" \
    "$IMAGEN" --config /etc/shieldbk/config.toml "$@"
}

# Para mirar el volumen desde fuera del ciclo, sin pasar por shieldbk.
inspeccionar() {
  docker run --rm --entrypoint sh -v "$VOLUMEN:/datos" "$IMAGEN" -c "$1"
}

# ── 0. El usuario y el sellado del lockfile ──────────────────────────────────
titulo "0. usuario sin privilegios y lockfile sellado en el build"
identidad_proceso="$(docker run --rm --entrypoint id "$IMAGEN" -u)"
[[ "$identidad_proceso" == "10001" ]] \
  || malo "el contenedor corre como UID $identidad_proceso, no como 10001"
ok "corre como UID 10001"

docker run --rm --entrypoint test "$IMAGEN" -f /usr/lib/shieldbk/plugins.lock \
  || malo 'la imagen no trae lockfile: `plugin lock` no se ejecutó en el build' 
ok "/usr/lib/shieldbk/plugins.lock existe en la imagen"

version_pg="$(docker run --rm --entrypoint pg_dump "$IMAGEN" --version)"
ok "$version_pg"

# ── 1. plugin lock ───────────────────────────────────────────────────────────
# Es idempotente y aquí se ejecuta contra el lockfile que ya trae la imagen:
# tiene que reconocer los mismos hashes, no reescribir nada (el fichero es de
# solo lectura y de root) y salir bien.
titulo "1. plugin lock / plugin verify"
salida="$(sb --format json plugin verify)" \
  || malo "plugin verify falló sobre el lockfile de la imagen: $salida"
echo "$salida" | grep -q '"fallidos":0' \
  || malo "hay plugins que no verifican: $salida"
ok "los dos plugins de la imagen verifican contra el lockfile del build"

# Un `plugin lock` desde el contenedor tiene que fallar limpiamente, porque el
# lockfile es de root y de solo lectura: la inmutabilidad es la garantía.
if sb plugin lock >/dev/null 2>&1; then
  malo "plugin lock pudo reescribir el lockfile de la imagen; debería ser inmutable"
fi
ok "plugin lock no puede reescribir el lockfile sellado (imagen inmutable)"

# ── 2. doctor ────────────────────────────────────────────────────────────────
titulo "2. doctor"
salida="$(sb --format json doctor)" || malo "doctor falló: $salida"
echo "$salida" | grep -q '"ok":true' || malo "doctor no da ok: $salida"
ok "doctor: todo correcto"

# ── 3. backup ────────────────────────────────────────────────────────────────
titulo "3. backup"
salida="$(sb --format json backup)" || malo "backup falló: $salida"
echo "$salida" | grep -q '"ok":true' || malo "backup no da ok: $salida"
ARTEFACTO="$(printf '%s' "$salida" \
  | sed -n 's/.*"artifact_key":"\([^"]*\)".*/\1/p')"
[[ -n "$ARTEFACTO" ]] || malo "el backup no devolvió artifact_key: $salida"
ok "artefacto: $ARTEFACTO"

inspeccionar "test -f '/datos/$ARTEFACTO'" \
  || malo "el artefacto no está en el volumen"
tam="$(inspeccionar "stat -c %s '/datos/$ARTEFACTO'")"
ok "está en el volumen, $tam bytes"

# ── 4. verify ────────────────────────────────────────────────────────────────
titulo "4. verify"
salida="$(sb verify produccion)" || malo "verify falló: $salida"
printf '%s\n' "$salida" | grep -q '1/1' \
  || malo "verify no comprobó el artefacto: $salida"
ok "verify: 1/1"

# ── 5. restore ───────────────────────────────────────────────────────────────
titulo "5. restore"
salida="$(sb restore produccion "$ARTEFACTO" --identity /etc/shieldbk/clave.age)" \
  || malo "restore falló: $salida"
ok "restore terminó sin error"

# El motor mock deja en `restore.bin` lo que recibe, y su volcado es
# determinista: comparar su SHA-256 con el de un backup nuevo cierra el ciclo.
sha_restaurado="$(inspeccionar "sha256sum /datos/restore.bin | cut -d' ' -f1")"
[[ -n "$sha_restaurado" ]] || malo "restore no escribió /datos/restore.bin"
tam_restaurado="$(inspeccionar "stat -c %s /datos/restore.bin")"
[[ "$tam_restaurado" == "$TAMANO" ]] \
  || malo "lo restaurado mide $tam_restaurado bytes y el volcado eran $TAMANO"
ok "restore.bin: $tam_restaurado bytes, sha256 ${sha_restaurado:0:16}…"

# Segunda vuelta: otro backup del mismo motor determinista y otra restauración.
# Si los dos `restore.bin` coinciden, el ciclo reproduce los datos.
inspeccionar "rm -f /datos/restore.bin"
salida="$(sb --format json backup)" || malo "el segundo backup falló: $salida"
ARTEFACTO2="$(printf '%s' "$salida" \
  | sed -n 's/.*"artifact_key":"\([^"]*\)".*/\1/p')"
sb restore produccion "$ARTEFACTO2" --identity /etc/shieldbk/clave.age >/dev/null \
  || malo "la segunda restauración falló"
sha2="$(inspeccionar "sha256sum /datos/restore.bin | cut -d' ' -f1")"
[[ "$sha2" == "$sha_restaurado" ]] \
  || malo "dos ciclos completos dieron datos distintos: $sha_restaurado vs $sha2"
ok "dos ciclos completos reproducen los mismos bytes"

# ── 6. La puerta de integridad, desde dentro del contenedor ──────────────────
# Sustituir un plugin en caliente tiene que rechazarse. Se hace en una copia de
# la imagen para no tocar la original.
titulo "6. un plugin alterado se rechaza"
alterada="${IMAGEN}-alterada"
docker build -q -t "$alterada" - >/dev/null <<EOF
FROM $IMAGEN
USER root
RUN printf 'x' >> /usr/lib/shieldbk/plugins/sb-plugin-mock
USER 10001:10001
EOF
codigo=0
salida="$(docker run --rm --init --read-only \
  --tmpfs /tmp:rw,mode=1777 --cap-drop ALL \
  -v "$TRABAJO/config.toml:/etc/shieldbk/config.toml:ro" \
  -v "$VOLUMEN:/var/lib/shieldbk" \
  "$alterada" --config /etc/shieldbk/config.toml backup 2>&1)" || codigo=$?
docker image rm -f "$alterada" >/dev/null 2>&1 || true
[[ "$codigo" == "3" ]] \
  || malo "un plugin alterado debe salir con código 3, salió con $codigo: $salida"
printf '%s' "$salida" | grep -q 'ha cambiado' \
  || malo "el mensaje no explica que el binario cambió: $salida"
ok "plugin alterado -> código 3, «ha cambiado»"

# ── Resumen ──────────────────────────────────────────────────────────────────
titulo "resultado"
printf '   imagen   : %s\n' "$IMAGEN"
printf '   tamaño   : %s (sin comprimir, suma de capas)\n' \
  "$(docker history "$IMAGEN" --format '{{.Size}}' | awk '
      /GB/{sub("GB","");s+=$0*1e9;next}
      /MB/{sub("MB","");s+=$0*1e6;next}
      /kB/{sub("kB","");s+=$0*1e3;next}
      {sub("B","");s+=$0}
      END{printf "%.0f MB", s/1e6}')"
printf '   pg_dump  : %s\n' "${version_pg#pg_dump }"
printf '   ciclo    : plugin lock -> doctor -> backup -> verify -> restore  \033[32mOK\033[0m\n'
