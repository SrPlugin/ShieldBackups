//! Claves de artefactos: de una clave del núcleo a una ruta dentro del destino.
//!
//! Una clave llega por la red desde el núcleo y acaba siendo una ruta del
//! sistema de ficheros. Ese es exactamente el sitio donde un `..` de más deja
//! de ser un detalle y pasa a ser una escritura fuera del directorio del
//! destino, así que la traducción vive en su propio módulo y se prueba sola.

use std::path::{Component, Path, PathBuf};

use sb_plugin_sdk::tonic::Status;
use time::OffsetDateTime;

/// Un artefacto guardado, tal y como lo ve `List`.
pub struct Artefacto {
    pub clave: String,
    pub tamano: u64,
    /// Fecha de última modificación en **RFC-3339 UTC**, como exige el `.proto`
    /// para `ArtifactMeta.modified_at`: `2026-08-21T09:30:00Z`. Cadena vacía si
    /// el sistema de ficheros no expone la fecha.
    pub modificado: String,
}

/// Traduce una clave a una ruta dentro de `dir`.
///
/// Solo se aceptan claves formadas por componentes normales separados por `/`:
/// eso deja pasar `produccion/2026/08/21/x.age` y rechaza `../fuera`, `/etc/passwd`
/// y `./a`, que no son claves sino intentos de salirse.
///
/// # Errors
/// [`Status::invalid_argument`] si la clave está vacía o contiene algún
/// componente que no sea un nombre.
pub fn ruta_de(dir: &Path, clave: &str) -> Result<PathBuf, Status> {
    if clave.is_empty() {
        return Err(Status::invalid_argument("la clave no puede estar vacía"));
    }
    let relativa = Path::new(clave);
    if relativa
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(Status::invalid_argument(format!(
            "la clave `{clave}` escapa del directorio del destino: solo se aceptan rutas relativas sin `.` ni `..`"
        )));
    }
    Ok(dir.join(relativa))
}

/// Recorre `dir` y devuelve los artefactos cuya clave empieza por `prefijo`.
///
/// Un directorio que aún no existe es un destino vacío, no un error: listar un
/// repositorio antes del primer backup debe devolver cero artefactos.
///
/// El resultado va ordenado por clave: un destino de pruebas que devolviera las
/// claves en el orden del sistema de ficheros haría que un test del núcleo
/// pasara en una máquina y fallara en otra.
///
/// # Errors
/// Devuelve el error de E/S si el directorio existe pero no se puede recorrer.
pub fn listar(dir: &Path, prefijo: &str) -> std::io::Result<Vec<Artefacto>> {
    let mut encontrados = Vec::new();
    if !dir.exists() {
        return Ok(encontrados);
    }
    let mut pendientes = vec![dir.to_path_buf()];
    while let Some(actual) = pendientes.pop() {
        for entrada in std::fs::read_dir(&actual)? {
            let entrada = entrada?;
            let ruta = entrada.path();
            let meta = entrada.metadata()?;
            if meta.is_dir() {
                pendientes.push(ruta);
                continue;
            }
            let Some(clave) = clave_de(dir, &ruta) else {
                continue;
            };
            if !clave.starts_with(prefijo) {
                continue;
            }
            encontrados.push(Artefacto {
                clave,
                tamano: meta.len(),
                modificado: modificado(&meta),
            });
        }
    }
    encontrados.sort_by(|a, b| a.clave.cmp(&b.clave));
    Ok(encontrados)
}

/// La clave de un fichero: su ruta relativa a `dir`, con `/` como separador.
fn clave_de(dir: &Path, ruta: &Path) -> Option<String> {
    let relativa = ruta.strip_prefix(dir).ok()?;
    let mut partes = Vec::new();
    for componente in relativa.components() {
        match componente {
            Component::Normal(n) => partes.push(n.to_str()?.to_string()),
            // Un nombre que no es UTF-8 o una ruta rara no tiene clave que
            // ofrecerle al núcleo; se omite del listado.
            _ => return None,
        }
    }
    Some(partes.join("/"))
}

/// La fecha de modificación en el único formato que el `.proto` admite para
/// `ArtifactMeta.modified_at`: RFC-3339 con la hora en UTC.
///
/// Este destino devolvía antes el epoch en segundos. Era estable, pero el
/// plugin de R2 devuelve RFC-3339, y dos destinos que contestan cosas
/// incomparables rompen en silencio cualquier comparación de fechas entre
/// destinos. El formato lo fija ahora el contrato y aquí solo se cumple.
///
/// Un fichero cuya fecha el sistema no expone —o que cae fuera del rango de
/// fechas representables, cosa que solo pasa con un reloj roto— devuelve
/// cadena vacía: es lo que el contrato pide para «no lo sé», y es preferible a
/// inventarse un instante que luego decidiría qué se borra.
fn modificado(meta: &std::fs::Metadata) -> String {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok())
        .map_or_else(String::new, rfc3339)
}

/// `2026-08-21T09:30:00Z`.
///
/// Se compone con `format!` sobre los accesores en vez de con la feature
/// `formatting` de `time`, que arrastraría proc-macros solo para esto. Sin
/// fracción de segundo, que es lo que fija el `.proto`: una precisión que un
/// destino tiene y otro no volvería a hacer incomparables las fechas —`…:15Z`
/// ordena **después** de `…:15.983Z`, porque `Z` es mayor que `.`—.
fn rfc3339(fecha: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        fecha.year(),
        u8::from(fecha.month()),
        fecha.day(),
        fecha.hour(),
        fecha.minute(),
        fecha.second()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_plugin_sdk::tonic::Code;

    #[test]
    fn una_clave_simple_cae_dentro_del_directorio() {
        let r = ruta_de(Path::new("/destino"), "backup.age").unwrap();
        assert_eq!(r, PathBuf::from("/destino/backup.age"));
    }

    #[test]
    fn una_clave_con_barras_conserva_la_jerarquia() {
        let r = ruta_de(Path::new("/destino"), "produccion/2026/08/21/x.age").unwrap();
        assert_eq!(r, PathBuf::from("/destino/produccion/2026/08/21/x.age"));
    }

    #[test]
    fn una_clave_con_dos_puntos_se_rechaza() {
        for clave in ["../fuera", "a/../../fuera", ".."] {
            let e = ruta_de(Path::new("/destino"), clave).unwrap_err();
            assert_eq!(e.code(), Code::InvalidArgument, "clave {clave}");
        }
    }

    #[test]
    fn una_clave_absoluta_se_rechaza() {
        let e = ruta_de(Path::new("/destino"), "/etc/passwd").unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument);
    }

    #[test]
    fn una_clave_vacia_se_rechaza() {
        assert_eq!(
            ruta_de(Path::new("/destino"), "").unwrap_err().code(),
            Code::InvalidArgument
        );
    }

    #[test]
    fn listar_un_directorio_inexistente_devuelve_vacio() {
        let dir = tempfile::tempdir().unwrap();
        let vacio = listar(&dir.path().join("nunca-creado"), "").unwrap();
        assert!(vacio.is_empty());
    }

    #[test]
    fn listar_recorre_los_subdirectorios_y_ordena() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
        std::fs::write(dir.path().join("a/b/dos.age"), b"xx").unwrap();
        std::fs::write(dir.path().join("uno.age"), b"y").unwrap();

        let todos = listar(dir.path(), "").unwrap();
        let claves: Vec<&str> = todos.iter().map(|a| a.clave.as_str()).collect();
        assert_eq!(claves, vec!["a/b/dos.age", "uno.age"]);
        assert_eq!(todos[0].tamano, 2);

        let filtrados = listar(dir.path(), "a/").unwrap();
        assert_eq!(filtrados.len(), 1);
        assert_eq!(filtrados[0].clave, "a/b/dos.age");
    }

    #[test]
    fn la_fecha_de_un_instante_conocido_es_rfc3339_en_utc() {
        // 1 771 234 200 = 2026-02-16T09:30:00Z. Un instante fijo, no `now()`:
        // así el test comprueba el formato **y** la conversión, y no cambia de
        // resultado según cuándo se ejecute ni en qué huso.
        let fecha = OffsetDateTime::from_unix_timestamp(1_771_234_200).unwrap();
        assert_eq!(rfc3339(fecha), "2026-02-16T09:30:00Z");
    }

    #[test]
    fn el_listado_devuelve_la_fecha_en_rfc3339_y_no_en_epoch() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("uno.age"), b"y").unwrap();

        let todos = listar(dir.path(), "").unwrap();
        let fecha = &todos[0].modificado;

        // La forma exacta que fija el `.proto`: `2026-08-21T09:30:00Z`. Se
        // comprueba la forma y no un valor concreto porque la fecha la pone el
        // sistema de ficheros.
        assert_eq!(fecha.len(), 20, "«{fecha}» no mide lo que un RFC-3339 UTC");
        assert!(fecha.ends_with('Z'), "«{fecha}» no acaba en Z");
        assert_eq!(&fecha[4..5], "-");
        assert_eq!(&fecha[7..8], "-");
        assert_eq!(&fecha[10..11], "T");
        assert_eq!(&fecha[13..14], ":");
        assert_eq!(&fecha[16..17], ":");
        // El epoch en decimal era lo que este destino devolvía antes: si
        // volviera, la cadena sería toda dígitos.
        assert!(
            !fecha.chars().all(|c| c.is_ascii_digit()),
            "«{fecha}» sigue siendo el epoch en segundos"
        );
        // Y se puede volver a leer como fecha, que es lo que el núcleo haría.
        let año: i32 = fecha[..4].parse().unwrap();
        assert!(año >= 2024, "«{fecha}» no parece una fecha real");
    }
}
