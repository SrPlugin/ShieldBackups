//! Expansión de `~` en las rutas que vienen de la configuración.
//!
//! El fichero de configuración se escribe a mano y se comparte entre máquinas,
//! así que sus rutas se escriben como las escribiría una persona:
//! `~/.shieldbk/plugins`. La shell expande esa tilde cuando el argumento pasa
//! por ella, pero una ruta leída de un TOML no pasa por ninguna shell, y sin
//! esto `shieldbk` buscaría los plugins en un directorio llamado literalmente
//! `~`, creado dentro del directorio de trabajo. El fallo no sería un error
//! sino algo peor: funcionaría, en el sitio equivocado.

use std::path::PathBuf;

/// Convierte una ruta de la configuración en una ruta del sistema.
///
/// Solo se expande `~` a secas y `~/…`: la forma `~usuario` exigiría consultar
/// la base de datos de usuarios del sistema y se deja tal cual, que es lo que
/// hacen la mayoría de las herramientas y lo que evita fingir que se entiende
/// algo que no se entiende.
///
/// Si `HOME` no está definida la ruta se devuelve intacta: es preferible que
/// falle luego nombrando la ruta literal —que es lo que se buscó— a inventarse
/// un directorio personal.
#[must_use]
pub fn expandir(ruta: &str) -> PathBuf {
    let Some(hogar) = std::env::var_os("HOME") else {
        return PathBuf::from(ruta);
    };

    if ruta == "~" {
        return PathBuf::from(hogar);
    }
    if let Some(resto) = ruta.strip_prefix("~/") {
        return PathBuf::from(hogar).join(resto);
    }
    PathBuf::from(ruta)
}

#[cfg(test)]
mod tests {
    use super::*;

    // `HOME` no se toca aquí: cambiar el entorno del proceso es `unsafe` desde
    // la edición 2024 y el workspace lo prohíbe. Estas pruebas se apoyan en el
    // `HOME` real —siempre definido bajo cargo— y son los tests de `tests/` los
    // que comprueban la expansión con un hogar de mentira, porque ahí el
    // binario es un proceso hijo y su entorno sí se puede fijar.

    #[test]
    fn una_ruta_absoluta_no_se_toca() {
        assert_eq!(expandir("/opt/plugins"), PathBuf::from("/opt/plugins"));
    }

    #[test]
    fn una_ruta_relativa_no_se_toca() {
        assert_eq!(
            expandir("plugins/locales"),
            PathBuf::from("plugins/locales")
        );
    }

    #[test]
    fn la_tilde_se_expande_al_hogar() {
        let Some(hogar) = std::env::var_os("HOME") else {
            return;
        };
        assert_eq!(
            expandir("~/.shieldbk/plugins"),
            PathBuf::from(&hogar).join(".shieldbk/plugins")
        );
        assert_eq!(expandir("~"), PathBuf::from(&hogar));
    }

    #[test]
    fn una_tilde_a_media_ruta_no_significa_nada() {
        // Solo el prefijo es especial: `/datos/~/x` es un directorio que se
        // llama así, no el hogar de nadie.
        assert_eq!(expandir("/datos/~/x"), PathBuf::from("/datos/~/x"));
        assert_eq!(expandir("~otro/x"), PathBuf::from("~otro/x"));
    }
}
