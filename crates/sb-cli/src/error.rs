//! El error de la CLI y, con él, el código con el que termina el proceso.
//!
//! Un script que llama a `shieldbk` desde un `cron` necesita reaccionar
//! distinto según **qué** haya fallado: una configuración mal escrita se
//! arregla editando un fichero y no tiene sentido reintentarla, un plugin
//! alterado es un incidente de seguridad, y un backup que se rompe a mitad
//! probablemente se pueda repetir dentro de una hora. Un único «salió mal»
//! obligaría a todos ellos a leer el mensaje, que es justo lo que un programa
//! no debería tener que hacer.
//!
//! Por eso este enum tiene exactamente tres variantes y no una por cada tipo
//! de error del núcleo: las clases son las que un script puede distinguir, no
//! las que el código produce. El detalle completo va dentro del mensaje.

use sb_config::{ConfigError, ValidationError};
use sb_core::lockfile::LockfileError;
use sb_core::naming::NamingError;
use sb_core::ops::BackupError;
use sb_core::plugin::PluginError;
use sb_crypto::AgeError;

/// La configuración no sirve: falta, no se entiende o dice algo imposible.
pub const CODIGO_CONFIG: i32 = 2;
/// Un plugin no se pudo usar: no está, no está registrado, o cambió.
pub const CODIGO_PLUGIN: i32 = 3;
/// La operación falló: el volcado, la subida, la descarga o el diagnóstico.
pub const CODIGO_OPERACION: i32 = 4;

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Nada llegó a ejecutarse porque lo que se pidió no tiene sentido.
    #[error("{0}")]
    Config(String),
    /// El plugin no se pudo poner en marcha, o no se debía.
    #[error("{0}")]
    Plugin(String),
    /// Todo estaba en su sitio y la operación falló igualmente.
    #[error("{0}")]
    Operacion(String),
}

impl CliError {
    pub fn config(mensaje: impl Into<String>) -> Self {
        Self::Config(mensaje.into())
    }

    pub fn plugin(mensaje: impl Into<String>) -> Self {
        Self::Plugin(mensaje.into())
    }

    pub fn operacion(mensaje: impl Into<String>) -> Self {
        Self::Operacion(mensaje.into())
    }

    /// El código con el que termina el proceso.
    #[must_use]
    pub fn codigo(&self) -> i32 {
        match self {
            Self::Config(_) => CODIGO_CONFIG,
            Self::Plugin(_) => CODIGO_PLUGIN,
            Self::Operacion(_) => CODIGO_OPERACION,
        }
    }

    /// El nombre de la clase, para el JSON. Es el mismo dato que el código,
    /// pero legible: `jq '.clase'` es más claro que memorizar que 3 es plugin.
    #[must_use]
    pub fn clase(&self) -> &'static str {
        match self {
            Self::Config(_) => "config",
            Self::Plugin(_) => "plugin",
            Self::Operacion(_) => "operacion",
        }
    }

    /// Una copia con la misma clase y el mismo mensaje.
    ///
    /// `CliError` no es `Clone` a propósito: un error se propaga, no se
    /// duplica. Las dos excepciones son reales y están acotadas —emitirlo por
    /// la salida y agrupar los de varios targets sin sacarlos del informe—, y
    /// tener la copia aquí evita que cada una se escriba su propio `match`.
    #[must_use]
    pub fn duplicar(&self) -> Self {
        match self {
            Self::Config(m) => Self::Config(m.clone()),
            Self::Plugin(m) => Self::Plugin(m.clone()),
            Self::Operacion(m) => Self::Operacion(m.clone()),
        }
    }

    /// Junta los fallos de varios targets en uno solo.
    ///
    /// La clase se conserva **solo si todos coinciden**. Con un único target
    /// eso significa que un plugin sin registrar sale con el código de plugin,
    /// que es lo que un script necesita para no reintentar algo que nunca va a
    /// funcionar solo. Con varios targets fallando por motivos distintos no hay
    /// una clase que los represente, y fingir que sí la hay sería peor que
    /// decir «falló la operación»: mandaría al script a arreglar lo que no era.
    ///
    /// Con la lista vacía no hay nada que agrupar y devuelve `None`.
    #[must_use]
    pub fn agrupar(mensaje: impl Into<String>, fallos: &[Self]) -> Option<Self> {
        let primera = fallos.first()?.clase();
        let mensaje = mensaje.into();
        if fallos.iter().all(|f| f.clase() == primera) {
            Some(match fallos[0] {
                Self::Config(_) => Self::Config(mensaje),
                Self::Plugin(_) => Self::Plugin(mensaje),
                Self::Operacion(_) => Self::Operacion(mensaje),
            })
        } else {
            Some(Self::Operacion(mensaje))
        }
    }
}

impl From<ConfigError> for CliError {
    fn from(e: ConfigError) -> Self {
        Self::Config(format!("la configuración no se pudo usar: {e}"))
    }
}

impl From<ValidationError> for CliError {
    fn from(e: ValidationError) -> Self {
        // Validar contra el esquema del plugin es tarde en el tiempo pero
        // temprano en la causa: lo que está mal es el fichero de configuración,
        // así que el código de salida tiene que ser el de configuración aunque
        // haya hecho falta arrancar un plugin para descubrirlo.
        Self::Config(e.to_string())
    }
}

impl From<NamingError> for CliError {
    fn from(e: NamingError) -> Self {
        Self::Config(e.to_string())
    }
}

impl From<AgeError> for CliError {
    fn from(e: AgeError) -> Self {
        Self::Config(e.to_string())
    }
}

impl From<LockfileError> for CliError {
    fn from(e: LockfileError) -> Self {
        // El mensaje de `sb-core::lockfile` ya dice qué hacer —incluido el
        // `shieldbk plugin lock <nombre>` que hay que teclear—, así que no se
        // envuelve en nada: envolverlo solo lo alejaría del ojo.
        Self::Plugin(e.to_string())
    }
}

impl From<PluginError> for CliError {
    fn from(e: PluginError) -> Self {
        Self::Plugin(e.to_string())
    }
}

impl From<BackupError> for CliError {
    fn from(e: BackupError) -> Self {
        // Un `BackupError` llega cuando la operación ya estaba en marcha,
        // incluidos los suyos que envuelven un `PluginError`: para quien
        // reintenta, el hecho relevante es que el backup no está.
        Self::Operacion(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cada_clase_tiene_su_propio_codigo() {
        // Es toda la razón de ser de este módulo: un script tiene que poder
        // distinguir «arregla el TOML» de «vuelve a intentarlo».
        assert_eq!(CliError::config("x").codigo(), CODIGO_CONFIG);
        assert_eq!(CliError::plugin("x").codigo(), CODIGO_PLUGIN);
        assert_eq!(CliError::operacion("x").codigo(), CODIGO_OPERACION);

        let codigos = [CODIGO_CONFIG, CODIGO_PLUGIN, CODIGO_OPERACION];
        assert!(
            !codigos.contains(&0),
            "ninguna clase de error puede salir con éxito"
        );
    }

    #[test]
    fn un_lockfile_que_no_cuadra_es_un_error_de_plugin_y_conserva_su_remedio() {
        let error = CliError::from(LockfileError::NoRegistrado {
            nombre: "postgres".into(),
            ruta: "/opt/sb-plugin-postgres".into(),
        });
        assert_eq!(error.codigo(), CODIGO_PLUGIN);
        assert!(
            error.to_string().contains("plugin lock postgres"),
            "el remedio del núcleo tiene que llegar intacto: {error}"
        );
    }

    #[test]
    fn agrupar_un_solo_fallo_conserva_su_clase() {
        // El caso que importa: un target, un plugin sin registrar. El script
        // tiene que ver un 3 y no reintentar algo que nunca va a arreglarse
        // solo.
        let agrupado = CliError::agrupar("1 de 1 falló", &[CliError::plugin("no registrado")]);
        assert_eq!(agrupado.map(|e| e.codigo()), Some(CODIGO_PLUGIN));
    }

    #[test]
    fn agrupar_fallos_de_la_misma_clase_la_conserva() {
        let agrupado = CliError::agrupar("2 de 2", &[CliError::plugin("a"), CliError::plugin("b")]);
        assert_eq!(agrupado.map(|e| e.codigo()), Some(CODIGO_PLUGIN));
    }

    #[test]
    fn agrupar_clases_distintas_cae_en_la_general() {
        // No hay una clase que represente a «uno por el TOML y otro por la
        // red»: fingir que sí la hay mandaría al script a arreglar lo que no
        // era.
        let agrupado =
            CliError::agrupar("2 de 3", &[CliError::config("a"), CliError::operacion("b")]);
        assert_eq!(agrupado.map(|e| e.codigo()), Some(CODIGO_OPERACION));
    }

    #[test]
    fn agrupar_sin_fallos_no_inventa_ninguno() {
        assert!(CliError::agrupar("nada", &[]).is_none());
    }

    #[test]
    fn un_fallo_de_validacion_se_cuenta_como_configuracion() {
        // Hace falta un plugin vivo para descubrirlo, pero lo que hay que
        // arreglar es el fichero: reintentarlo no lo va a cambiar.
        let error = CliError::from(ValidationError::CampoRequeridoAusente {
            seccion: "engine".into(),
            campo: "host".into(),
        });
        assert_eq!(error.codigo(), CODIGO_CONFIG);
        assert_eq!(error.clase(), "config");
    }
}
