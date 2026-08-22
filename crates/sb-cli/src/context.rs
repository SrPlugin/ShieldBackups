//! La configuración cargada y ya resuelta contra el sistema de ficheros.
//!
//! Todos los comandos parten de lo mismo: un fichero TOML leído, sus rutas
//! expandidas y una forma de elegir sobre qué targets se trabaja. Si cada
//! comando lo hiciera por su cuenta, «expandir la tilde» sería una regla con
//! seis implementaciones y bastaría con olvidarla en una para que un comando
//! buscara los plugins donde no están.

use std::path::{Path, PathBuf};

use sb_config::{Config, Target};

use crate::cli::{CONFIG_POR_DEFECTO, Cli};
use crate::error::CliError;
use crate::paths;

/// Todo lo que un comando necesita saber antes de empezar.
pub struct Contexto {
    pub config: Config,
    /// La ruta desde la que se leyó, para poder nombrarla en los errores.
    pub ruta_config: PathBuf,
    pub dir_plugins: PathBuf,
    pub ruta_lockfile: PathBuf,
    /// Cuántos targets se procesan a la vez. Nunca cero.
    pub jobs: usize,
}

impl Contexto {
    /// Lee la configuración que pidió la línea de órdenes.
    ///
    /// Exige al menos un `[[target]]`: es lo que necesitan los comandos que de
    /// verdad respaldan o restauran algo. Los que solo miran el directorio de
    /// plugins usan [`Contexto::cargar_sin_exigir_targets`].
    ///
    /// # Errors
    /// Devuelve [`CliError::Config`] si el fichero no existe —el mensaje
    /// nombra la ruta exacta que se buscó, que es lo único que permite
    /// distinguir «me equivoqué de ruta» de «se me olvidó crearlo»—, si no se
    /// puede leer o si su contenido no es una configuración válida.
    pub fn cargar(cli: &Cli) -> Result<Self, CliError> {
        Self::leer(cli, sb_config::Config::parse)
    }

    /// Igual, pero sin exigir que la configuración declare ningún target.
    ///
    /// Es para los comandos de `plugin`: el directorio de plugins y el
    /// lockfile son lo único que miran, y registrar un binario es un paso de
    /// instalación que ocurre **antes** de decidir qué bases de datos se
    /// respaldan. Exigirles un `[[target]]` obliga a inventarse uno con un
    /// `recipient` falso solo para poder sellar el lockfile.
    ///
    /// # Errors
    /// Los mismos que [`Contexto::cargar`] menos «no hay targets».
    pub fn cargar_sin_exigir_targets(cli: &Cli) -> Result<Self, CliError> {
        Self::leer(cli, sb_config::Config::parse_without_requiring_targets)
    }

    /// El cuerpo común: localizar el fichero, leerlo, interpretarlo con el
    /// parser que corresponda y expandir las rutas. Lo único que cambia entre
    /// las dos entradas es esa función, así que «expandir la tilde» sigue
    /// teniendo una sola implementación.
    fn leer(
        cli: &Cli,
        parsear: fn(&str) -> Result<Config, sb_config::ConfigError>,
    ) -> Result<Self, CliError> {
        let ruta_config = cli
            .config
            .clone()
            .unwrap_or_else(|| paths::expandir(CONFIG_POR_DEFECTO));

        let texto = std::fs::read_to_string(&ruta_config).map_err(|fuente| {
            CliError::config(format!(
                "no se pudo leer la configuración «{}»: {fuente}. Indica otra con `--config \
                 <ruta>` o crea esa",
                ruta_config.display()
            ))
        })?;

        let config = parsear(&texto).map_err(|fuente| {
            CliError::config(format!(
                "la configuración «{}» no se pudo usar: {fuente}",
                ruta_config.display()
            ))
        })?;

        let dir_plugins = paths::expandir(&config.plugins.dir);
        let ruta_lockfile = paths::expandir(&config.plugins.lockfile);

        // Cero trabajos concurrentes no significa nada y dejaría el proceso
        // esperando un permiso que nunca llega: se corrige en vez de fallar,
        // porque el usuario claramente quería «pocos», no «ninguno».
        let jobs = cli.jobs.max(1);

        tracing::debug!(
            config = %ruta_config.display(),
            plugins = %dir_plugins.display(),
            lockfile = %ruta_lockfile.display(),
            targets = config.targets.len(),
            jobs,
            "contexto cargado"
        );

        Ok(Self {
            config,
            ruta_config,
            dir_plugins,
            ruta_lockfile,
            jobs,
        })
    }

    /// El target que se pidió por nombre.
    ///
    /// # Errors
    /// Devuelve [`CliError::Config`] nombrando el target que no está **y los
    /// que sí**: quien se equivoca al teclear un nombre necesita ver la lista,
    /// no volver a abrir el fichero.
    pub fn target(&self, nombre: &str) -> Result<&Target, CliError> {
        self.config.target(nombre).ok_or_else(|| {
            CliError::config(format!(
                "no hay ningún target llamado «{nombre}» en «{}». Los declarados son: {}",
                self.ruta_config.display(),
                self.nombres_de_target().join(", ")
            ))
        })
    }

    /// Los targets sobre los que hay que trabajar: el que se pidió, o todos.
    ///
    /// # Errors
    /// Devuelve [`CliError::Config`] si se nombró un target que no existe.
    pub fn targets(&self, filtro: Option<&str>) -> Result<Vec<&Target>, CliError> {
        match filtro {
            Some(nombre) => Ok(vec![self.target(nombre)?]),
            None => Ok(self.config.targets.iter().collect()),
        }
    }

    fn nombres_de_target(&self) -> Vec<&str> {
        self.config
            .targets
            .iter()
            .map(|t| t.name.as_str())
            .collect()
    }

    /// La ruta del binario de un plugin: `<plugins.dir>/sb-plugin-<nombre>`.
    #[must_use]
    pub fn ruta_de_plugin(&self, nombre: &str) -> PathBuf {
        ruta_de_plugin(&self.dir_plugins, nombre)
    }
}

/// Prefijo con el que se nombra el binario de un plugin.
///
/// Es lo que permite listar el directorio y saber qué es un plugin y qué es un
/// fichero que alguien dejó ahí.
pub const PREFIJO_BINARIO: &str = "sb-plugin-";

/// La ruta del binario de `nombre` dentro de `dir`.
#[must_use]
pub fn ruta_de_plugin(dir: &Path, nombre: &str) -> PathBuf {
    dir.join(format!("{PREFIJO_BINARIO}{nombre}"))
}

/// El nombre del plugin que corresponde a un fichero, si es que lo es.
#[must_use]
pub fn nombre_de_binario(fichero: &str) -> Option<&str> {
    fichero
        .strip_prefix(PREFIJO_BINARIO)
        .filter(|resto| !resto.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn un_binario_de_plugin_se_reconoce_por_su_prefijo() {
        assert_eq!(nombre_de_binario("sb-plugin-postgres"), Some("postgres"));
        assert_eq!(nombre_de_binario("sb-plugin-mock"), Some("mock"));
    }

    #[test]
    fn lo_que_no_es_un_binario_de_plugin_no_lo_parece() {
        // El directorio de plugins es un directorio normal: puede tener un
        // LEEME, un `.bak` de alguien, o el propio lockfile.
        for ajeno in ["LEEME.txt", "plugins.lock", "sb-plugin-", "postgres"] {
            assert_eq!(nombre_de_binario(ajeno), None, "«{ajeno}» no es un plugin");
        }
    }

    #[test]
    fn la_ruta_de_un_plugin_es_el_prefijo_mas_el_nombre() {
        assert_eq!(
            ruta_de_plugin(Path::new("/opt/sb"), "r2"),
            PathBuf::from("/opt/sb/sb-plugin-r2")
        );
    }
}
