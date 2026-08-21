//! La forma de la línea de órdenes, y nada más.
//!
//! Aquí no se ejecuta nada: este archivo es la única descripción de qué se
//! puede teclear. Tenerlo aparte hace que añadir una opción no obligue a leer
//! ninguna implementación, y que leer la implementación de un comando no
//! obligue a bucear entre atributos de `clap`.

use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand};

use crate::output::Formato;

/// Ruta de la configuración cuando no se pasa `--config`.
pub const CONFIG_POR_DEFECTO: &str = "~/.shieldbk/config.toml";

#[derive(Debug, Parser)]
#[command(
    name = "shieldbk",
    version,
    about = "Backups de bases de datos cifrados de extremo a extremo",
    long_about = "shieldbk respalda bases de datos a través de plugins que corren como procesos \
                  aparte. El volcado se comprime, se cifra con age y se sube sin tocar el disco \
                  local.\n\nCódigos de salida: 0 correcto, 2 error de configuración, 3 error de \
                  plugin, 4 error de operación."
)]
pub struct Cli {
    /// Fichero de configuración TOML.
    #[arg(long, global = true, value_name = "RUTA")]
    pub config: Option<PathBuf>,

    /// Formato de la salida estándar. Los registros van siempre a stderr.
    #[arg(long, global = true, value_enum, default_value = "human")]
    pub format: Formato,

    /// Cuántos targets se procesan a la vez.
    ///
    /// Uno por defecto: varios volcados simultáneos compiten por el mismo disco
    /// y la misma base de datos, y el que sale perdiendo es el servidor que
    /// está atendiendo a los usuarios.
    #[arg(long, global = true, value_name = "N", default_value_t = 1)]
    pub jobs: usize,

    /// Sube el nivel de traza: `-v` info, `-vv` debug, `-vvv` trace.
    #[arg(short = 'v', long = "verbose", global = true, action = ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub comando: Comando,
}

#[derive(Debug, Subcommand)]
pub enum Comando {
    /// Respalda un target, o todos si no se nombra ninguno.
    Backup {
        /// Target a respaldar. Sin él, se respaldan todos.
        target: Option<String>,
    },

    /// Restaura un artefacto sobre el motor del target.
    Restore {
        /// Target sobre el que se restaura.
        target: String,
        /// Clave del artefacto en el destino.
        artifact: String,
        /// Fichero con la clave privada age (`age-keygen`).
        #[arg(long, value_name = "RUTA")]
        identity: PathBuf,
    },

    /// Comprueba que los artefactos siguen íntegros. No necesita la clave.
    Verify {
        /// Target cuyos artefactos se comprueban.
        target: String,
        /// Artefacto concreto. Sin él, se comprueban todos los del target.
        artifact: Option<String>,
    },

    /// Diagnostica un target —o todos— antes de que falle un backup de verdad.
    Doctor {
        /// Target a diagnosticar. Sin él, se diagnostican todos.
        target: Option<String>,
    },

    /// Gestiona los plugins y el lockfile que autoriza sus binarios.
    Plugin {
        #[command(subcommand)]
        accion: AccionPlugin,
    },

    /// Tareas de mantenimiento sobre el destino.
    Storage {
        #[command(subcommand)]
        accion: AccionStorage,
    },
}

#[derive(Debug, Subcommand)]
pub enum AccionPlugin {
    /// Enumera los binarios encontrados y su estado en el lockfile.
    List,
    /// Imprime el esquema de configuración de un plugin. Nunca imprime valores.
    Docs {
        /// Nombre del plugin, sin el prefijo `sb-plugin-`.
        plugin: String,
    },
    /// Comprueba los hashes de todos los plugins sin arrancar ninguno.
    Verify,
    /// Registra el hash de cada binario del directorio y escribe el lockfile.
    Lock,
}

#[derive(Debug, Subcommand)]
pub enum AccionStorage {
    /// Aborta las subidas incompletas que el destino siga cobrando.
    Gc {
        /// Target cuyo destino se limpia.
        target: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn la_definicion_es_coherente() {
        // `debug_assert` de clap detecta las incoherencias que solo se verían
        // al ejecutar: nombres repetidos, valores por defecto que no encajan
        // con su tipo, opciones globales en sitios imposibles.
        Cli::command().debug_assert();
    }

    #[test]
    fn estan_los_seis_comandos() {
        let nombres: Vec<String> = Cli::command()
            .get_subcommands()
            .map(|c| c.get_name().to_owned())
            .collect();
        for esperado in ["backup", "restore", "verify", "doctor", "plugin", "storage"] {
            assert!(nombres.contains(&esperado.to_owned()), "falta {esperado}");
        }
    }

    #[test]
    fn las_opciones_globales_valen_despues_del_subcomando() {
        // `shieldbk backup --format json` tiene que funcionar igual que
        // `shieldbk --format json backup`: nadie recuerda dónde va cada cosa.
        let cli = Cli::try_parse_from(["shieldbk", "backup", "--format", "json", "-vv"]).unwrap();
        assert_eq!(cli.format, Formato::Json);
        assert_eq!(cli.verbose, 2);
        assert!(matches!(cli.comando, Comando::Backup { target: None }));
    }

    #[test]
    fn jobs_es_uno_por_defecto() {
        // El valor por defecto es una decisión de seguridad operativa, no un
        // detalle: varios volcados a la vez saturan el servidor de base de
        // datos, y quien quiera correr ese riesgo tiene que pedirlo.
        let cli = Cli::try_parse_from(["shieldbk", "backup"]).unwrap();
        assert_eq!(cli.jobs, 1);
    }

    #[test]
    fn restore_exige_la_identidad() {
        // Sin clave privada no hay restauración posible, así que no se puede
        // llegar a arrancar un plugin sin ella.
        assert!(Cli::try_parse_from(["shieldbk", "restore", "t", "clave"]).is_err());
        let cli =
            Cli::try_parse_from(["shieldbk", "restore", "t", "clave", "--identity", "/k"]).unwrap();
        assert!(matches!(cli.comando, Comando::Restore { .. }));
    }

    #[test]
    fn verify_admite_un_artefacto_opcional() {
        let todos = Cli::try_parse_from(["shieldbk", "verify", "t"]).unwrap();
        assert!(matches!(
            todos.comando,
            Comando::Verify { artifact: None, .. }
        ));
        let uno = Cli::try_parse_from(["shieldbk", "verify", "t", "clave"]).unwrap();
        assert!(matches!(
            uno.comando,
            Comando::Verify {
                artifact: Some(_),
                ..
            }
        ));
    }
}
