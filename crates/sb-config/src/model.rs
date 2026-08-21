//! Modelo de la configuración TOML de `shieldbk`.
//!
//! Dos decisiones gobiernan este módulo:
//!
//! 1. **`engine_config` y `storage_config` son opacos para el núcleo.** El
//!    núcleo no sabe qué es un puerto de base de datos ni un bucket: guarda esas
//!    tablas como pares clave/valor genéricos ([`ConfigTable`]) y las valida
//!    más tarde contra el esquema que cada plugin declara por gRPC. Codificar
//!    aquí los campos de un motor concreto obligaría a recompilar el núcleo
//!    para soportar un plugin nuevo, que es justo lo que la arquitectura de
//!    plugins evita.
//! 2. **Un secreto nunca es un literal.** Un campo secreto se escribe como una
//!    referencia a su origen ([`SecretRef`]), así que el fichero de
//!    configuración —que se versiona, se copia y se comparte— no contiene
//!    contraseñas.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

/// Nivel de compresión mínimo aceptado (el de zstd).
const NIVEL_MINIMO: i32 = 1;
/// Nivel de compresión máximo aceptado (el de zstd).
const NIVEL_MAXIMO: i32 = 22;

/// Nivel de compresión por defecto.
///
/// Deliberadamente lejos del máximo: comprimir a 19 o 22 multiplica el tiempo
/// de CPU en la máquina que está haciendo el volcado —normalmente el mismo
/// servidor que atiende la base de datos— a cambio de unos pocos puntos
/// porcentuales de tamaño. Quien prefiera el intercambio contrario lo pide
/// explícitamente.
const NIVEL_POR_DEFECTO: i32 = 6;

/// Origen de un secreto. Nunca el secreto en sí.
///
/// El fichero de configuración es un artefacto que se versiona en git, se
/// copia entre máquinas y aparece en informes de error. Un literal ahí dentro
/// es una filtración esperando a ocurrir, así que el modelo directamente no
/// admite ninguno: solo se puede decir *dónde* está el secreto.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretRef {
    /// Variable de entorno del proceso `shieldbk`.
    Env(String),
    /// Archivo cuyo contenido es el secreto. Se exigen permisos restrictivos.
    File(String),
    /// Entrada del llavero del sistema, en formato `servicio/clave`.
    Keyring(String),
    /// Comando y argumentos por separado: no hay shell, así que no hay
    /// inyección.
    Command(Vec<String>),
    /// Acepta permisos abiertos y avisa. Existe solo para secretos montados
    /// por un orquestador: Docker usa 0444 en `/run/secrets` y Kubernetes 0644
    /// por defecto. Rechazarlos sin alternativa impediría el caso de uso más
    /// común en contenedor; relajar la comprobación por defecto sería peor. El
    /// nombre es incómodo a propósito.
    FileInsecure(String),
}

/// Un valor cualquiera dentro de una tabla opaca de plugin.
///
/// El orden de las variantes es significativo: con `untagged`, serde prueba
/// una tras otra y se queda con la primera que encaja. [`SecretRef`] va
/// primero para que una tabla como `{ env = "PGPASSWORD" }` se reconozca como
/// referencia a secreto y no como un valor estructurado cualquiera.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum ConfigValue {
    /// Referencia al origen de un secreto.
    Secret(SecretRef),
    /// Booleano literal.
    Bool(bool),
    /// Entero literal.
    Int(i64),
    /// Cadena literal.
    String(String),
    /// Lista de cadenas. Un array suelto llega aquí; uno dentro de
    /// `{ command = [...] }` se reconoce antes como [`SecretRef::Command`].
    List(Vec<String>),
}

/// Tabla de configuración opaca para el núcleo, validada más tarde contra el
/// esquema que declara el plugin correspondiente.
pub type ConfigTable = BTreeMap<String, ConfigValue>;

/// Dónde viven los plugins y su lockfile.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PluginsConfig {
    /// Directorio donde se buscan los binarios de plugin.
    pub dir: String,
    /// Fichero con los hashes de los binarios autorizados.
    pub lockfile: String,
}

impl Default for PluginsConfig {
    fn default() -> Self {
        Self {
            dir: "~/.shieldbk/plugins".to_owned(),
            lockfile: "~/.shieldbk/plugins.lock".to_owned(),
        }
    }
}

/// Valores que se aplican a todos los targets que no los sobrescriban.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Defaults {
    /// Nivel de compresión global, en `1..=22`.
    pub compression_level: i32,
    /// Plantilla de la clave del artefacto en el destino.
    pub artifact_template: String,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            compression_level: NIVEL_POR_DEFECTO,
            artifact_template:
                "{target}/{yyyy}/{mm}/{dd}/{target}-{timestamp}-{engine}.dump.zst.age".to_owned(),
        }
    }
}

/// Una base de datos que respaldar, con su motor y su destino.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Nombre del target. Se usa como parte de la clave del artefacto.
    pub name: String,
    /// Nombre del plugin de motor (`postgres`, `mysql`, …). El núcleo no
    /// interpreta este valor: solo lo usa para localizar el plugin.
    pub engine: String,
    /// Nombre del plugin de almacenamiento. Igual de opaco que `engine`.
    pub storage: String,
    /// Clave pública age a la que se cifra el backup.
    pub recipient: String,
    /// Configuración del plugin de motor. Opaca aquí.
    #[serde(default)]
    pub engine_config: ConfigTable,
    /// Configuración del plugin de almacenamiento. Opaca aquí.
    #[serde(default)]
    pub storage_config: ConfigTable,
    /// Nivel de compresión propio; si falta, manda el de [`Defaults`].
    #[serde(default)]
    pub compression_level: Option<i32>,
    /// Plantilla propia; si falta, manda la de [`Defaults`].
    #[serde(default)]
    pub artifact_template: Option<String>,
}

impl Target {
    /// Nivel de compresión que se aplicará: el del target si lo define, si no
    /// el global.
    #[must_use]
    pub fn nivel_efectivo(&self, defaults: &Defaults) -> i32 {
        self.compression_level.unwrap_or(defaults.compression_level)
    }

    /// Plantilla de artefacto que se aplicará: la del target si la define, si
    /// no la global.
    #[must_use]
    pub fn plantilla_efectiva<'a>(&'a self, defaults: &'a Defaults) -> &'a str {
        self.artifact_template
            .as_deref()
            .unwrap_or(&defaults.artifact_template)
    }
}

/// La configuración completa de `shieldbk`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Localización de los plugins.
    #[serde(default)]
    pub plugins: PluginsConfig,
    /// Valores globales.
    #[serde(default)]
    pub defaults: Defaults,
    /// Los targets declarados, en el orden del fichero.
    #[serde(rename = "target", default)]
    pub targets: Vec<Target>,
}

/// Lo que puede ir mal al leer una configuración.
///
/// Cada variante nombra el elemento problemático: quien recibe el error tiene
/// que poder ir al fichero y arreglarlo sin adivinar.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// El texto no es TOML válido o no encaja con el modelo.
    #[error("la configuración no es TOML válido: {0}")]
    TomlInvalido(Box<toml::de::Error>),

    /// Dos targets comparten nombre.
    #[error(
        "hay dos targets llamados «{nombre}». El nombre identifica al target en la línea de \
         órdenes y forma parte de la clave del artefacto, así que tiene que ser único"
    )]
    NombreDuplicado {
        /// El nombre repetido.
        nombre: String,
    },

    /// No hay ningún target que respaldar.
    #[error(
        "la configuración no declara ningún target: añade al menos un bloque `[[target]]` con \
         `name`, `engine`, `storage` y `recipient`"
    )]
    SinTargets,

    /// Un valor está fuera del rango admitido.
    #[error("el valor de «{campo}» en {donde} no es válido ({valor}): {motivo}")]
    ValorInvalido {
        /// Nombre del campo.
        campo: String,
        /// Dónde aparece: `[defaults]` o el target concreto.
        donde: String,
        /// El valor rechazado.
        valor: String,
        /// Por qué se rechaza.
        motivo: String,
    },

    /// El nombre de un target no puede usarse en la clave de un artefacto.
    #[error("el nombre de target «{nombre}» no es válido: {motivo}")]
    NombreInvalido {
        /// El nombre rechazado.
        nombre: String,
        /// Por qué se rechaza.
        motivo: String,
    },
}

impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self {
        Self::TomlInvalido(Box::new(e))
    }
}

impl Config {
    /// Lee una configuración desde texto TOML y la valida.
    ///
    /// La validación que se hace aquí es la que el núcleo puede hacer solo:
    /// nombres de target utilizables, unicidad, rangos de compresión. Lo que
    /// haya dentro de `engine_config` y `storage_config` no se toca: eso se
    /// valida contra el esquema que declara cada plugin.
    ///
    /// # Errors
    ///
    /// Devuelve [`ConfigError::TomlInvalido`] si el texto no es TOML válido,
    /// le falta un campo obligatorio o trae un campo desconocido;
    /// [`ConfigError::SinTargets`] si no hay ningún `[[target]]` —los comandos
    /// que no respaldan nada usan [`Config::parse_sin_exigir_targets`]—;
    /// [`ConfigError::NombreDuplicado`] o [`ConfigError::NombreInvalido`] si
    /// los nombres de target no sirven, y [`ConfigError::ValorInvalido`] si un
    /// nivel de compresión está fuera de `1..=22`.
    pub fn parse(texto: &str) -> Result<Self, ConfigError> {
        let config = Self::parse_sin_exigir_targets(texto)?;
        if config.targets.is_empty() {
            return Err(ConfigError::SinTargets);
        }
        Ok(config)
    }

    /// Igual que [`Config::parse`] pero **sin** exigir que haya targets.
    ///
    /// Existe para los comandos que solo necesitan la sección `[plugins]`:
    /// registrar, verificar o listar los binarios de plugin no tiene nada que
    /// ver con qué bases de datos se respaldan, y de hecho es lo que se hace
    /// *antes* de decidirlo —al instalar, o al construir una imagen—. Exigir
    /// ahí un `[[target]]` obliga a inventarse uno con un `recipient` falso.
    ///
    /// Todo lo demás se valida igual. Quien sí vaya a respaldar algo llama a
    /// [`Config::parse`], que es la que exige los targets.
    ///
    /// # Errors
    ///
    /// Los mismos que [`Config::parse`] menos [`ConfigError::SinTargets`].
    pub fn parse_sin_exigir_targets(texto: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(texto)?;

        valida_nivel(config.defaults.compression_level, "[defaults]")?;

        let mut vistos = BTreeSet::new();
        for target in &config.targets {
            valida_nombre(&target.name)?;
            if !vistos.insert(target.name.as_str()) {
                return Err(ConfigError::NombreDuplicado {
                    nombre: target.name.clone(),
                });
            }
            if let Some(nivel) = target.compression_level {
                valida_nivel(nivel, &format!("el target «{}»", target.name))?;
            }
        }

        tracing::debug!(targets = config.targets.len(), "configuración cargada");
        Ok(config)
    }

    /// Busca un target por su nombre.
    #[must_use]
    pub fn target(&self, nombre: &str) -> Option<&Target> {
        self.targets.iter().find(|t| t.name == nombre)
    }
}

/// Comprueba que un nivel de compresión está en el rango de zstd.
fn valida_nivel(nivel: i32, donde: &str) -> Result<(), ConfigError> {
    if (NIVEL_MINIMO..=NIVEL_MAXIMO).contains(&nivel) {
        return Ok(());
    }
    Err(ConfigError::ValorInvalido {
        campo: "compression_level".to_owned(),
        donde: donde.to_owned(),
        valor: nivel.to_string(),
        motivo: format!("zstd solo admite niveles de {NIVEL_MINIMO} a {NIVEL_MAXIMO}"),
    })
}

/// Comprueba que un nombre de target puede formar parte de la clave de un
/// artefacto sin sorpresas.
///
/// El nombre acaba concatenado en una ruta del destino remoto. Una barra
/// crearía jerarquía donde no se esperaba, `..` podría escapar del prefijo del
/// target al escribir en un destino de sistema de archivos, y un byte nulo
/// trunca cadenas en cualquier API en C que haya por debajo.
fn valida_nombre(nombre: &str) -> Result<(), ConfigError> {
    let motivo = if nombre.is_empty() {
        "no puede estar vacío"
    } else if nombre.contains('/') || nombre.contains('\\') {
        "no puede contener barras: el nombre forma parte de la clave del artefacto"
    } else if nombre.contains("..") {
        "no puede contener «..»: podría escapar del prefijo del target en el destino"
    } else if nombre.contains('\0') {
        "no puede contener bytes nulos"
    } else {
        return Ok(());
    };
    Err(ConfigError::NombreInvalido {
        nombre: nombre.to_owned(),
        motivo: motivo.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EJEMPLO: &str = r#"
[plugins]
dir = "~/.shieldbk/plugins"
lockfile = "~/.shieldbk/plugins.lock"

[defaults]
compression_level = 6
artifact_template = "{target}/{yyyy}/{mm}/{dd}/{target}-{timestamp}-{engine}.dump.zst.age"

[[target]]
name = "produccion"
engine = "postgres"
storage = "r2"
recipient = "age1qqqqqqqqqq"

[target.engine_config]
host = "db.interno"
port = 5432
ssl = true
password = { env = "PGPASSWORD" }

[target.storage_config]
bucket = "backups"
secret_access_key = { keyring = "shieldbk/r2" }
"#;

    #[test]
    fn parsea_una_configuracion_completa() {
        let c = Config::parse(EJEMPLO).unwrap();
        assert_eq!(c.targets.len(), 1);
        assert_eq!(c.targets[0].name, "produccion");
        assert_eq!(c.targets[0].engine, "postgres");
        assert_eq!(c.targets[0].storage, "r2");
        assert_eq!(c.defaults.compression_level, 6);
    }

    #[test]
    fn los_valores_literales_y_las_referencias_conviven() {
        let c = Config::parse(EJEMPLO).unwrap();
        let ec = &c.targets[0].engine_config;
        assert!(matches!(ec.get("host"), Some(ConfigValue::String(s)) if s == "db.interno"));
        assert!(matches!(ec.get("port"), Some(ConfigValue::Int(5432))));
        assert!(matches!(ec.get("ssl"), Some(ConfigValue::Bool(true))));
        assert!(
            matches!(ec.get("password"), Some(ConfigValue::Secret(SecretRef::Env(v))) if v == "PGPASSWORD")
        );
    }

    #[test]
    fn reconoce_las_cinco_fuentes_de_secreto() {
        let toml = r#"
[[target]]
name = "t"
engine = "e"
storage = "s"
recipient = "age1x"
[target.engine_config]
a = { env = "A" }
b = { file = "/ruta/b" }
c = { keyring = "servicio/c" }
d = { command = ["vault", "read", "x"] }
e = { file_insecure = "/run/secrets/e" }
"#;
        let c = Config::parse(toml).unwrap();
        let ec = &c.targets[0].engine_config;
        assert!(matches!(
            ec.get("a"),
            Some(ConfigValue::Secret(SecretRef::Env(_)))
        ));
        assert!(matches!(
            ec.get("b"),
            Some(ConfigValue::Secret(SecretRef::File(_)))
        ));
        assert!(matches!(
            ec.get("c"),
            Some(ConfigValue::Secret(SecretRef::Keyring(_)))
        ));
        assert!(matches!(
            ec.get("d"),
            Some(ConfigValue::Secret(SecretRef::Command(_)))
        ));
        assert!(matches!(
            ec.get("e"),
            Some(ConfigValue::Secret(SecretRef::FileInsecure(_)))
        ));
    }

    #[test]
    fn una_lista_de_cadenas_no_se_confunde_con_un_comando() {
        // `command` es un array de cadenas, igual que una lista normal. La
        // diferencia la marca estar dentro de una tabla con esa clave.
        let toml = r#"
[[target]]
name = "t"
engine = "e"
storage = "s"
recipient = "age1x"
[target.engine_config]
exclusiones = ["tabla_a", "tabla_b"]
"#;
        let c = Config::parse(toml).unwrap();
        assert!(matches!(
            c.targets[0].engine_config.get("exclusiones"),
            Some(ConfigValue::List(v)) if v.len() == 2
        ));
    }

    #[test]
    fn se_rechazan_dos_targets_con_el_mismo_nombre() {
        let toml = r#"
[[target]]
name = "dup"
engine = "e"
storage = "s"
recipient = "age1x"
[[target]]
name = "dup"
engine = "e"
storage = "s"
recipient = "age1x"
"#;
        let err = Config::parse(toml).unwrap_err();
        assert!(matches!(err, ConfigError::NombreDuplicado { .. }));
        assert!(err.to_string().contains("dup"), "debe nombrar el duplicado");
    }

    #[test]
    fn se_rechaza_una_configuracion_sin_targets() {
        assert!(matches!(
            Config::parse("[plugins]\ndir = \"/x\"").unwrap_err(),
            ConfigError::SinTargets
        ));
    }

    #[test]
    fn sin_exigir_targets_una_config_de_solo_plugins_es_valida() {
        // Instalar plugins pasa antes que decidir qué se respalda: quien solo
        // va a sellar el lockfile no tiene por qué inventarse un target.
        let c = Config::parse_sin_exigir_targets("[plugins]\ndir = \"/opt/sb\"").unwrap();
        assert!(c.targets.is_empty());
        assert_eq!(c.plugins.dir, "/opt/sb");
    }

    #[test]
    fn sin_exigir_targets_el_resto_de_la_validacion_sigue_en_pie() {
        // Lo único que se relaja es la exigencia de targets. Un target mal
        // escrito se sigue rechazando igual.
        for malo in [
            "[defaults]\ncompression_level = 99\n",
            "[[target]]\nname = \"con/barra\"\nengine = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\n",
            "esto no es toml [[[",
        ] {
            assert!(
                Config::parse_sin_exigir_targets(malo).is_err(),
                "«{malo}» debería rechazarse igual que en `parse`"
            );
        }
    }

    #[test]
    fn se_rechaza_un_target_sin_recipient() {
        // Sin clave pública no se puede cifrar, y un backup sin cifrar no es
        // lo que esta herramienta promete.
        let toml = "[[target]]\nname = \"t\"\nengine = \"e\"\nstorage = \"s\"\n";
        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn el_nivel_de_compresion_global_se_valida() {
        let toml = format!("[defaults]\ncompression_level = 99\n{EJEMPLO_TARGET}");
        assert!(matches!(
            Config::parse(&toml).unwrap_err(),
            ConfigError::ValorInvalido { .. }
        ));
    }

    #[test]
    fn el_nivel_de_compresion_por_target_se_valida() {
        let toml = "[[target]]\nname = \"t\"\nengine = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\ncompression_level = 0\n";
        let err = Config::parse(toml).unwrap_err();
        assert!(matches!(err, ConfigError::ValorInvalido { .. }));
        assert!(err.to_string().contains('t'), "debe decir en qué target");
    }

    const EJEMPLO_TARGET: &str = r#"
[[target]]
name = "t"
engine = "e"
storage = "s"
recipient = "age1x"
"#;

    #[test]
    fn un_target_se_busca_por_nombre() {
        let c = Config::parse(EJEMPLO).unwrap();
        assert!(c.target("produccion").is_some());
        assert!(c.target("no-existe").is_none());
    }

    #[test]
    fn el_nivel_del_target_gana_al_global() {
        let toml = "[defaults]\ncompression_level = 3\n[[target]]\nname = \"t\"\nengine = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\ncompression_level = 19\n";
        let c = Config::parse(toml).unwrap();
        assert_eq!(c.targets[0].nivel_efectivo(&c.defaults), 19);
    }

    #[test]
    fn sin_nivel_en_el_target_se_usa_el_global() {
        let c = Config::parse(EJEMPLO).unwrap();
        assert_eq!(c.targets[0].nivel_efectivo(&c.defaults), 6);
    }

    #[test]
    fn la_plantilla_del_target_gana_a_la_global() {
        let toml = "[[target]]\nname = \"t\"\nengine = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\nartifact_template = \"propia\"\n";
        let c = Config::parse(toml).unwrap();
        assert_eq!(c.targets[0].plantilla_efectiva(&c.defaults), "propia");
    }

    #[test]
    fn los_valores_por_defecto_son_razonables() {
        let c = Config::parse(EJEMPLO_TARGET).unwrap();
        assert!(
            (1..=9).contains(&c.defaults.compression_level),
            "el nivel por defecto debe ser rápido, no máximo"
        );
        assert!(c.defaults.artifact_template.contains("{target}"));
        assert!(c.plugins.dir.contains("plugins"));
    }

    #[test]
    fn un_toml_invalido_da_error_y_no_panico() {
        assert!(matches!(
            Config::parse("esto no es toml [[[").unwrap_err(),
            ConfigError::TomlInvalido(_)
        ));
    }

    #[test]
    fn un_campo_desconocido_en_target_se_rechaza() {
        // Un typo en un nombre de campo no puede ignorarse en silencio: el
        // usuario creería haber configurado algo que no está activo.
        let toml = "[[target]]\nname = \"t\"\nengine = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\ncompresion_level = 5\n";
        assert!(
            Config::parse(toml).is_err(),
            "un campo desconocido debe rechazarse"
        );
    }

    #[test]
    fn los_nombres_de_target_no_pueden_estar_vacios_ni_llevar_barras() {
        // El nombre del target va en la clave del artefacto: una barra o un
        // nombre vacío producirían rutas absurdas o inseguras en el destino.
        for malo in ["", "con/barra", "..", "con espacio/y barra"] {
            let toml = format!(
                "[[target]]\nname = \"{malo}\"\nengine = \"e\"\nstorage = \"s\"\nrecipient = \"age1x\"\n"
            );
            assert!(Config::parse(&toml).is_err(), "«{malo}» debería rechazarse");
        }
    }
}
