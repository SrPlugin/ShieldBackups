//! Lockfile de plugins: verificación de integridad de los binarios que
//! `shieldbk` va a ejecutar.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Versión del formato del lockfile. Se incrementa solo ante cambios que un
/// lector antiguo no pueda interpretar con seguridad.
pub const LOCKFILE_VERSION: u32 = 1;

/// Tamaño del trozo con el que se alimenta al hasher. Ni el binario ni el
/// buffer completo se cargan en memoria.
const TROZO: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum LockfileError {
    #[error("no se pudo leer «{ruta}»: {source}")]
    Lectura {
        ruta: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("no se pudo escribir «{ruta}»: {source}")]
    Escritura {
        ruta: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "el plugin «{nombre}» no está registrado en el lockfile. shieldbk no ejecuta binarios \
         que no ha verificado. Comprueba que «{ruta}» es el binario que esperas y regístralo con \
         `shieldbk plugin lock {nombre}`"
    )]
    NoRegistrado { nombre: String, ruta: PathBuf },
    #[error(
        "el binario del plugin «{nombre}» ({ruta}) ha cambiado desde que se registró: el \
         lockfile esperaba sha256 {esperado} y el archivo tiene {encontrado}. Si el cambio es \
         esperado (has actualizado el plugin), vuelve a registrarlo con `shieldbk plugin lock \
         {nombre}`. Si no lo esperabas, NO lo ejecutes: el binario recibe las credenciales de tu \
         base de datos y de tu almacenamiento"
    )]
    HashNoCoincide {
        nombre: String,
        ruta: PathBuf,
        esperado: String,
        encontrado: String,
    },
    #[error("el lockfile no es válido: {0}")]
    TomlInvalido(String),
}

/// SHA-256 en hexadecimal minúscula del contenido de un archivo.
///
/// Lee en streaming, por trozos de 64 KiB: un binario de Rust compilado puede
/// pesar decenas de megabytes y esto se ejecuta antes de **cada** arranque de
/// plugin, así que el fichero nunca se carga entero en memoria.
///
/// # Errors
/// Devuelve [`LockfileError::Lectura`] si el archivo no existe o no se puede
/// leer.
pub fn hash_de_archivo(ruta: &Path) -> Result<String, LockfileError> {
    let mut archivo = std::fs::File::open(ruta).map_err(|source| LockfileError::Lectura {
        ruta: ruta.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; TROZO];
    loop {
        let leidos = archivo
            .read(&mut buffer)
            .map_err(|source| LockfileError::Lectura {
                ruta: ruta.to_path_buf(),
                source,
            })?;
        if leidos == 0 {
            break;
        }
        hasher.update(&buffer[..leidos]);
    }
    Ok(a_hex(&hasher.finalize()))
}

fn a_hex(bytes: &[u8]) -> String {
    const DIGITOS: &[u8; 16] = b"0123456789abcdef";
    let mut salida = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        salida.push(char::from(DIGITOS[usize::from(byte >> 4)]));
        salida.push(char::from(DIGITOS[usize::from(byte & 0x0f)]));
    }
    salida
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Entrada {
    sha256: String,
}

/// Documento tal y como se serializa a TOML. Separado de [`Lockfile`] para
/// que la versión del formato no forme parte del estado en memoria.
#[derive(Debug, Serialize, Deserialize)]
struct Documento {
    version: u32,
    #[serde(default)]
    plugins: BTreeMap<String, Entrada>,
}

/// Registro de los binarios de plugin que este sistema ha aprobado, con el
/// SHA-256 de cada uno.
///
/// Un plugin recibe las credenciales de la base de datos y del object storage:
/// ejecutar un binario cuyo contenido no se ha verificado es ejecutar código
/// arbitrario con acceso a esos secretos. Antes de arrancar un plugin,
/// `shieldbk` vuelve a calcular el hash del binario y lo compara con el que
/// registró. La idea es la misma que la del lockfile de proveedores de
/// Terraform.
///
/// # Qué protege y qué no
///
/// Protege contra que el binario **cambie** desde que se registró: una
/// actualización silenciosa, una sustitución en el `PATH`, un compromiso del
/// servidor que reescriba el archivo.
///
/// **No** protege contra un plugin malicioso desde el primer momento. Eso es
/// imposible por construcción: un plugin necesita las credenciales para hacer
/// su trabajo, así que registrar el binario equivocado significa haberle dado
/// los secretos al binario equivocado. La confianza en el origen del plugin es
/// una decisión de quien lo registra; el lockfile solo garantiza que sigue
/// siendo el mismo.
///
/// Las entradas se guardan en un [`BTreeMap`]: el orden estable hace que el
/// TOML generado sea determinista y sus diffs legibles, porque este archivo se
/// revisa a mano y se versiona.
#[derive(Debug, Default, Clone)]
pub struct Lockfile {
    plugins: BTreeMap<String, Entrada>,
}

impl Lockfile {
    /// Registra (o vuelve a registrar) el binario de un plugin con el hash que
    /// tiene ahora mismo.
    ///
    /// Re-registrar es la operación normal tras actualizar un plugin: el hash
    /// anterior se reemplaza.
    ///
    /// # Errors
    /// Devuelve [`LockfileError::Lectura`] si el binario no se puede leer.
    pub fn registrar(&mut self, nombre: &str, ruta: &Path) -> Result<(), LockfileError> {
        let sha256 = hash_de_archivo(ruta)?;
        self.plugins.insert(nombre.to_owned(), Entrada { sha256 });
        Ok(())
    }

    /// Comprueba que el binario de `ruta` sigue siendo el que se registró bajo
    /// `nombre`.
    ///
    /// # Errors
    /// - [`LockfileError::NoRegistrado`] si el plugin no está en el lockfile.
    /// - [`LockfileError::HashNoCoincide`] si el binario ha cambiado.
    /// - [`LockfileError::Lectura`] si el binario no se puede leer.
    pub fn verificar(&self, nombre: &str, ruta: &Path) -> Result<(), LockfileError> {
        let Some(entrada) = self.plugins.get(nombre) else {
            return Err(LockfileError::NoRegistrado {
                nombre: nombre.to_owned(),
                ruta: ruta.to_path_buf(),
            });
        };
        let encontrado = hash_de_archivo(ruta)?;
        if encontrado == entrada.sha256 {
            Ok(())
        } else {
            Err(LockfileError::HashNoCoincide {
                nombre: nombre.to_owned(),
                ruta: ruta.to_path_buf(),
                esperado: entrada.sha256.clone(),
                encontrado,
            })
        }
    }

    /// Nombres de los plugins registrados, en orden alfabético estable.
    #[must_use]
    pub fn nombres(&self) -> Vec<String> {
        self.plugins.keys().cloned().collect()
    }

    /// Serializa el lockfile a TOML. La salida solo depende del contenido, no
    /// del orden en que se registraron los plugins.
    ///
    /// # Errors
    /// Devuelve [`LockfileError::TomlInvalido`] si la serialización falla.
    pub fn to_toml(&self) -> Result<String, LockfileError> {
        let documento = Documento {
            version: LOCKFILE_VERSION,
            plugins: self.plugins.clone(),
        };
        toml::to_string(&documento).map_err(|e| LockfileError::TomlInvalido(e.to_string()))
    }

    /// Interpreta el contenido TOML de un lockfile.
    ///
    /// # Errors
    /// Devuelve [`LockfileError::TomlInvalido`] si el texto no es TOML válido,
    /// no tiene la forma esperada o viene de una versión más nueva del
    /// formato.
    pub fn from_toml(texto: &str) -> Result<Self, LockfileError> {
        let documento: Documento =
            toml::from_str(texto).map_err(|e| LockfileError::TomlInvalido(e.to_string()))?;
        if documento.version > LOCKFILE_VERSION {
            return Err(LockfileError::TomlInvalido(format!(
                "lockfile de versión {}, esta versión de shieldbk soporta hasta la {LOCKFILE_VERSION}",
                documento.version
            )));
        }
        Ok(Self {
            plugins: documento.plugins,
        })
    }

    /// Carga el lockfile de disco.
    ///
    /// Si el archivo no existe devuelve un lockfile vacío: la primera vez que
    /// alguien usa `shieldbk` todavía no hay nada registrado, y eso no es un
    /// error de configuración. La diferencia la nota al primer
    /// [`verificar`](Self::verificar), con un mensaje que dice qué hacer.
    ///
    /// # Errors
    /// Devuelve [`LockfileError::Lectura`] si el archivo existe pero no se
    /// puede leer, o [`LockfileError::TomlInvalido`] si su contenido no es
    /// válido.
    pub fn load(ruta: &Path) -> Result<Self, LockfileError> {
        match std::fs::read_to_string(ruta) {
            Ok(texto) => Self::from_toml(&texto),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(LockfileError::Lectura {
                ruta: ruta.to_path_buf(),
                source,
            }),
        }
    }

    /// Escribe el lockfile en disco.
    ///
    /// # Errors
    /// Devuelve [`LockfileError::Escritura`] si el archivo no se puede escribir
    /// o [`LockfileError::TomlInvalido`] si la serialización falla.
    pub fn save(&self, ruta: &Path) -> Result<(), LockfileError> {
        let texto = self.to_toml()?;
        std::fs::write(ruta, texto).map_err(|source| LockfileError::Escritura {
            ruta: ruta.to_path_buf(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn binario_falso(dir: &std::path::Path, nombre: &str, contenido: &[u8]) -> std::path::PathBuf {
        let ruta = dir.join(nombre);
        let mut f = std::fs::File::create(&ruta).unwrap();
        f.write_all(contenido).unwrap();
        ruta
    }

    #[test]
    fn calcula_el_hash_de_un_binario() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = binario_falso(dir.path(), "sb-plugin-x", b"contenido");
        let hash = hash_de_archivo(&ruta).unwrap();
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, hash_de_archivo(&ruta).unwrap());
    }

    #[test]
    fn el_hash_coincide_con_el_sha256_conocido() {
        // Verifica contra un valor externo, no solo consigo mismo: un hash
        // consistente pero incorrecto pasaría el test anterior sin problema.
        let dir = tempfile::tempdir().unwrap();
        let ruta = binario_falso(dir.path(), "sb-plugin-x", b"abc");
        assert_eq!(
            hash_de_archivo(&ruta).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn el_hash_de_un_archivo_vacio_es_el_conocido() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = binario_falso(dir.path(), "vacio", b"");
        assert_eq!(
            hash_de_archivo(&ruta).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hashear_un_archivo_inexistente_da_error() {
        assert!(hash_de_archivo(std::path::Path::new("/no/existe/nada")).is_err());
    }

    #[test]
    fn acepta_un_binario_cuyo_hash_coincide() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = binario_falso(dir.path(), "sb-plugin-x", b"contenido");
        let mut lock = Lockfile::default();
        lock.registrar("x", &ruta).unwrap();
        assert!(lock.verificar("x", &ruta).is_ok());
    }

    #[test]
    fn rechaza_un_binario_modificado() {
        // El caso que justifica todo el módulo.
        let dir = tempfile::tempdir().unwrap();
        let ruta = binario_falso(dir.path(), "sb-plugin-x", b"original");
        let mut lock = Lockfile::default();
        lock.registrar("x", &ruta).unwrap();

        binario_falso(dir.path(), "sb-plugin-x", b"MODIFICADO");

        let err = lock.verificar("x", &ruta).unwrap_err();
        assert!(matches!(err, LockfileError::HashNoCoincide { .. }));
    }

    #[test]
    fn detecta_un_cambio_de_un_solo_byte() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = binario_falso(dir.path(), "p", &vec![7_u8; 100_000]);
        let mut lock = Lockfile::default();
        lock.registrar("p", &ruta).unwrap();

        let mut datos = vec![7_u8; 100_000];
        datos[50_000] = 8;
        binario_falso(dir.path(), "p", &datos);

        assert!(lock.verificar("p", &ruta).is_err());
    }

    #[test]
    fn rechaza_un_plugin_que_no_esta_en_el_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = binario_falso(dir.path(), "sb-plugin-y", b"c");
        let lock = Lockfile::default();
        assert!(matches!(
            lock.verificar("y", &ruta).unwrap_err(),
            LockfileError::NoRegistrado { .. }
        ));
    }

    #[test]
    fn registrar_de_nuevo_actualiza_el_hash() {
        // Actualizar un plugin es legítimo; hay que poder re-registrarlo.
        let dir = tempfile::tempdir().unwrap();
        let ruta = binario_falso(dir.path(), "p", b"v1");
        let mut lock = Lockfile::default();
        lock.registrar("p", &ruta).unwrap();
        binario_falso(dir.path(), "p", b"v2");
        assert!(lock.verificar("p", &ruta).is_err());
        lock.registrar("p", &ruta).unwrap();
        assert!(lock.verificar("p", &ruta).is_ok());
    }

    #[test]
    fn ida_y_vuelta_por_toml() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = binario_falso(dir.path(), "sb-plugin-x", b"c");
        let mut lock = Lockfile::default();
        lock.registrar("x", &ruta).unwrap();

        let texto = lock.to_toml().unwrap();
        let vuelta = Lockfile::from_toml(&texto).unwrap();
        assert!(vuelta.verificar("x", &ruta).is_ok());
    }

    #[test]
    fn el_toml_generado_es_determinista() {
        // El lockfile se revisa a mano y se versiona: sus diffs deben ser
        // legibles, no reordenarse en cada escritura.
        let dir = tempfile::tempdir().unwrap();
        let a = binario_falso(dir.path(), "a", b"1");
        let b = binario_falso(dir.path(), "b", b"2");
        let c = binario_falso(dir.path(), "c", b"3");

        let mut uno = Lockfile::default();
        uno.registrar("zeta", &c).unwrap();
        uno.registrar("alfa", &a).unwrap();
        uno.registrar("mu", &b).unwrap();

        let mut dos = Lockfile::default();
        dos.registrar("alfa", &a).unwrap();
        dos.registrar("mu", &b).unwrap();
        dos.registrar("zeta", &c).unwrap();

        assert_eq!(uno.to_toml().unwrap(), dos.to_toml().unwrap());
    }

    #[test]
    fn un_toml_corrupto_da_error_y_no_panico() {
        assert!(matches!(
            Lockfile::from_toml("esto no es toml [[[").unwrap_err(),
            LockfileError::TomlInvalido(_)
        ));
    }

    #[test]
    fn un_lockfile_ausente_se_trata_como_vacio() {
        // La primera vez que alguien usa shieldbk no existe el archivo. La
        // diferencia la nota al primer `verificar`, con un mensaje que dice
        // qué hacer, no con un error de fichero no encontrado.
        let dir = tempfile::tempdir().unwrap();
        let lock = Lockfile::load(&dir.path().join("no-existe.lock")).unwrap();
        assert!(matches!(
            lock.verificar("x", std::path::Path::new("/bin/true"))
                .unwrap_err(),
            LockfileError::NoRegistrado { .. }
        ));
    }

    #[test]
    fn guardar_y_cargar_desde_disco() {
        let dir = tempfile::tempdir().unwrap();
        let ruta_bin = binario_falso(dir.path(), "p", b"x");
        let ruta_lock = dir.path().join("plugins.lock");

        let mut lock = Lockfile::default();
        lock.registrar("p", &ruta_bin).unwrap();
        lock.save(&ruta_lock).unwrap();

        assert!(
            Lockfile::load(&ruta_lock)
                .unwrap()
                .verificar("p", &ruta_bin)
                .is_ok()
        );
    }

    #[test]
    fn el_mensaje_de_error_dice_que_hacer() {
        // Un error que solo dice "no coincide" deja al usuario a oscuras a las
        // tres de la mañana. Debe decir qué pasó y cómo seguir.
        let dir = tempfile::tempdir().unwrap();
        let ruta = binario_falso(dir.path(), "sb-plugin-x", b"a");
        let mut lock = Lockfile::default();
        lock.registrar("x", &ruta).unwrap();
        binario_falso(dir.path(), "sb-plugin-x", b"b");

        let texto = lock.verificar("x", &ruta).unwrap_err().to_string();
        assert!(
            texto.contains("plugin lock"),
            "debe decir cómo re-registrarlo"
        );
        assert!(texto.contains('x'), "debe nombrar el plugin");
    }

    #[test]
    fn el_error_de_no_registrado_tambien_dice_que_hacer() {
        let lock = Lockfile::default();
        let texto = lock
            .verificar("fantasma", std::path::Path::new("/bin/true"))
            .unwrap_err()
            .to_string();
        assert!(texto.contains("plugin lock"));
        assert!(texto.contains("fantasma"));
    }

    #[test]
    fn lista_los_plugins_registrados() {
        let dir = tempfile::tempdir().unwrap();
        let a = binario_falso(dir.path(), "a", b"1");
        let mut lock = Lockfile::default();
        lock.registrar("uno", &a).unwrap();
        lock.registrar("dos", &a).unwrap();
        let nombres = lock.nombres();
        assert_eq!(nombres, vec!["dos", "uno"], "en orden estable");
    }
}
