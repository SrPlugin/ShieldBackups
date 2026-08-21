// Igual que en `sb-core/tests/comun/mod.rs`: esto es todo código de prueba, y
// ahí un `unwrap` es lo que se quiere —que el test explote justo donde falló—.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Este módulo se compila dentro de **cada** binario de test que lo declara, y
// ninguno de ellos usa todos sus ayudantes.
#![allow(dead_code)]

//! Lo que comparten los tests de la CLI: un entorno aislado —config, directorio
//! de plugins y lockfile propios— y una forma cómoda de invocar al binario.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use assert_cmd::Command;

/// Un banco de pruebas completo: `HOME` propio, config propia, plugins propios.
///
/// El `HOME` propio no es un detalle: la CLI expande `~` en las rutas de
/// plugins y del lockfile, y un test que se dejara el `HOME` real escribiría en
/// el directorio de quien lo ejecuta.
pub struct Banco {
    pub raiz: tempfile::TempDir,
}

impl Banco {
    pub fn nuevo() -> Self {
        let raiz = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(raiz.path().join("plugins")).unwrap();
        std::fs::create_dir_all(raiz.path().join("datos")).unwrap();
        Self { raiz }
    }

    pub fn ruta(&self, relativa: &str) -> PathBuf {
        self.raiz.path().join(relativa)
    }

    pub fn dir_plugins(&self) -> PathBuf {
        self.ruta("plugins")
    }

    pub fn dir_datos(&self) -> PathBuf {
        self.ruta("datos")
    }

    pub fn lockfile(&self) -> PathBuf {
        self.ruta("plugins.lock")
    }

    /// Escribe la configuración y devuelve su ruta.
    pub fn config(&self, contenido: &str) -> PathBuf {
        let ruta = self.ruta("config.toml");
        std::fs::write(&ruta, contenido).unwrap();
        ruta
    }

    /// Configuración mínima con un target sobre el plugin mock.
    pub fn config_mock(&self, recipient: &str) -> PathBuf {
        self.config(&format!(
            r#"
[plugins]
dir = {dir:?}
lockfile = {lock:?}

[[target]]
name = "produccion"
engine = "mock"
storage = "mock"
recipient = "{recipient}"

[target.engine_config]
dir = {datos:?}
seed = 7
size = 65536

[target.storage_config]
dir = {datos:?}
"#,
            dir = self.dir_plugins().to_string_lossy(),
            lock = self.lockfile().to_string_lossy(),
            datos = self.dir_datos().to_string_lossy(),
        ))
    }

    /// El binario, con el entorno ya aislado.
    pub fn cmd(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_shieldbk"));
        cmd.env("HOME", self.raiz.path());
        cmd.env_remove("RUST_LOG");
        cmd
    }

    /// Copia el binario del plugin mock al directorio de plugins con el nombre
    /// que la CLI espera encontrar: `sb-plugin-<nombre>`.
    pub fn instalar_mock(&self) -> PathBuf {
        let destino = self.dir_plugins().join("sb-plugin-mock");
        std::fs::copy(ruta_mock(), &destino).unwrap();
        destino
    }
}

/// Ruta del binario del plugin mock.
///
/// `CARGO_BIN_EXE_*` solo lo define cargo para los binarios del **propio**
/// paquete, y el mock vive en otro. Se localiza junto al ejecutable del test y,
/// si todavía no está construido, se construye una sola vez.
pub fn ruta_mock() -> PathBuf {
    static MOCK: LazyLock<PathBuf> = LazyLock::new(|| {
        let mut dir = std::env::current_exe().unwrap();
        dir.pop();
        if dir.ends_with("deps") {
            dir.pop();
        }
        let binario = dir.join("sb-plugin-mock");
        if !binario.is_file() {
            let release = dir.file_name() == Some(OsStr::new("release"));
            let mut cargo = std::process::Command::new(env!("CARGO"));
            cargo.args(["build", "-p", "sb-plugin-mock"]);
            if release {
                cargo.arg("--release");
            }
            assert!(
                cargo.status().unwrap().success(),
                "no se pudo construir el plugin mock"
            );
        }
        assert!(
            binario.is_file(),
            "no se encontró el binario del plugin mock en {}",
            binario.display()
        );
        binario
    });

    MOCK.clone()
}

/// Añade un byte al final de un archivo: es la forma más barata de simular un
/// binario que ha cambiado desde que se registró.
pub fn alterar(ruta: &Path) {
    let mut bytes = std::fs::read(ruta).unwrap();
    bytes.push(0);
    std::fs::write(ruta, bytes).unwrap();
}

/// Interpreta la salida estándar como JSON. Falla con el texto completo si no
/// lo es: en `--format json` eso es justo lo que hay que ver.
pub fn json_de(stdout: &[u8]) -> serde_json::Value {
    let texto = String::from_utf8_lossy(stdout);
    serde_json::from_str(&texto)
        .unwrap_or_else(|e| panic!("stdout no es JSON válido ({e}):\n---\n{texto}\n---"))
}
