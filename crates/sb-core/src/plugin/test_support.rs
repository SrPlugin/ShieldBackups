//! Utilidades compartidas por los tests de este módulo.
//!
//! Los tests del proceso y los del cliente arrancan el mismo binario, y
//! localizarlo tiene más miga de la que parece. Vive aquí para que la receta
//! sea una sola: si mañana cambia dónde deja cargo los binarios, cambia en un
//! sitio.

/// Ruta del binario del plugin mock.
///
/// `CARGO_BIN_EXE_*` solo lo define cargo para los binarios del **propio**
/// paquete, y el mock vive en otro. Como estos tests son unitarios —viven en
/// `src/`, no en `tests/`—, su ejecutable está siempre en
/// `target/<perfil>/deps/`, así que se sube un nivel para llegar al
/// `target/<perfil>/` donde cargo deja los binarios. Si el mock todavía no
/// está construido se construye una sola vez, para que este fichero se pueda
/// ejecutar aislado con `cargo test -p sb-core process`.
pub(crate) fn ruta_mock() -> std::path::PathBuf {
    use std::ffi::OsStr;
    use std::path::PathBuf;
    use std::sync::LazyLock;

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
            let estado = cargo.status().unwrap();
            assert!(estado.success(), "no se pudo construir el plugin mock");
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
