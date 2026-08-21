//! Resolución de secretos: convierte una [`SecretRef`] en su valor.
//!
//! # Por qué vive aquí y no en cada plugin
//!
//! El núcleo es el único que toca las fuentes de secretos —entorno, archivo,
//! llavero del sistema o comando externo—. El plugin recibe el valor ya
//! resuelto por el canal gRPC autenticado y nunca sabe de dónde salió. La
//! política de secretos queda así en un solo sitio auditable en vez de
//! reinventarse, con distinto criterio, en cada plugin.
//!
//! # Los errores no filtran
//!
//! Ningún [`SecretError`] contiene el valor leído, ni la salida del comando
//! ejecutado (ni `stdout` ni `stderr`), ni los bytes que el llavero devolvió.
//! Un error que filtra la credencial que no pudo interpretar es peor que
//! inútil: acaba en un log, en un ticket y en una captura de pantalla. Las
//! variantes de abajo nombran el *origen* del secreto (una ruta, una variable,
//! un programa), que es lo que el operador necesita para arreglarlo, y nunca
//! su contenido.

use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::process::{Command, Stdio};

use sb_crypto::Secret;
use zeroize::Zeroize as _;

use crate::model::SecretRef;

/// Usuario que se asume cuando la entrada del llavero no lleva `servicio/usuario`.
///
/// Quien provisione la entrada a mano necesita saberlo:
/// `secret-tool store --label=… service <servicio> username shieldbk`.
const USUARIO_POR_DEFECTO: &str = "shieldbk";

/// Máscara de los permisos de grupo y de «otros».
///
/// Cualquier bit encendido aquí significa que alguien que no es el dueño puede
/// leer, escribir o ejecutar el archivo.
const PERMISOS_AJENOS: u32 = 0o077;

/// Bits de permiso dentro del `st_mode` que devuelve `stat(2)`.
///
/// [`std::fs::Permissions::mode`] incluye también el tipo de archivo
/// (`0o100000` para un fichero regular); sin esta máscara el modo que se
/// muestra en el error no se parecería al que el operador pasó a `chmod`.
const BITS_DE_PERMISO: u32 = 0o7777;

/// Fallo al obtener el valor de un secreto.
///
/// **Ninguna variante contiene el secreto.** Todas nombran su origen —una
/// ruta, una variable de entorno, un programa, una entrada del llavero— porque
/// es lo que hace falta para arreglar el problema, y ninguna incluye el valor
/// leído ni la salida de un comando, que podría llevarlo dentro. Esto vale
/// tanto para `Display` como para el `Debug` derivado: todos los campos son
/// cadenas construidas aquí, nunca datos que vengan de la fuente.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// La variable de entorno referenciada no está definida en el proceso.
    #[error("la variable de entorno «{0}» no está definida")]
    VariableAusente(String),

    /// El archivo no se pudo abrir o leer.
    ///
    /// `motivo` es el mensaje del sistema operativo (por ejemplo «No such file
    /// or directory»): describe el fallo de E/S, nunca el contenido.
    #[error("no se pudo leer el secreto de «{ruta}»: {motivo}")]
    LecturaFallo {
        /// Ruta del archivo que se intentó leer.
        ruta: String,
        /// Mensaje del sistema operativo.
        motivo: String,
    },

    /// El archivo es accesible para el grupo o para el resto del mundo.
    #[error(
        "el archivo de secreto «{ruta}» tiene permisos {modo:04o} y es accesible para \
         el grupo o para otros; corrígelo con «chmod 600 {ruta}», o usa \
         `file_insecure` si lo monta un orquestador"
    )]
    PermisosDemasiadoAbiertos {
        /// Ruta del archivo rechazado.
        ruta: String,
        /// Permisos encontrados, en octal.
        modo: u32,
    },

    /// La referencia `command` no trae ni siquiera el programa a ejecutar.
    #[error("la referencia «command» está vacía: falta el programa a ejecutar")]
    ComandoVacio,

    /// El comando no se pudo lanzar, o terminó con un código distinto de cero.
    ///
    /// El mensaje nombra el programa —que ya está escrito en el fichero de
    /// configuración— pero **no** su salida: un comando que falla puede haber
    /// escrito el secreto en `stdout` antes de fallar, o haberlo volcado en
    /// `stderr` junto al diagnóstico. El motivo concreto (código de salida o
    /// error de `exec`) se registra por `tracing`, donde no viaja el valor.
    #[error(
        "el comando «{comando}» no se pudo ejecutar o terminó con error; \
         su salida se omite a propósito porque podría contener el secreto"
    )]
    ComandoFallo {
        /// Programa que se intentó ejecutar (`argv[0]`), sin sus argumentos.
        comando: String,
    },

    /// El llavero del sistema no devolvió la entrada.
    ///
    /// `motivo` es una descripción fija elegida aquí a partir de la variante
    /// de error del llavero, no el `Display` ni el `Debug` de la biblioteca:
    /// algunas de sus variantes llevan dentro los bytes crudos de la
    /// credencial.
    #[error("no se pudo leer la entrada «{entrada}» del llavero: {motivo}")]
    KeyringFallo {
        /// Entrada solicitada, en formato `servicio/usuario`.
        entrada: String,
        /// Descripción del fallo, sin datos de la credencial.
        motivo: String,
    },

    /// El valor obtenido no es texto UTF-8 válido.
    ///
    /// No se dice qué bytes fallaron ni en qué posición: eso ya sería una
    /// filtración parcial del secreto.
    #[error("el secreto no es UTF-8 válido")]
    NoEsUtf8,
}

/// Obtiene el valor de un secreto.
///
/// Solo el núcleo llama a esto. El plugin recibe el resultado por el canal
/// autenticado y nunca sabe de dónde salió.
///
/// El valor vuelve envuelto en [`Secret`], que se borra de memoria al
/// destruirse y no implementa `Debug` ni `Display`.
///
/// # Errors
///
/// Devuelve [`SecretError`] si la fuente no existe, no se puede leer, tiene
/// permisos demasiado abiertos o no contiene texto UTF-8. Ningún error incluye
/// el valor del secreto.
pub fn resolver(referencia: &SecretRef) -> Result<Secret<String>, SecretError> {
    match referencia {
        SecretRef::Env(nombre) => desde_entorno(nombre),
        SecretRef::File(ruta) => desde_archivo(ruta, Permisos::Exigidos),
        SecretRef::FileInsecure(ruta) => desde_archivo(ruta, Permisos::Ignorados),
        SecretRef::Keyring(entrada) => desde_llavero(entrada),
        SecretRef::Command(argv) => desde_comando(argv),
    }
}

/// Si un archivo de secreto tiene que demostrar permisos restrictivos.
#[derive(Clone, Copy)]
enum Permisos {
    /// Se rechaza cualquier acceso de grupo o de otros.
    Exigidos,
    /// Se acepta lo que haya y se avisa. Ver [`SecretRef::FileInsecure`].
    Ignorados,
}

/// Lee el secreto de una variable de entorno del proceso.
///
/// El valor **no** se recorta: a diferencia de un archivo, que un editor cierra
/// con `\n`, una variable de entorno vale exactamente lo que el operador
/// exportó, y recortarla podría estropear en silencio una contraseña.
fn desde_entorno(nombre: &str) -> Result<Secret<String>, SecretError> {
    match std::env::var(nombre) {
        Ok(valor) => Ok(Secret::new(valor)),
        Err(std::env::VarError::NotPresent) => Err(SecretError::VariableAusente(nombre.to_owned())),
        // `VarError::NotUnicode` lleva dentro el valor y lo imprime en su
        // `Display`. Se descarta aquí para que no llegue al mensaje de error.
        Err(std::env::VarError::NotUnicode(_)) => Err(SecretError::NoEsUtf8),
    }
}

/// Lee el secreto del contenido de un archivo.
///
/// Los permisos se comprueban sobre el descriptor ya abierto, no sobre la ruta:
/// mirar con `stat` y abrir después deja una ventana en la que alguien puede
/// cambiar el archivo entre las dos operaciones.
fn desde_archivo(ruta: &str, permisos: Permisos) -> Result<Secret<String>, SecretError> {
    let fallo = |motivo: &std::io::Error| SecretError::LecturaFallo {
        ruta: ruta.to_owned(),
        motivo: motivo.to_string(),
    };

    let mut archivo = std::fs::File::open(ruta).map_err(|e| fallo(&e))?;
    let modo = archivo
        .metadata()
        .map_err(|e| fallo(&e))?
        .permissions()
        .mode()
        & BITS_DE_PERMISO;

    match permisos {
        Permisos::Exigidos if modo & PERMISOS_AJENOS != 0 => {
            return Err(SecretError::PermisosDemasiadoAbiertos {
                ruta: ruta.to_owned(),
                modo,
            });
        }
        Permisos::Exigidos => {}
        Permisos::Ignorados => tracing::warn!(
            ruta = %ruta,
            modo = %format!("{modo:04o}"),
            "secreto leído sin comprobar permisos (`file_insecure`); \
             prefiere `defaultMode: 0400` en el volumen que lo monta"
        ),
    }

    let mut bytes = Vec::new();
    let leido = archivo.read_to_end(&mut bytes).map_err(|e| fallo(&e));
    let resultado = leido.and_then(|_| {
        std::str::from_utf8(&bytes)
            .map(|texto| recortar_saltos_finales(texto).to_owned())
            .map_err(|_| SecretError::NoEsUtf8)
    });
    // El buffer intermedio tuvo el secreto en claro; se borra aquí porque `Vec`
    // no lo hace al destruirse.
    bytes.zeroize();

    resultado.map(Secret::new)
}

/// Lee el secreto del llavero del sistema.
///
/// `entrada` es `servicio/usuario`; sin barra, el servicio es la entrada entera
/// y el usuario es [`USUARIO_POR_DEFECTO`].
///
/// # Dentro de un contenedor no funciona
///
/// El llavero se consulta por el Secret Service de D-Bus, que un contenedor no
/// tiene: no hay bus de sesión ni agente que lo sirva. Ahí se usan `env` o
/// `file` —normalmente `file_insecure` sobre el secreto que monta el
/// orquestador—. Tampoco funciona por SSH sin sesión gráfica, ni desde `cron`,
/// por la misma razón: el llavero está cerrado y nadie puede desbloquearlo.
fn desde_llavero(entrada: &str) -> Result<Secret<String>, SecretError> {
    let (servicio, usuario) = entrada
        .split_once('/')
        .unwrap_or((entrada, USUARIO_POR_DEFECTO));

    let fallo = |motivo: &str| SecretError::KeyringFallo {
        entrada: entrada.to_owned(),
        motivo: motivo.to_owned(),
    };

    let credencial =
        keyring::Entry::new(servicio, usuario).map_err(|e| fallo(&motivo_del_llavero(&e)))?;
    let valor = credencial
        .get_password()
        .map_err(|e| fallo(&motivo_del_llavero(&e)))?;

    Ok(Secret::new(valor))
}

/// Traduce un error del llavero a una descripción que no lleva datos dentro.
///
/// No se usa el `Display` ni el `Debug` de `keyring`: su variante `BadEncoding`
/// guarda los bytes crudos de la credencial y el `Debug` derivado los
/// imprimiría enteros.
fn motivo_del_llavero(error: &keyring::Error) -> String {
    let descripcion = match error {
        keyring::Error::NoEntry => "la entrada no existe en el llavero",
        keyring::Error::NoDefaultStore => {
            "no hay llavero disponible; dentro de un contenedor no existe D-Bus, usa `env` o `file`"
        }
        keyring::Error::NoStorageAccess(_) => "el llavero está bloqueado o no es accesible",
        keyring::Error::BadEncoding(_) => "el valor guardado en el llavero no es UTF-8",
        keyring::Error::Ambiguous(_) => "la entrada coincide con más de una credencial",
        keyring::Error::Invalid(atributo, _) => {
            return format!("el atributo «{atributo}» de la entrada no es válido");
        }
        _ => "fallo del llavero del sistema",
    };
    descripcion.to_owned()
}

/// Ejecuta un comando y toma su `stdout` como secreto.
///
/// **Nunca hay shell.** El programa y sus argumentos van por separado a
/// [`Command`], así que un argumento con `;`, `$(…)` o `&&` dentro es texto
/// literal para el programa y no otra orden. La inyección de comandos queda
/// eliminada por construcción, no filtrada por una lista de caracteres
/// prohibidos.
///
/// `stdout` y `stderr` se capturan —no se heredan— para que el secreto no
/// aparezca en la terminal ni en los logs de `shieldbk` si el comando lo
/// escribe donde no debe. `stdin` se cierra para que un programa que quiera
/// preguntar algo falle en vez de quedarse colgado esperando.
fn desde_comando(argv: &[String]) -> Result<Secret<String>, SecretError> {
    let (programa, argumentos) = argv.split_first().ok_or(SecretError::ComandoVacio)?;

    let salida = Command::new(programa)
        .args(argumentos)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| {
            // El error de `exec` (ENOENT, EACCES…) no puede contener el
            // secreto: el programa ni siquiera llegó a arrancar. Va al log,
            // donde sirve para diagnosticar, y no al error, cuya forma es fija.
            tracing::warn!(programa = %programa, error = %e, "no se pudo ejecutar el comando de secreto");
            SecretError::ComandoFallo {
                comando: programa.clone(),
            }
        })?;

    let mut bytes = salida.stdout;
    // `stderr` no se mira siquiera: el comando pudo volcar ahí el secreto
    // junto al diagnóstico. Se borra sin leerlo.
    let mut descartado = salida.stderr;
    descartado.zeroize();

    let resultado = if salida.status.success() {
        std::str::from_utf8(&bytes)
            .map(|texto| recortar_saltos_finales(texto).to_owned())
            .map_err(|_| SecretError::NoEsUtf8)
    } else {
        tracing::warn!(
            programa = %programa,
            estado = %salida.status,
            "el comando de secreto terminó con error; su salida se descarta sin leerla"
        );
        Err(SecretError::ComandoFallo {
            comando: programa.clone(),
        })
    };
    bytes.zeroize();

    resultado.map(Secret::new)
}

/// Recorta los saltos de línea del final, y solo eso.
///
/// Un editor añade `\n` al guardar y `echo` lo pone siempre, así que un
/// secreto de archivo o de comando casi nunca termina donde el usuario cree.
/// Los espacios sí se respetan, incluidos los del final: una contraseña puede
/// llevarlos y recortarlos sería corromperla en silencio.
fn recortar_saltos_finales(texto: &str) -> &str {
    texto.trim_end_matches(['\n', '\r'])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// Escribe un fichero de secreto con los permisos indicados.
    fn fichero(dir: &std::path::Path, nombre: &str, contenido: &[u8], modo: u32) -> String {
        use std::os::unix::fs::PermissionsExt;
        let ruta = dir.join(nombre);
        let mut f = std::fs::File::create(&ruta).unwrap();
        f.write_all(contenido).unwrap();
        drop(f);
        std::fs::set_permissions(&ruta, std::fs::Permissions::from_mode(modo)).unwrap();
        ruta.to_string_lossy().into_owned()
    }

    #[test]
    fn resuelve_desde_una_variable_de_entorno_existente() {
        // PATH siempre existe y no hace falta modificar el entorno, que en
        // edition 2024 requeriría `unsafe`.
        let r = resolver(&SecretRef::Env("PATH".into())).unwrap();
        assert!(!r.expose().is_empty());
    }

    #[test]
    fn una_variable_ausente_da_un_error_que_la_nombra() {
        let err = resolver(&SecretRef::Env("SB_NO_EXISTE_XYZ_123".into()))
            .err()
            .unwrap();
        assert!(err.to_string().contains("SB_NO_EXISTE_XYZ_123"));
    }

    #[test]
    fn resuelve_desde_un_archivo_con_permisos_correctos() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = fichero(dir.path(), "secreto", b"del-archivo\n", 0o600);
        let r = resolver(&SecretRef::File(ruta)).unwrap();
        assert_eq!(
            r.expose(),
            "del-archivo",
            "el salto de línea final se recorta"
        );
    }

    #[test]
    fn se_recortan_los_saltos_finales_pero_no_los_espacios_internos() {
        // Un editor añade \n al guardar; una contraseña puede llevar espacios.
        let dir = tempfile::tempdir().unwrap();
        let ruta = fichero(dir.path(), "s", b"con espacios dentro  \r\n", 0o600);
        assert_eq!(
            resolver(&SecretRef::File(ruta)).unwrap().expose(),
            "con espacios dentro  "
        );
    }

    #[test]
    fn se_rechaza_un_archivo_legible_por_el_grupo() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = fichero(dir.path(), "s", b"x", 0o640);
        assert!(matches!(
            resolver(&SecretRef::File(ruta)).err().unwrap(),
            SecretError::PermisosDemasiadoAbiertos { .. }
        ));
    }

    #[test]
    fn se_rechaza_un_archivo_legible_por_todo_el_mundo() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = fichero(dir.path(), "s", b"x", 0o644);
        let err = resolver(&SecretRef::File(ruta)).err().unwrap();
        assert!(matches!(err, SecretError::PermisosDemasiadoAbiertos { .. }));
        assert!(
            err.to_string().contains("chmod"),
            "debe decir cómo arreglarlo"
        );
    }

    #[test]
    fn un_secreto_montado_por_el_orquestador_se_acepta_con_el_opt_out() {
        // Docker monta /run/secrets con 0444 y Kubernetes los suyos con 0644.
        // Rechazarlos sin alternativa impediría el caso de uso más común en
        // contenedor; relajar la comprobación por defecto sería peor.
        let dir = tempfile::tempdir().unwrap();
        let ruta = fichero(dir.path(), "montado", b"del-orquestador\n", 0o444);

        assert!(
            resolver(&SecretRef::File(ruta.clone())).is_err(),
            "sin opt-out se rechaza"
        );
        assert_eq!(
            resolver(&SecretRef::FileInsecure(ruta)).unwrap().expose(),
            "del-orquestador"
        );
    }

    #[test]
    fn el_opt_out_sigue_fallando_si_el_archivo_no_existe() {
        // Relaja los permisos, no la existencia.
        assert!(resolver(&SecretRef::FileInsecure("/no/existe/nada".into())).is_err());
    }

    #[test]
    fn resuelve_ejecutando_un_comando() {
        let r = resolver(&SecretRef::Command(vec![
            "/bin/echo".into(),
            "desde-comando".into(),
        ]))
        .unwrap();
        assert_eq!(r.expose(), "desde-comando");
    }

    #[test]
    fn un_comando_que_falla_da_error() {
        assert!(matches!(
            resolver(&SecretRef::Command(vec!["/bin/false".into()]))
                .err()
                .unwrap(),
            SecretError::ComandoFallo { .. }
        ));
    }

    #[test]
    fn un_comando_vacio_se_rechaza() {
        assert!(matches!(
            resolver(&SecretRef::Command(vec![])).err().unwrap(),
            SecretError::ComandoVacio
        ));
    }

    #[test]
    fn un_comando_inexistente_da_error_y_no_panico() {
        assert!(resolver(&SecretRef::Command(vec!["/no/existe/comando".into()])).is_err());
    }

    #[test]
    fn el_comando_no_pasa_por_un_shell() {
        // Si hubiera shell, esto ejecutaría dos comandos o interpretaría el
        // punto y coma. Sin shell, «;» y «echo» son argumentos literales de
        // /bin/echo. Es lo que elimina por construcción la inyección.
        let r = resolver(&SecretRef::Command(vec![
            "/bin/echo".into(),
            "uno; echo dos".into(),
        ]))
        .unwrap();
        assert_eq!(r.expose(), "uno; echo dos");
    }

    #[test]
    fn el_error_nunca_incluye_el_valor_del_secreto() {
        // Un error que filtra la credencial que no pudo leer es peor que inútil.
        let dir = tempfile::tempdir().unwrap();
        let ruta = fichero(dir.path(), "s", b"CONTENIDO-ULTRASECRETO", 0o644);
        let texto = resolver(&SecretRef::File(ruta)).err().unwrap().to_string();
        assert!(!texto.contains("ULTRASECRETO"));
    }

    #[test]
    fn el_error_de_comando_no_incluye_su_salida() {
        use std::os::unix::fs::PermissionsExt;

        // Un comando que falla puede haber escrito el secreto en stdout antes
        // de fallar, o volcarlo en stderr.
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("fuga.sh");
        std::fs::write(
            &script,
            b"#!/bin/sh\necho SECRETO-EN-STDOUT\necho SECRETO-EN-STDERR >&2\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();

        let texto = resolver(&SecretRef::Command(vec![
            script.to_string_lossy().into_owned(),
        ]))
        .err()
        .unwrap()
        .to_string();
        assert!(!texto.contains("SECRETO-EN-STDOUT"));
        assert!(!texto.contains("SECRETO-EN-STDERR"));
    }

    #[test]
    fn un_secreto_que_no_es_utf8_da_error_claro() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = fichero(dir.path(), "binario", &[0xff, 0xfe, 0xfd], 0o600);
        assert!(resolver(&SecretRef::File(ruta)).is_err());
    }

    #[test]
    fn un_secreto_vacio_se_acepta_pero_es_vacio() {
        // No es tarea de esta capa decidir si una contraseña vacía es válida:
        // eso lo dirá el plugin al usarla. Aquí solo se lee lo que hay.
        let dir = tempfile::tempdir().unwrap();
        let ruta = fichero(dir.path(), "vacio", b"", 0o600);
        assert_eq!(resolver(&SecretRef::File(ruta)).unwrap().expose(), "");
    }
}
