//! Poner un plugin en marcha, con la comprobación que va delante de todas.
//!
//! Un plugin es un proceso al que `shieldbk` le entrega la contraseña de la
//! base de datos y las credenciales del almacenamiento. Eso convierte «¿qué
//! binario es este?» en la pregunta más importante del arranque, y por eso
//! **nada de este módulo ejecuta un binario sin haberlo verificado antes
//! contra el lockfile**. La comprobación vive aquí y no en cada comando
//! precisamente porque olvidarla una sola vez bastaría para anularla.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sb_config::{ConfigTable, Target, validar_y_convertir};
use sb_core::lockfile::Lockfile;
use sb_core::plugin::{Capacidad, PluginClient};

use crate::context::{Contexto, nombre_de_binario};
use crate::error::CliError;

/// Qué papel juega un plugin en un target: de dónde salen los bytes o adónde
/// van.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Papel {
    Motor,
    Destino,
}

impl Papel {
    /// La sección de la configuración de la que salen sus campos. Es también
    /// lo que aparece en los mensajes de validación.
    pub const fn seccion(self) -> &'static str {
        match self {
            Self::Motor => "engine",
            Self::Destino => "storage",
        }
    }

    const fn capacidad(self) -> Capacidad {
        match self {
            Self::Motor => Capacidad::Engine,
            Self::Destino => Capacidad::Storage,
        }
    }

    fn nombre_en(self, target: &Target) -> &str {
        match self {
            Self::Motor => &target.engine,
            Self::Destino => &target.storage,
        }
    }

    fn configuracion_en(self, target: &Target) -> &ConfigTable {
        match self {
            Self::Motor => &target.engine_config,
            Self::Destino => &target.storage_config,
        }
    }
}

/// Los binarios de plugin que hay en el directorio, en orden alfabético.
///
/// Un directorio que todavía no existe es un directorio sin plugins y no un
/// error: es el estado de una instalación recién hecha, y decírselo así a quien
/// ejecuta `plugin list` explica más que un fallo de E/S.
///
/// # Errors
/// Devuelve [`CliError::Plugin`] si el directorio existe pero no se puede leer.
pub fn binarios(dir: &Path) -> Result<Vec<(String, PathBuf)>, CliError> {
    let entradas = match std::fs::read_dir(dir) {
        Ok(entradas) => entradas,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(fuente) => {
            return Err(CliError::plugin(format!(
                "no se pudo leer el directorio de plugins «{}»: {fuente}",
                dir.display()
            )));
        }
    };

    let mut encontrados = Vec::new();
    for entrada in entradas {
        let entrada = entrada.map_err(|fuente| {
            CliError::plugin(format!(
                "no se pudo recorrer el directorio de plugins «{}»: {fuente}",
                dir.display()
            ))
        })?;
        let nombre_fichero = entrada.file_name().to_string_lossy().into_owned();
        let Some(nombre) = nombre_de_binario(&nombre_fichero) else {
            continue;
        };
        if entrada.path().is_file() {
            encontrados.push((nombre.to_owned(), entrada.path()));
        }
    }
    encontrados.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(encontrados)
}

/// Comprueba que el binario de `nombre` está donde debe y es el que se
/// registró.
///
/// # Errors
/// Devuelve [`CliError::Plugin`] si el binario no está —el mensaje dice dónde
/// se buscó— o si el lockfile no lo autoriza. El mensaje del lockfile llega
/// intacto: ya trae el `shieldbk plugin lock <nombre>` que hay que teclear.
pub fn verificar(ctx: &Contexto, nombre: &str) -> Result<PathBuf, CliError> {
    let ruta = ctx.ruta_de_plugin(nombre);
    if !ruta.is_file() {
        return Err(CliError::plugin(format!(
            "no se encontró el plugin «{nombre}»: se buscó en «{}». Instálalo ahí o cambia \
             `plugins.dir` en la configuración",
            ruta.display()
        )));
    }

    let lockfile = Lockfile::load(&ctx.ruta_lockfile)?;
    lockfile.verificar(nombre, &ruta)?;
    tracing::debug!(plugin = nombre, ruta = %ruta.display(), "binario verificado");
    Ok(ruta)
}

/// Arranca un plugin verificado, **sin configurarlo**.
///
/// Es lo que necesita `plugin docs`: un plugin vivo al que solo se le va a
/// preguntar qué campos acepta.
///
/// # Errors
/// Devuelve [`CliError::Plugin`] si el binario no pasa la verificación o si el
/// proceso no llega a hablar.
pub async fn arrancar(ctx: &Contexto, nombre: &str) -> Result<PluginClient, CliError> {
    let ruta = verificar(ctx, nombre)?;
    Ok(PluginClient::start(nombre, &ruta).await?)
}

/// Arranca el plugin que juega `papel` en `target`, ya configurado y con su
/// capacidad comprobada.
///
/// El orden importa y es el mismo en las cuatro operaciones: verificar el
/// binario, arrancarlo, **preguntarle su esquema**, validar contra él lo que
/// dice la configuración —resolviendo los secretos por el camino— y solo
/// entonces entregárselo. Validar contra el esquema del plugin y no contra una
/// lista en el núcleo es lo que permite que añadir un motor nuevo no obligue a
/// recompilar `shieldbk`.
///
/// # Errors
/// Devuelve [`CliError::Plugin`] si el plugin no arranca o no sabe hacer el
/// papel que se le pide, y [`CliError::Config`] si su configuración no encaja
/// con el esquema o un secreto no se pudo resolver.
pub async fn arrancar_para(
    ctx: &Contexto,
    target: &Target,
    papel: Papel,
) -> Result<PluginClient, CliError> {
    let nombre = papel.nombre_en(target);
    let cliente = arrancar(ctx, nombre).await?;

    // La capacidad se comprueba aquí y no al usarla: pedirle un volcado a un
    // plugin que solo sabe almacenar tiene que fallar al elegirlo, no a mitad
    // del backup.
    if let Err(fuente) = cliente.exigir_capacidad(papel.capacidad()) {
        let _ = cliente.shutdown().await;
        return Err(CliError::config(format!(
            "el target «{}» usa «{nombre}» como {}, pero {fuente}",
            target.name,
            papel.seccion()
        )));
    }

    match configurar(&cliente, target, papel).await {
        Ok(()) => Ok(cliente),
        Err(error) => {
            // Un plugin al que no se ha podido configurar no puede quedarse
            // vivo: es un proceso con material criptográfico de sesión al que
            // ya nadie va a pedirle nada.
            let _ = cliente.shutdown().await;
            Err(error)
        }
    }
}

/// Le pregunta el esquema, valida la configuración contra él y se la entrega.
async fn configurar(cliente: &PluginClient, target: &Target, papel: Papel) -> Result<(), CliError> {
    let esquema = cliente.schema().await?;
    let seccion = papel.seccion();
    let valores = validar_y_convertir(papel.configuracion_en(target), &esquema, seccion).map_err(
        |fuente| {
            CliError::config(format!(
                "la configuración de `{seccion}` del target «{}» no es válida: {fuente}",
                target.name
            ))
        },
    )?;

    // Lo que se registra es **cuántos** campos van, nunca cuáles ni sus
    // valores: entre ellos hay contraseñas.
    tracing::debug!(
        plugin = cliente.nombre(),
        papel = seccion,
        campos = valores.len(),
        "configurando plugin"
    );
    entregar(cliente, valores).await
}

/// La entrega en sí, aparte para que quede claro que el mapa —que lleva los
/// secretos ya resueltos— no pasa por ningún otro sitio.
async fn entregar(
    cliente: &PluginClient,
    valores: HashMap<String, sb_proto::Value>,
) -> Result<(), CliError> {
    Ok(cliente.configure(valores).await?)
}

/// Cierra un plugin sin dejar que su fallo tape el de la operación.
///
/// Un cierre que falla es una anotación en el log; el resultado del backup es
/// lo que el usuario vino a saber. Devolver el error del cierre haría que un
/// backup correcto pareciera roto.
pub async fn cerrar(cliente: PluginClient) {
    let nombre = cliente.nombre().to_owned();
    if let Err(fuente) = cliente.shutdown().await {
        tracing::warn!(plugin = %nombre, %fuente, "el plugin no se cerró limpiamente");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cada_papel_sabe_de_que_seccion_y_capacidad_habla() {
        assert_eq!(Papel::Motor.seccion(), "engine");
        assert_eq!(Papel::Destino.seccion(), "storage");
        assert_eq!(Papel::Motor.capacidad(), Capacidad::Engine);
        assert_eq!(Papel::Destino.capacidad(), Capacidad::Storage);
    }

    #[test]
    fn un_directorio_que_no_existe_es_un_directorio_sin_plugins() {
        // Es el estado de una instalación recién hecha, no un fallo.
        let vacio = binarios(Path::new("/no/existe/este/directorio"));
        assert!(matches!(vacio, Ok(v) if v.is_empty()));
    }

    #[test]
    fn solo_se_listan_los_ficheros_con_el_prefijo_del_proyecto() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("sb-plugin-zeta"), b"z").unwrap();
        std::fs::write(dir.path().join("sb-plugin-alfa"), b"a").unwrap();
        std::fs::write(dir.path().join("plugins.lock"), b"l").unwrap();
        std::fs::create_dir(dir.path().join("sb-plugin-dir")).unwrap();

        let encontrados = binarios(dir.path()).unwrap();
        let nombres: Vec<&str> = encontrados.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            nombres,
            vec!["alfa", "zeta"],
            "solo ficheros, y en orden estable"
        );
    }
}
