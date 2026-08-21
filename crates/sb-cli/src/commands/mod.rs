//! El despacho, y solo el despacho.
//!
//! Este archivo existe para poder responder a «¿dónde está el código de
//! `verify`?» sin leer nada más. Cada subcomando vive en su propio archivo y
//! ninguno necesita conocer a los demás; lo único común —cargar el contexto y
//! limitar cuántos targets se procesan a la vez— está en [`concurrencia`],
//! porque es una decisión de la herramienta y no de ningún comando concreto.

mod backup;
mod concurrencia;
mod doctor;
mod plugin;
mod restore;
mod storage;
mod verify;

use crate::cli::{AccionPlugin, AccionStorage, Cli, Comando};
use crate::context::Contexto;
use crate::error::CliError;
use crate::output::Informe;

/// Ejecuta lo que se pidió y devuelve lo que hay que contar.
///
/// # Errors
/// Devuelve [`CliError`] con la clase del fallo, que es lo que decide el código
/// de salida del proceso.
pub async fn ejecutar(cli: &Cli) -> Result<Informe, CliError> {
    // La configuración se carga para todos los comandos, incluidos los de
    // `plugin`: el directorio de plugins y el lockfile salen de ahí, así que
    // sin ella no se sabría ni dónde mirar. Lo que cambia entre unos y otros es
    // cuánto le exigen (ver [`contexto`]).
    let ctx = contexto(cli)?;

    match &cli.comando {
        Comando::Backup { target } => backup::ejecutar(&ctx, target.as_deref()).await,
        Comando::Restore {
            target,
            artifact,
            identity,
        } => restore::ejecutar(&ctx, target, artifact, identity).await,
        Comando::Verify { target, artifact } => {
            verify::ejecutar(&ctx, target, artifact.as_deref()).await
        }
        Comando::Doctor { target } => doctor::ejecutar(&ctx, target.as_deref()).await,
        Comando::Plugin { accion } => match accion {
            AccionPlugin::List => plugin::listar(&ctx),
            AccionPlugin::Docs { plugin: nombre } => plugin::docs(&ctx, nombre).await,
            AccionPlugin::Verify => plugin::verificar(&ctx),
            AccionPlugin::Lock => plugin::lock(&ctx),
        },
        Comando::Storage { accion } => match accion {
            AccionStorage::Gc { target } => storage::gc(&ctx, target).await,
        },
    }
}

/// El contexto que le toca a cada comando.
///
/// Los de `plugin` solo usan la sección `[plugins]`: registrar el hash de un
/// binario, comprobarlo o listarlo no tiene nada que ver con qué bases de
/// datos se respaldan, y es lo que se hace **antes** de decidirlo —al
/// instalar, o al construir una imagen—. Los demás sí trabajan sobre targets y
/// tienen que seguir exigiéndolos: un `backup` que arrancara con una
/// configuración vacía no haría nada y terminaría diciendo que todo fue bien,
/// que es peor que negarse.
///
/// El caso general es exigirlos, así que un comando nuevo lo hará por defecto.
fn contexto(cli: &Cli) -> Result<Contexto, CliError> {
    match &cli.comando {
        Comando::Plugin { .. } => Contexto::cargar_sin_exigir_targets(cli),
        _ => Contexto::cargar(cli),
    }
}
