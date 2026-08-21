//! `shieldbk storage gc <target>`.
//!
//! Una subida que se corta a mitad —el proceso muere, la red se cae— no
//! desaparece sola: en un destino con subidas multipart quedan las partes ya
//! escritas, invisibles al listado y **facturables**. Nadie las ve y todo el
//! mundo las paga, hasta que alguien mira la factura y no entiende por qué el
//! bucket «vacío» cuesta dinero.
//!
//! Este comando es la única forma de barrerlas. Se acota al prefijo del target
//! y no al bucket entero a propósito: un destino puede tener más cosas dentro
//! que los backups de este `shieldbk`, y abortar subidas ajenas sería peor que
//! el problema que se venía a resolver.

use crate::artifacts;
use crate::context::Contexto;
use crate::error::CliError;
use crate::output::Informe;
use crate::plugins::{self, Papel};

/// # Errors
/// Devuelve [`CliError::Config`] si el target no existe, [`CliError::Plugin`]
/// si el destino no arranca y [`CliError::Operacion`] si el destino rechaza la
/// limpieza.
pub async fn gc(ctx: &Contexto, target: &str) -> Result<Informe, CliError> {
    let target = ctx.target(target)?;
    let prefijo = artifacts::prefijo_de(target, &ctx.config.defaults);

    let destino = plugins::arrancar_para(ctx, target, Papel::Destino).await?;
    let resultado = artifacts::abortar_incompletas(&destino, &prefijo).await;
    plugins::cerrar(destino).await;

    let abortadas = resultado?;
    tracing::info!(target = %target.name, %prefijo, abortadas, "limpieza del destino terminada");

    Ok(Informe::new(
        format!(
            "{}: {abortadas} subidas incompletas abortadas bajo «{prefijo}»",
            target.name
        ),
        serde_json::json!({
            "comando": "storage gc",
            "target": target.name,
            "prefijo": prefijo,
            "abortadas": abortadas,
        }),
    ))
}
