//! Encontrar en el destino los artefactos que son de un target.
//!
//! `verify <target>` sin artefacto y `storage gc <target>` necesitan lo mismo:
//! acotar el destino a la parte que pertenece a un target. El destino no sabe
//! qué es un target —solo tiene claves—, así que lo único que hay para acotar
//! es la propia plantilla con la que se nombran los artefactos.
//!
//! De ahí sale la regla de este módulo: **el prefijo de un target es su
//! plantilla hasta el primer marcador que dependa del momento del backup**. Con
//! la plantilla por defecto, `{target}/{yyyy}/{mm}/{dd}/…`, eso da
//! `produccion/`, que es exactamente la carpeta del target. Con una plantilla
//! que empezara por la fecha no habría prefijo posible, y entonces el prefijo
//! vacío —listar todo— es la respuesta honesta: mejor mirar de más que
//! silenciar artefactos que sí eran del target.

use sb_config::{Defaults, Target};
use sb_core::model::manifest_key_for;
use sb_core::plugin::PluginClient;
use sb_proto::storage_client::StorageClient;
use sb_proto::{AbortIncompleteRequest, ArtifactMeta, ListRequest};

use crate::error::CliError;

/// El prefijo bajo el que viven los artefactos de `target`.
#[must_use]
pub fn prefijo_de(target: &Target, defaults: &Defaults) -> String {
    prefijo_de_plantilla(
        target.plantilla_efectiva(defaults),
        &target.name,
        &target.engine,
        &target.storage,
    )
}

/// La parte fija de una plantilla, con los marcadores que sí se conocen ya
/// sustituidos.
fn prefijo_de_plantilla(plantilla: &str, target: &str, engine: &str, storage: &str) -> String {
    let mut prefijo = String::new();
    let mut resto = plantilla;

    loop {
        let Some(abre) = resto.find('{') else {
            // No queda ningún marcador: lo que sobra de la plantilla es fijo y
            // forma parte del prefijo. Sin esta rama, una plantilla sin
            // marcadores daría un prefijo vacío y se listaría el destino
            // entero.
            prefijo.push_str(resto);
            return prefijo;
        };

        let (literal, desde_llave) = resto.split_at(abre);
        prefijo.push_str(literal);

        let Some(cierra) = desde_llave.find('}') else {
            // Una llave sin cerrar es una errata de la plantilla, y `render` la
            // rechazará cuando toque. Aquí solo hay que dejar de mirar.
            return prefijo;
        };
        let marcador = &desde_llave[1..cierra];
        match marcador {
            "target" => prefijo.push_str(target),
            "engine" => prefijo.push_str(engine),
            "storage" => prefijo.push_str(storage),
            // Un marcador que depende de cuándo se hizo el backup no se puede
            // conocer al listar, y uno desconocido no se puede sustituir: en
            // ambos casos el prefijo termina aquí.
            _ => return prefijo,
        }
        resto = &desde_llave[cierra + 1..];
    }
}

/// Los artefactos del destino bajo `prefijo`, **sin los manifiestos**.
///
/// Los manifiestos se filtran porque no son artefactos sino sus etiquetas:
/// incluirlos haría que `verify` intentara buscarle un manifiesto al
/// manifiesto y contara el doble de comprobaciones de las que hay.
///
/// # Errors
/// Devuelve [`CliError::Operacion`] si el destino no puede listar.
pub async fn listar(storage: &PluginClient, prefijo: &str) -> Result<Vec<ArtifactMeta>, CliError> {
    let mut grpc = StorageClient::new(storage.channel());
    let respuesta = grpc
        .list(ListRequest {
            prefix: prefijo.to_owned(),
        })
        .await
        .map_err(|status| {
            CliError::operacion(format!(
                "el destino «{}» no pudo listar «{prefijo}»: {}",
                storage.name(),
                status.message()
            ))
        })?;

    let sufijo = manifest_key_for("");
    Ok(respuesta
        .into_inner()
        .artifacts
        .into_iter()
        .filter(|a| !a.key.ends_with(&sufijo))
        .collect())
}

/// Le pide al destino que aborte las subidas incompletas bajo `prefijo`.
///
/// Devuelve cuántas abortó.
///
/// # Errors
/// Devuelve [`CliError::Operacion`] si el destino rechaza la petición.
pub async fn abortar_incompletas(storage: &PluginClient, prefijo: &str) -> Result<u32, CliError> {
    let mut grpc = StorageClient::new(storage.channel());
    let respuesta = grpc
        .abort_incomplete(AbortIncompleteRequest {
            prefix: prefijo.to_owned(),
        })
        .await
        .map_err(|status| {
            CliError::operacion(format!(
                "el destino «{}» no pudo abortar las subidas incompletas de «{prefijo}»: {}",
                storage.name(),
                status.message()
            ))
        })?;
    Ok(respuesta.into_inner().aborted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_plantilla_por_defecto_da_la_carpeta_del_target() {
        let prefijo = prefijo_de_plantilla(
            "{target}/{yyyy}/{mm}/{dd}/{target}-{timestamp}-{engine}.dump.zst.age",
            "produccion",
            "postgres",
            "r2",
        );
        assert_eq!(prefijo, "produccion/");
    }

    #[test]
    fn se_sustituyen_todos_los_marcadores_fijos_antes_de_cortar() {
        let prefijo = prefijo_de_plantilla(
            "{storage}/{engine}/{target}/{timestamp}.age",
            "prod",
            "postgres",
            "r2",
        );
        assert_eq!(prefijo, "r2/postgres/prod/");
    }

    #[test]
    fn una_plantilla_que_empieza_por_la_fecha_no_tiene_prefijo() {
        // Y eso es lo correcto: listar de más y filtrar es recuperable;
        // silenciar artefactos del target no lo es.
        assert_eq!(
            prefijo_de_plantilla("{yyyy}/{target}.age", "prod", "e", "s"),
            ""
        );
    }

    #[test]
    fn una_plantilla_sin_marcadores_es_su_propio_prefijo() {
        assert_eq!(
            prefijo_de_plantilla("fijo/artefacto.age", "prod", "e", "s"),
            "fijo/artefacto.age"
        );
    }

    #[test]
    fn una_llave_sin_cerrar_corta_el_prefijo_en_vez_de_entrar_en_bucle() {
        assert_eq!(
            prefijo_de_plantilla("copias/{target/x", "prod", "e", "s"),
            "copias/"
        );
    }

    #[test]
    fn un_marcador_desconocido_corta_el_prefijo() {
        // `render` dará el error explicándolo; aquí no hay nada que sustituir.
        assert_eq!(
            prefijo_de_plantilla("copias/{semana}/x", "prod", "e", "s"),
            "copias/"
        );
    }
}
