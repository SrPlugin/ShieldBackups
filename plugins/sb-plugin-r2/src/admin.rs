//! Listar, borrar y limpiar subidas incompletas.
//!
//! Los tres RPC administrativos del destino. Lo que tienen en común, y lo que
//! justifica que estén juntos, es que **los tres tienen que paginar o mentir**:
//! la API de S3 corta las respuestas y devuelve un marcador para seguir.
//!
//! ## Por qué la paginación no es un detalle
//!
//! `ListObjectsV2` devuelve como mucho 1000 claves por página. Un destino que
//! se quedara con la primera no daría un error: daría una lista **corta y
//! silenciosa**. Con ella, `verify --all` diría que todo está bien tras mirar
//! los mil primeros artefactos, y una retención borraría creyendo que no hay
//! nada más. Una lista truncada es peor que un fallo, porque un fallo se ve.
//!
//! Igual con `ListMultipartUploads`: las subidas que se dejan sin abortar no
//! aparecen al listar el bucket y se facturan indefinidamente, así que la
//! limpieza que solo mira la primera página deja pagando lo que no vio.

use aws_sdk_s3::primitives::DateTimeFormat;
use aws_sdk_s3::types::Object;
use sb_plugin_sdk::tonic::Status;

use crate::claves;
use crate::cliente::{Contexto, traducir};

/// Un artefacto tal y como lo ve `List`.
pub struct Artefacto {
    /// La clave **sin** el prefijo interno: es la que el núcleo usó al
    /// guardarlo y la única con la que puede volver a pedirlo.
    pub clave: String,
    pub tamano: u64,
    /// Fecha de última modificación en **ISO-8601 UTC** (RFC-3339), del estilo
    /// `2026-08-21T09:30:00Z`. Se elige este formato y no el epoch porque es el
    /// que el operador lee sin convertir nada, y porque ordena igual como texto
    /// que como fecha. Cadena vacía si R2 no la devolvió.
    pub modificado: String,
}

/// Todos los artefactos bajo `prefijo`, **paginando hasta el final**.
///
/// El prefijo llega ya completo —con el prefijo interno delante—; las claves
/// que salen van sin él.
///
/// # Errors
///
/// El motivo ya depurado si R2 falla en cualquiera de las páginas. Una página
/// que falla aborta el listado entero a propósito: devolver lo que se llevaba
/// sería exactamente la lista truncada que este módulo existe para evitar.
pub async fn listar(contexto: &Contexto, prefijo: &str) -> Result<Vec<Artefacto>, Status> {
    let mut encontrados = Vec::new();
    let mut token: Option<String> = None;
    let mut paginas = 0_u64;

    loop {
        let pagina = contexto
            .cliente
            .list_objects_v2()
            .bucket(&contexto.config.bucket)
            .prefix(prefijo)
            .set_continuation_token(token.clone())
            .send()
            .await
            .map_err(|e| traducir("ListObjectsV2", &e))?;
        paginas += 1;

        for objeto in pagina.contents() {
            if let Some(artefacto) = artefacto_de(contexto, objeto) {
                encontrados.push(artefacto);
            }
        }

        // El marcador de la página siguiente es la única condición de parada
        // fiable: `is_truncated` es opcional en la respuesta y hay servidores
        // compatibles con S3 que no lo mandan.
        let siguiente = pagina
            .next_continuation_token()
            .map(ToString::to_string)
            .filter(|t| !t.is_empty());
        match siguiente {
            None => break,
            // Un servidor que repitiera el marcador dejaría este bucle pidiendo
            // la misma página para siempre. Es lo mismo que hace el paginador
            // del SDK con `stop_on_duplicate_token`.
            Some(t) if Some(&t) == token.as_ref() => {
                tracing::warn!(
                    "R2 repitió el marcador de continuación al listar: se corta el listado aquí"
                );
                break;
            }
            Some(t) => token = Some(t),
        }
    }

    tracing::debug!(
        prefijo = %prefijo,
        paginas,
        artefactos = encontrados.len(),
        "listado completado"
    );
    Ok(encontrados)
}

/// Traduce un objeto de S3 a un artefacto. `None` si no trae clave, que no
/// debería pasar y que no da nada que devolverle al núcleo.
fn artefacto_de(contexto: &Contexto, objeto: &Object) -> Option<Artefacto> {
    let clave = objeto.key()?;
    Some(Artefacto {
        clave: claves::sin_prefijo(clave, contexto.config.prefix()),
        // Un tamaño negativo no existe en S3; si llegara, cero es más honesto
        // que un número enorme por dar la vuelta.
        tamano: u64::try_from(objeto.size().unwrap_or(0)).unwrap_or(0),
        modificado: objeto
            .last_modified()
            .and_then(|f| f.fmt(DateTimeFormat::DateTime).ok())
            .unwrap_or_default(),
    })
}

/// Borra `clave`. **Es idempotente**: borrar lo que ya no está no es un error.
///
/// La retención se reintenta, y un reintento que acierta —porque la pasada
/// anterior ya borró la mitad— no puede convertirse en un fallo de la
/// operación entera.
///
/// # Errors
///
/// El motivo ya depurado si R2 falla por algo que no sea la ausencia del
/// objeto.
pub async fn borrar(contexto: &Contexto, clave: &str) -> Result<(), Status> {
    match contexto
        .cliente
        .delete_object()
        .bucket(&contexto.config.bucket)
        .key(clave)
        .send()
        .await
    {
        Ok(_) => Ok(()),
        Err(e) => {
            let motivo = traducir("DeleteObject", &e);
            // S3 contesta 204 al borrar algo que no existe, pero no todos los
            // servidores compatibles lo hacen; el que conteste 404 tampoco
            // debe hacer fallar la retención.
            if motivo.es_ausencia() {
                tracing::debug!(clave = %clave, "borrado de un artefacto que ya no estaba");
                return Ok(());
            }
            Err(motivo.into())
        }
    }
}

/// Aborta todas las subidas multipart incompletas bajo `prefijo` y devuelve
/// cuántas eran. Es lo que respalda `shieldbk storage gc`.
///
/// Pagina con la pareja de marcadores que usa `ListMultipartUploads` —clave y
/// `upload_id`—, porque una misma clave puede tener varias subidas abiertas y
/// la clave sola no las distingue.
///
/// # Errors
///
/// El motivo ya depurado si falla el listado o alguno de los abortos.
pub async fn abortar_incompletos(contexto: &Contexto, prefijo: &str) -> Result<u32, Status> {
    let mut abortadas = 0_u32;
    // La pareja de marcadores viaja junta: `upload_id_marker` sin su
    // `key_marker` no significa nada.
    let mut marcador: Option<(String, Option<String>)> = None;

    loop {
        let (clave_desde, id_desde) = match &marcador {
            Some((clave, id)) => (Some(clave.clone()), id.clone()),
            None => (None, None),
        };
        let pagina = contexto
            .cliente
            .list_multipart_uploads()
            .bucket(&contexto.config.bucket)
            .prefix(prefijo)
            .set_key_marker(clave_desde)
            .set_upload_id_marker(id_desde)
            .send()
            .await
            .map_err(|e| traducir("ListMultipartUploads", &e))?;

        for subida in pagina.uploads() {
            let (Some(clave), Some(id)) = (subida.key(), subida.upload_id()) else {
                continue;
            };
            contexto
                .cliente
                .abort_multipart_upload()
                .bucket(&contexto.config.bucket)
                .key(clave)
                .upload_id(id)
                .send()
                .await
                .map_err(|e| traducir("AbortMultipartUpload", &e))?;
            abortadas = abortadas.saturating_add(1);
            tracing::info!(clave = %clave, "subida multipart incompleta abortada");
        }

        if pagina.is_truncated() != Some(true) {
            break;
        }
        let siguiente = pagina.next_key_marker().map(|clave| {
            (
                clave.to_string(),
                pagina.next_upload_id_marker().map(ToString::to_string),
            )
        });
        match siguiente {
            // Truncado pero sin marcador: no hay forma de pedir la página
            // siguiente. Se corta y se deja dicho, porque quedan subidas sin
            // abortar y siguen facturándose.
            None => {
                tracing::warn!(
                    "R2 dijo que el listado de subidas incompletas seguía pero no mandó marcador: \
                     puede quedar alguna sin abortar"
                );
                break;
            }
            Some(s) if Some(&s) == marcador.as_ref() => {
                tracing::warn!("R2 repitió el marcador de subidas incompletas: se corta aquí");
                break;
            }
            Some(s) => marcador = Some(s),
        }
    }

    Ok(abortadas)
}
