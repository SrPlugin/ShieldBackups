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

use aws_sdk_s3::primitives::{DateTime, DateTimeFormat};
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
    /// Fecha de última modificación en **RFC-3339 UTC con precisión de
    /// segundo**: `2026-08-21T09:30:00Z`, veinte caracteres exactos. Es lo que
    /// exige el `.proto` para `ArtifactMeta.modified_at`. Cadena vacía si R2 no
    /// la devolvió.
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
        modificado: objeto.last_modified().map(fecha).unwrap_or_default(),
    })
}

/// La fecha en el formato que fija el `.proto`: RFC-3339 UTC **sin fracción de
/// segundo**.
///
/// El truncado a segundos no es cosmético. R2 devuelve milisegundos y el
/// destino de pruebas no los tiene, así que sin truncar los dos destinos
/// producen cadenas que **no se pueden ordenar entre sí**: `…:15Z` y
/// `…:15.983Z` se comparan en el carácter 19, donde `Z` es mayor que `.`, y el
/// artefacto más antiguo sale por delante del más nuevo. Lo destapó el test de
/// integración contra `MinIO`, comparando lo que devuelve este plugin con lo
/// que promete el contrato.
fn fecha(momento: &DateTime) -> String {
    DateTime::from_secs(momento.secs())
        .fmt(DateTimeFormat::DateTime)
        .unwrap_or_default()
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
/// El filtro por prefijo lo aplica **este código**, no el servidor: ver el
/// comentario dentro del bucle.
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
        // **Sin `prefix` en la petición, a propósito.** El parámetro existe en
        // la API, pero no todos los servidores compatibles con S3 lo
        // implementan: `MinIO` solo devuelve algo cuando el prefijo es el
        // nombre completo del objeto, y con cualquier prefijo parcial contesta
        // una lista vacía. Confiar en él convierte `shieldbk storage gc` en una
        // operación que **dice que abortó cero y se queda tan ancha** mientras
        // las partes huérfanas se siguen facturando. Un filtro que no filtra se
        // ve; uno que devuelve vacío, no.
        //
        // El filtrado se hace aquí abajo, sobre la clave. Cuesta traer las
        // subidas de todo el bucket, pero las subidas en curso son pocas por
        // definición: las que sobreviven son fallos, no tráfico normal.
        let pagina = contexto
            .cliente
            .list_multipart_uploads()
            .bucket(&contexto.config.bucket)
            .set_key_marker(clave_desde)
            .set_upload_id_marker(id_desde)
            .send()
            .await
            .map_err(|e| traducir("ListMultipartUploads", &e))?;

        for subida in pagina.uploads() {
            let (Some(clave), Some(id)) = (subida.key(), subida.upload_id()) else {
                continue;
            };
            // Lo que no está bajo el prefijo no es nuestro. En un bucket
            // compartido, abortar la subida de otro sería destruir su backup a
            // mitad.
            if !clave.starts_with(prefijo) {
                continue;
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_fecha_sale_en_rfc3339_utc_con_precision_de_segundo() {
        // 1 771 234 200 = 2026-02-16T09:30:00Z.
        assert_eq!(
            fecha(&DateTime::from_secs(1_771_234_200)),
            "2026-02-16T09:30:00Z"
        );
    }

    #[test]
    fn los_milisegundos_que_manda_r2_se_recortan() {
        // Sin recortar saldría `2026-02-16T09:30:00.983Z`, que ordena **por
        // detrás** de un `2026-02-16T09:30:00Z` de otro destino aunque sea
        // posterior: en el carácter 19 se compara `.` contra `Z`.
        let con_milisegundos = DateTime::from_secs_and_nanos(1_771_234_200, 983_000_000);
        let recortada = fecha(&con_milisegundos);
        assert_eq!(recortada, "2026-02-16T09:30:00Z");
        assert_eq!(recortada.len(), 20);
        assert!(recortada > fecha(&DateTime::from_secs(1_771_234_199)));
    }
}
