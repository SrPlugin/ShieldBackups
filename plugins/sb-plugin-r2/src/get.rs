//! Descargar un artefacto de R2 y volcarlo en el canal de datos.
//!
//! Lo único delicado aquí es lo que **no** se hace: no se llama a
//! `body.collect()`. Esa llamada, que es la que sale en todos los ejemplos del
//! SDK, junta el objeto entero en memoria antes de devolverlo. Un artefacto de
//! este programa puede pesar cientos de gigabytes, y la promesa de memoria
//! acotada se rompería aquí y en ningún otro sitio. El cuerpo se
//! consume trozo a trozo, según llega de la red, y cada trozo se escribe y se
//! suelta.
//!
//! La ausencia se detecta **antes** de responder al RPC: el núcleo distingue
//! «ese artefacto no existe» de «la transferencia se cortó», y esa distinción
//! se pierde si el error llega por el flujo de progreso cuando la respuesta ya
//! salió.

use aws_sdk_s3::primitives::ByteStream;
use sb_plugin_sdk::ProgressEmitter;
use sb_plugin_sdk::tonic::Status;

use crate::canal;
use crate::cliente::{Contexto, traducir};

/// Pide el objeto a R2 y devuelve su cuerpo **sin leer**.
///
/// Se llama desde el cuerpo del RPC, no desde la tarea de fondo: así un
/// artefacto que no está se contesta como un error de la llamada y no como un
/// corte a mitad del flujo.
///
/// # Errors
///
/// [`Status::not_found`] con la clave dentro si el objeto no existe, y el
/// motivo ya depurado en cualquier otro fallo contra R2.
pub async fn pedir(contexto: &Contexto, clave: &str) -> Result<ByteStream, Status> {
    let salida = contexto
        .cliente
        .get_object()
        .bucket(&contexto.config.bucket)
        .key(clave)
        .send()
        .await
        .map_err(|e| {
            let motivo = traducir("GetObject", &e);
            if motivo.es_ausencia() {
                return Status::not_found(format!(
                    "el artefacto `{clave}` no existe en el bucket `{}`",
                    contexto.config.bucket
                ));
            }
            Status::from(motivo)
        })?;
    Ok(salida.body)
}

/// Vuelca `cuerpo` en el canal de datos, trozo a trozo, y lo cierra.
///
/// # Errors
///
/// [`Status::unavailable`] si falla la red de R2 o el canal de datos: en ambos
/// casos el artefacto no llegó entero y el núcleo tiene que enterarse.
pub async fn volcar(
    mut cuerpo: ByteStream,
    socket: &str,
    progreso: &mut ProgressEmitter,
) -> Result<(), Status> {
    let mut destino = canal::conectar(socket).await?;
    // `next()` entrega el siguiente trozo tal y como llegó de la red. El objeto
    // entero no está nunca en memoria: solo el trozo que se está escribiendo.
    while let Some(trozo) = cuerpo.next().await {
        let trozo = trozo.map_err(|e| {
            // El error del cuerpo es del SDK y podría arrastrar la petición que
            // lo provocó; solo se dice que la descarga se cortó.
            tracing::debug!(error = %e, "el cuerpo de GetObject se cortó");
            Status::unavailable("la descarga desde R2 se cortó antes de terminar")
        })?;
        canal::escribir(&mut destino, &trozo).await?;
        progreso.advance(trozo.len()).await;
    }
    // El cierre es la señal de fin de flujo para el núcleo. Sin él, el
    // `restore` espera bytes que ya no vienen.
    canal::cerrar(&mut destino).await
}
