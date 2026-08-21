//! El armazón de los RPC que mueven bytes.
//!
//! `Dump`, `Restore`, `Put` y `Get` tienen la misma forma: lanzar una tarea que
//! bombea bytes por el canal de datos y devolverle al núcleo un flujo de
//! `Progress` por el que también viaja el error si algo falla. Esa forma está
//! aquí una vez, para que un motor o un destino solo escriba su lógica de mover
//! bytes.

use std::future::Future;

use sb_proto::Progress;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Response, Status};

/// Cada cuántos bytes movidos se emite un `Progress`.
///
/// Es público porque el tamaño de trozo lo elige el plugin y solo tiene sentido
/// si es más pequeño que esto: un trozo mayor saltaría hitos enteros y el
/// progreso daría saltos en vez de fluir.
pub const HITO: u64 = 1024 * 1024;

/// Cuántos `Progress` caben sin consumir antes de frenar a la tarea.
///
/// Hay backpressure a propósito: un núcleo que no lee el progreso es un núcleo
/// que tampoco está leyendo los datos, y seguir generando no ayudaría.
const CAPACIDAD: usize = 64;

/// El flujo de `Progress` que devuelven los RPC de datos.
///
/// Es el tipo que se declara en `type DumpStream = ProgresoStream;` y en sus
/// tres hermanos.
pub type ProgresoStream = ReceiverStream<Result<Progress, Status>>;

/// Por donde el trabajo cuenta lo que lleva movido.
///
/// Lo construye [`stream_de_progreso`] y se lo entrega al trabajo; no hay otra
/// forma de crear uno, porque un emisor sin su flujo al otro lado no emitiría a
/// nadie.
pub struct EmisorProgreso {
    tx: tokio::sync::mpsc::Sender<Result<Progress, Status>>,
    bytes: u64,
    hitos: u64,
}

impl EmisorProgreso {
    /// Anota `n` bytes movidos y emite un `Progress` si se cruzó un hito.
    ///
    /// Se llama por cada trozo: es barato, porque solo emite al cruzar
    /// [`HITO`].
    pub async fn avanzar(&mut self, n: usize) {
        self.bytes += como_u64(n);
        let hitos = self.bytes / HITO;
        if hitos > self.hitos {
            self.hitos = hitos;
            self.emitir("en curso").await;
        }
    }

    /// Emite el `Progress` final con el total movido.
    ///
    /// El núcleo usa el último `Progress` como resumen de la operación, así que
    /// `mensaje` es lo que acabará viendo el operador.
    pub async fn terminar(&mut self, mensaje: &str) {
        self.emitir(mensaje).await;
    }

    /// Bytes movidos hasta ahora.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    async fn emitir(&self, mensaje: &str) {
        // Un envío fallido significa que el núcleo cerró el flujo; no es un
        // error del plugin y no debe abortar la transferencia en curso.
        let _ = self
            .tx
            .send(Ok(Progress {
                bytes: self.bytes,
                message: mensaje.into(),
            }))
            .await;
    }
}

/// Ejecuta `trabajo` en una tarea y devuelve el flujo de progreso que el núcleo
/// consume.
///
/// Devuelve la [`Response`] ya montada porque es lo único que un RPC de datos
/// tiene que devolver:
///
/// ```ignore
/// async fn dump(&self, p: Request<DumpRequest>) -> Result<Response<Self::DumpStream>, Status> {
///     let config = self.config.resuelta()?;          // antes de tocar nada
///     let socket = p.into_inner().data_socket;
///     Ok(stream_de_progreso(move |mut avance| async move {
///         volcar(&socket, &config, &mut avance).await // solo mover bytes
///     }))
/// }
/// ```
///
/// Un `Err` del trabajo llega al núcleo **por el mismo flujo** en el que ya
/// está escuchando, no como un `Status` de la llamada: cuando el trabajo
/// empieza, la respuesta del RPC hace rato que se envió. Los errores que se
/// pueden detectar antes —falta de configuración, una clave inválida, un
/// artefacto que no existe— van fuera de aquí, con un `?` en el cuerpo del RPC.
pub fn stream_de_progreso<F, Fut>(trabajo: F) -> Response<ProgresoStream>
where
    F: FnOnce(EmisorProgreso) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), Status>> + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(CAPACIDAD);
    let tx_error = tx.clone();
    tokio::spawn(async move {
        let emisor = EmisorProgreso {
            tx,
            bytes: 0,
            hitos: 0,
        };
        if let Err(e) = trabajo(emisor).await {
            tracing::warn!(error = %e, "la transferencia falló");
            let _ = tx_error.send(Err(e)).await;
        }
    });
    Response::new(ReceiverStream::new(rx))
}

/// `usize` a `u64` sin un `as` que clippy tenga que perdonar. En las
/// plataformas que soporta el proyecto la conversión nunca satura.
fn como_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt as _;

    /// Consume el flujo entero y devuelve lo que llegó.
    async fn recoger(r: Response<ProgresoStream>) -> Vec<Result<Progress, Status>> {
        r.into_inner().collect().await
    }

    #[tokio::test]
    async fn un_trabajo_que_no_emite_nada_cierra_el_flujo_sin_error() {
        let salida = recoger(stream_de_progreso(|_| async { Ok(()) })).await;
        assert!(salida.is_empty());
    }

    #[tokio::test]
    async fn el_progreso_final_lleva_el_total_y_el_mensaje_del_plugin() {
        let salida = recoger(stream_de_progreso(|mut avance| async move {
            avance.avanzar(1000).await;
            avance.terminar("volcado completado").await;
            Ok(())
        }))
        .await;

        assert_eq!(salida.len(), 1, "por debajo de un hito solo va el final");
        let p = salida[0].as_ref().unwrap();
        assert_eq!(p.bytes, 1000);
        assert_eq!(p.message, "volcado completado");
    }

    #[tokio::test]
    async fn se_emite_un_progress_por_cada_hito_cruzado() {
        let salida = recoger(stream_de_progreso(|mut avance| async move {
            let trozo = usize::try_from(HITO).unwrap() / 4;
            for _ in 0..12 {
                avance.avanzar(trozo).await;
            }
            avance.terminar("fin").await;
            Ok(())
        }))
        .await;

        // Tres hitos cruzados más el final.
        assert_eq!(salida.len(), 4);
        assert_eq!(salida[0].as_ref().unwrap().bytes, HITO);
        assert_eq!(salida[3].as_ref().unwrap().bytes, HITO * 3);
    }

    #[tokio::test]
    async fn el_error_del_trabajo_llega_al_nucleo_por_el_flujo() {
        // Cuando el trabajo empieza, la respuesta del RPC ya se envió: el flujo
        // es el único camino que le queda al error.
        let salida = recoger(stream_de_progreso(|mut avance| async move {
            avance.avanzar(10).await;
            Err(Status::unavailable("el canal de datos se cayó"))
        }))
        .await;

        let e = salida.last().unwrap().as_ref().unwrap_err();
        assert_eq!(e.code(), tonic::Code::Unavailable);
        assert_eq!(e.message(), "el canal de datos se cayó");
    }

    #[tokio::test]
    async fn lo_emitido_antes_del_error_no_se_pierde() {
        let salida = recoger(stream_de_progreso(|mut avance| async move {
            avance.terminar("iba bien").await;
            Err(Status::internal("y luego no"))
        }))
        .await;

        assert_eq!(salida.len(), 2);
        assert_eq!(salida[0].as_ref().unwrap().message, "iba bien");
        assert!(salida[1].is_err());
    }

    #[tokio::test]
    async fn el_emisor_lleva_la_cuenta_de_los_bytes() {
        let salida = recoger(stream_de_progreso(|mut avance| async move {
            avance.avanzar(3).await;
            avance.avanzar(4).await;
            assert_eq!(avance.bytes(), 7);
            avance.terminar("fin").await;
            Ok(())
        }))
        .await;
        assert_eq!(salida[0].as_ref().unwrap().bytes, 7);
    }

    #[tokio::test]
    async fn un_nucleo_que_deja_de_leer_no_hace_fallar_al_trabajo() {
        // Si el núcleo cierra el flujo, emitir deja de llegar a alguien, pero
        // la transferencia en curso no es un error del plugin.
        let (aviso_tx, aviso_rx) = tokio::sync::oneshot::channel();
        let respuesta = stream_de_progreso(|mut avance| async move {
            for _ in 0..(CAPACIDAD * 4) {
                avance.terminar("tic").await;
            }
            let _ = aviso_tx.send(());
            Ok(())
        });
        drop(respuesta);
        aviso_rx.await.expect("el trabajo debe terminar igualmente");
    }
}
