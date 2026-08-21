//! Mover bytes por el canal de datos informando del avance.
//!
//! Los cinco RPC que mueven bytes —`Dump`, `Restore`, `Put`, `Get`— comparten
//! la misma forma: devolver un flujo de `Progress` mientras una tarea de fondo
//! bombea bytes entre el socket y un fichero. Esa forma vive aquí una sola vez.

use std::future::Future;
use std::path::Path;

use sb_plugin_sdk::sb_proto::Progress;
use sb_plugin_sdk::tonic::Status;
use sb_transport::connect_data;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio_stream::wrappers::ReceiverStream;

/// Cada cuántos bytes se emite un `Progress`.
const MIB: u64 = 1024 * 1024;
/// Tamaño de los trozos que se mueven de una vez.
pub const TROZO: usize = 64 * 1024;
/// Cuántos `Progress` caben sin consumir antes de frenar a la tarea.
///
/// Hay backpressure a propósito: un núcleo que no lee el progreso es un núcleo
/// que tampoco está leyendo los datos, y seguir generando no ayudaría.
const CAPACIDAD: usize = 64;

/// El flujo de `Progress` que devuelven los RPC de datos.
pub type FlujoProgreso = ReceiverStream<Result<Progress, Status>>;

/// Contador de bytes que emite un `Progress` cada mebibyte.
pub struct Progreso {
    tx: tokio::sync::mpsc::Sender<Result<Progress, Status>>,
    bytes: u64,
    hitos: u64,
}

impl Progreso {
    /// Anota `n` bytes movidos y emite un `Progress` si se cruzó un mebibyte.
    pub async fn avanzar(&mut self, n: usize) {
        self.bytes += como_u64(n);
        let hitos = self.bytes / MIB;
        if hitos > self.hitos {
            self.hitos = hitos;
            self.emitir("en curso").await;
        }
    }

    /// Emite el `Progress` final con el total movido.
    pub async fn terminar(&mut self, mensaje: &str) {
        self.emitir(mensaje).await;
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

/// Lanza `trabajo` en segundo plano y devuelve el flujo de progreso que emite.
///
/// Si el trabajo falla, el `Status` viaja por el mismo flujo: el núcleo se
/// entera del fallo por donde ya está escuchando.
pub fn servir<F, Fut>(trabajo: F) -> FlujoProgreso
where
    F: FnOnce(Progreso) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), Status>> + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(CAPACIDAD);
    let tx_error = tx.clone();
    tokio::spawn(async move {
        let progreso = Progreso {
            tx,
            bytes: 0,
            hitos: 0,
        };
        if let Err(e) = trabajo(progreso).await {
            tracing::warn!(error = %e, "la transferencia falló");
            let _ = tx_error.send(Err(e)).await;
        }
    });
    ReceiverStream::new(rx)
}

/// Se conecta al canal de datos que creó el núcleo.
///
/// # Errors
/// [`Status::unavailable`] si el socket no existe o no acepta la conexión.
pub async fn conectar(socket: &str) -> Result<UnixStream, Status> {
    connect_data(Path::new(socket)).await.map_err(|e| {
        Status::unavailable(format!(
            "no se pudo abrir el canal de datos `{socket}`: {e}"
        ))
    })
}

/// Lee el canal de datos hasta EOF y lo escribe en `destino`.
///
/// Crea los directorios intermedios: una clave como `produccion/2026/08/x.age`
/// nombra una jerarquía que aún no tiene por qué existir.
///
/// # Errors
/// [`Status::unavailable`] si el canal falla, [`Status::internal`] si el
/// fichero no se puede crear o escribir.
pub async fn del_canal_al_fichero(
    socket: &str,
    destino: &Path,
    progreso: &mut Progreso,
) -> Result<(), Status> {
    // Conectar primero: si el canal no está, no tiene sentido dejar atrás un
    // fichero vacío que luego parecería un artefacto de cero bytes.
    let mut canal = conectar(socket).await?;
    if let Some(padre) = destino.parent() {
        tokio::fs::create_dir_all(padre)
            .await
            .map_err(|e| Status::internal(format!("no se pudo crear {}: {e}", padre.display())))?;
    }
    let mut fichero = tokio::fs::File::create(destino)
        .await
        .map_err(|e| Status::internal(format!("no se pudo crear {}: {e}", destino.display())))?;

    let mut buffer = vec![0_u8; TROZO];
    loop {
        let leidos = canal
            .read(&mut buffer)
            .await
            .map_err(|e| Status::unavailable(format!("fallo leyendo el canal de datos: {e}")))?;
        if leidos == 0 {
            break;
        }
        fichero.write_all(&buffer[..leidos]).await.map_err(|e| {
            Status::internal(format!("fallo escribiendo {}: {e}", destino.display()))
        })?;
        progreso.avanzar(leidos).await;
    }
    // Sin el flush explícito el fichero podría quedarse corto justo cuando el
    // núcleo ya cree que la transferencia terminó.
    fichero
        .flush()
        .await
        .map_err(|e| Status::internal(format!("fallo cerrando {}: {e}", destino.display())))?;
    Ok(())
}

/// Escribe `origen` en el canal de datos y lo cierra.
///
/// # Errors
/// [`Status::unavailable`] si el canal falla, [`Status::internal`] si el
/// fichero no se puede leer.
pub async fn del_fichero_al_canal(
    socket: &str,
    origen: &Path,
    progreso: &mut Progreso,
) -> Result<(), Status> {
    let mut fichero = tokio::fs::File::open(origen)
        .await
        .map_err(|e| Status::internal(format!("no se pudo abrir {}: {e}", origen.display())))?;

    let mut canal = conectar(socket).await?;
    let mut buffer = vec![0_u8; TROZO];
    loop {
        let leidos = fichero
            .read(&mut buffer)
            .await
            .map_err(|e| Status::internal(format!("fallo leyendo {}: {e}", origen.display())))?;
        if leidos == 0 {
            break;
        }
        escribir(&mut canal, &buffer[..leidos]).await?;
        progreso.avanzar(leidos).await;
    }
    cerrar(&mut canal).await
}

/// Escribe un trozo en el canal de datos.
///
/// # Errors
/// [`Status::unavailable`] si el otro extremo se cerró.
pub async fn escribir(canal: &mut UnixStream, trozo: &[u8]) -> Result<(), Status> {
    canal
        .write_all(trozo)
        .await
        .map_err(|e| Status::unavailable(format!("fallo escribiendo en el canal de datos: {e}")))
}

/// Cierra el lado de escritura del canal.
///
/// **Esto es lo que le señala al núcleo el fin del flujo.** Sin este cierre el
/// núcleo esperaría bytes que ya no van a llegar.
///
/// # Errors
/// [`Status::unavailable`] si el cierre falla.
pub async fn cerrar(canal: &mut UnixStream) -> Result<(), Status> {
    canal
        .shutdown()
        .await
        .map_err(|e| Status::unavailable(format!("fallo cerrando el canal de datos: {e}")))
}

/// `usize` a `u64` sin un `as` que clippy tenga que perdonar. En las
/// plataformas que soporta el proyecto la conversión nunca satura.
fn como_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_trozo_cabe_holgadamente_en_un_hito() {
        // Si un trozo fuera mayor que un mebibyte se saltarían hitos enteros y
        // el progreso daría saltos en vez de fluir.
        assert!(como_u64(TROZO) < MIB);
    }

    #[tokio::test]
    async fn conectar_a_un_socket_inexistente_da_unavailable() {
        let e = conectar("/tmp/no-existe-sb-plugin-mock.sock")
            .await
            .unwrap_err();
        assert_eq!(e.code(), sb_plugin_sdk::tonic::Code::Unavailable);
    }
}
