//! Mover bytes entre el canal de datos y el disco.
//!
//! El armazón de los RPC que mueven bytes —la tarea de fondo y el flujo de
//! `Progress`— lo pone el SDK con `progress_stream`. Lo que queda aquí es lo
//! único que es de este plugin: bombear bytes entre el socket y un fichero.

use std::path::Path;

use sb_plugin_sdk::tonic::Status;
use sb_plugin_sdk::{ProgressEmitter, connect_data};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

/// Tamaño de los trozos que se mueven de una vez.
///
/// Más pequeño que el hito de progreso del SDK a propósito: un trozo mayor
/// saltaría hitos enteros y el progreso daría saltos en vez de fluir.
pub const TROZO: usize = 64 * 1024;

/// El hito del SDK, atado con este nombre para poder compararlo con `TROZO`.
#[cfg(test)]
use sb_plugin_sdk::progress::MILESTONE as MIB;

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
    progreso: &mut ProgressEmitter,
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
        progreso.advance(leidos).await;
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
    progreso: &mut ProgressEmitter,
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
        progreso.advance(leidos).await;
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

/// `usize` a `u64` sin un `as` que clippy tenga que perdonar. Solo la usa la
/// comprobación de abajo: el conteo de bytes lo lleva el SDK.
#[cfg(test)]
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
