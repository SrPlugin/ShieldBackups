//! El canal de datos: abrirlo, escribir en él y cerrarlo.
//!
//! Los bytes del artefacto no viajan por gRPC sino por un socket Unix que crea
//! el núcleo. Las tres operaciones que hacen falta para usarlo están aquí
//! porque las comparten la subida y la descarga, y porque una de ellas
//! —[`cerrar`]— es fácil de olvidar y su olvido no se nota hasta que un
//! `restore` se queda colgado.

use std::path::Path;

use sb_plugin_sdk::connect_data;
use sb_plugin_sdk::tonic::Status;
use tokio::io::AsyncWriteExt as _;
use tokio::net::UnixStream;

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
/// núcleo seguiría esperando bytes que ya no van a llegar y el `restore` se
/// quedaría colgado hasta que venciera su plazo.
///
/// # Errors
/// [`Status::unavailable`] si el cierre falla.
pub async fn cerrar(canal: &mut UnixStream) -> Result<(), Status> {
    canal
        .shutdown()
        .await
        .map_err(|e| Status::unavailable(format!("fallo cerrando el canal de datos: {e}")))
}

/// Un fallo leyendo el canal de datos es del otro extremo, no de R2.
#[must_use]
pub fn fallo_de_lectura(e: &std::io::Error) -> Status {
    Status::unavailable(format!("fallo leyendo el canal de datos: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn conectar_a_un_socket_inexistente_da_unavailable() {
        let e = conectar("/tmp/no-existe-sb-plugin-r2.sock")
            .await
            .unwrap_err();
        assert_eq!(e.code(), sb_plugin_sdk::tonic::Code::Unavailable);
    }

    #[test]
    fn un_fallo_del_canal_no_se_confunde_con_uno_de_r2() {
        // El núcleo decide con este código si el culpable es el destino o el
        // otro extremo del socket.
        let e = fallo_de_lectura(&std::io::Error::other("roto"));
        assert_eq!(e.code(), sb_plugin_sdk::tonic::Code::Unavailable);
    }
}
