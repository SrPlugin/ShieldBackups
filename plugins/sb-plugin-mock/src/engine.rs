//! El motor: produce bytes deterministas y los vuelve a recibir.
//!
//! No hay base de datos detrás. `Dump` genera el flujo desde una semilla y
//! `Restore` lo escribe en disco para que un test pueda compararlo con lo que
//! el generador produce, sin más dependencias que la aritmética.

use std::path::Path;

use sb_plugin_mock::datos_deterministas;
use sb_plugin_sdk::sb_proto::engine_server::Engine;
use sb_plugin_sdk::sb_proto::{DumpRequest, RestoreRequest};
use sb_plugin_sdk::tonic::{Request, Response, Status};
use sb_plugin_sdk::{EmisorProgreso, ProgresoStream, stream_de_progreso};

use crate::config::{Config, Estado};
use crate::flujo;

/// Nombre del fichero donde `Restore` deja lo que recibe.
pub const FICHERO_RESTAURADO: &str = "restore.bin";

pub struct MotorMock {
    estado: Estado,
}

impl MotorMock {
    #[must_use]
    pub fn new(estado: Estado) -> Self {
        Self { estado }
    }
}

#[sb_plugin_sdk::tonic::async_trait]
impl Engine for MotorMock {
    type DumpStream = ProgresoStream;
    type RestoreStream = ProgresoStream;

    async fn dump(
        &self,
        peticion: Request<DumpRequest>,
    ) -> Result<Response<Self::DumpStream>, Status> {
        // La configuración se exige aquí, antes de tocar el canal: si falta,
        // el núcleo recibe un `failed_precondition` inmediato en vez de un
        // volcado silencioso con valores que nadie pidió.
        let config = self.estado.resuelta()?;
        let socket = peticion.into_inner().data_socket;
        Ok(stream_de_progreso(move |mut progreso| async move {
            volcar(&socket, &config, &mut progreso).await
        }))
    }

    async fn restore(
        &self,
        peticion: Request<RestoreRequest>,
    ) -> Result<Response<Self::RestoreStream>, Status> {
        let config = self.estado.resuelta()?;
        let socket = peticion.into_inner().data_socket;
        let destino = config.dir.join(FICHERO_RESTAURADO);
        Ok(stream_de_progreso(move |mut progreso| async move {
            restaurar(&socket, &destino, &mut progreso).await
        }))
    }
}

/// Escribe `size` bytes de la semilla en el canal y lo cierra.
async fn volcar(
    socket: &str,
    config: &Config,
    progreso: &mut EmisorProgreso,
) -> Result<(), Status> {
    let mut canal = flujo::conectar(socket).await?;
    let mut generador = datos_deterministas(config.seed, config.size);
    loop {
        let trozo: Vec<u8> = generador.by_ref().take(flujo::TROZO).collect();
        if trozo.is_empty() {
            break;
        }
        flujo::escribir(&mut canal, &trozo).await?;
        progreso.avanzar(trozo.len()).await;
    }
    // El cierre es la señal de fin de flujo para el núcleo.
    flujo::cerrar(&mut canal).await?;
    progreso.terminar("volcado completado").await;
    tracing::info!(seed = config.seed, size = config.size, "volcado emitido");
    Ok(())
}

async fn restaurar(
    socket: &str,
    destino: &Path,
    progreso: &mut EmisorProgreso,
) -> Result<(), Status> {
    flujo::del_canal_al_fichero(socket, destino, progreso).await?;
    progreso.terminar("restauración completada").await;
    tracing::info!(destino = %destino.display(), "restauración escrita");
    Ok(())
}
