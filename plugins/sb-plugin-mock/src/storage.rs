//! El destino: un directorio del disco haciendo de bucket.
//!
//! Cada clave es un fichero bajo `dir`. Lo interesante no es guardar bytes sino
//! reproducir el contrato que el núcleo espera de un destino real: claves con
//! jerarquía, borrado idempotente y rechazo de claves que se salen.

use sb_plugin_sdk::sb_proto::storage_server::Storage;
use sb_plugin_sdk::sb_proto::{
    AbortIncompleteRequest, AbortIncompleteResponse, ArtifactMeta, DeleteRequest, DeleteResponse,
    GetRequest, ListRequest, ListResponse, PutRequest,
};
use sb_plugin_sdk::tonic::{Request, Response, Status};
use sb_plugin_sdk::{ProgressStream, progress_stream};

use crate::claves;
use crate::config::Estado;
use crate::flujo;

pub struct DestinoMock {
    estado: Estado,
}

impl DestinoMock {
    #[must_use]
    pub fn new(estado: Estado) -> Self {
        Self { estado }
    }
}

#[sb_plugin_sdk::tonic::async_trait]
impl Storage for DestinoMock {
    type PutStream = ProgressStream;
    type GetStream = ProgressStream;

    async fn put(
        &self,
        peticion: Request<PutRequest>,
    ) -> Result<Response<Self::PutStream>, Status> {
        let config = self.estado.resolved()?;
        let PutRequest { key, data_socket } = peticion.into_inner();
        // La clave se valida **antes** de abrir nada: un `..` debe fallar como
        // error inmediato del RPC, no como un error a mitad del flujo cuando
        // ya se escribió algo fuera del directorio.
        let destino = claves::ruta_de(&config.dir, &key)?;
        Ok(progress_stream(move |mut progreso| async move {
            flujo::del_canal_al_fichero(&data_socket, &destino, &mut progreso).await?;
            progreso.finish("artefacto almacenado").await;
            tracing::info!(clave = %key, "artefacto almacenado");
            Ok(())
        }))
    }

    async fn get(
        &self,
        peticion: Request<GetRequest>,
    ) -> Result<Response<Self::GetStream>, Status> {
        let config = self.estado.resolved()?;
        let GetRequest { key, data_socket } = peticion.into_inner();
        let origen = claves::ruta_de(&config.dir, &key)?;
        // La ausencia también se comprueba antes: el núcleo debe poder
        // distinguir «no está» de «se cortó a mitad».
        if !origen.is_file() {
            return Err(Status::not_found(format!(
                "el artefacto `{key}` no existe en {}",
                config.dir.display()
            )));
        }
        Ok(progress_stream(move |mut progreso| async move {
            flujo::del_fichero_al_canal(&data_socket, &origen, &mut progreso).await?;
            progreso.finish("artefacto entregado").await;
            Ok(())
        }))
    }

    async fn list(&self, peticion: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        let config = self.estado.resolved()?;
        let prefijo = peticion.into_inner().prefix;
        let encontrados = claves::listar(&config.dir, &prefijo).map_err(|e| {
            Status::internal(format!("no se pudo recorrer {}: {e}", config.dir.display()))
        })?;
        Ok(Response::new(ListResponse {
            artifacts: encontrados
                .into_iter()
                .map(|a| ArtifactMeta {
                    key: a.clave,
                    size: a.tamano,
                    modified_at: a.modificado,
                })
                .collect(),
        }))
    }

    async fn delete(
        &self,
        peticion: Request<DeleteRequest>,
    ) -> Result<Response<DeleteResponse>, Status> {
        let config = self.estado.resolved()?;
        let clave = peticion.into_inner().key;
        let ruta = claves::ruta_de(&config.dir, &clave)?;
        match tokio::fs::remove_file(&ruta).await {
            Ok(()) => {}
            // Borrar lo que ya no está es el resultado que se pedía. Una
            // retención que se reintenta no puede fallar por haber acertado.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(clave = %clave, "borrado de un artefacto que ya no estaba");
            }
            Err(e) => {
                return Err(Status::internal(format!(
                    "no se pudo borrar `{clave}`: {e}"
                )));
            }
        }
        Ok(Response::new(DeleteResponse {}))
    }

    async fn abort_incomplete(
        &self,
        _: Request<AbortIncompleteRequest>,
    ) -> Result<Response<AbortIncompleteResponse>, Status> {
        // Se exige configuración igual que en el resto del destino, aunque la
        // respuesta no dependa de ella: un núcleo que se saltó `Configure`
        // debe enterarse por el primer RPC que haga, no por el segundo.
        let _ = self.estado.resolved()?;
        // Este destino escribe cada artefacto de una vez: no hay multipart que
        // abortar, y por eso siempre son cero.
        Ok(Response::new(AbortIncompleteResponse { aborted: 0 }))
    }
}
