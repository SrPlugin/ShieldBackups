//! El destino R2.
//!
//! `Put` ya sube de verdad —la lógica está en [`crate::put`], que es donde vive
//! lo delicado del multipart—; los otros cuatro RPC llegan en la tarea
//! siguiente. Cada uno exige antes la configuración, así que un núcleo que se
//! saltara `Configure` se entera por el primer RPC que haga y no por el
//! segundo.

use sb_plugin_sdk::sb_proto::storage_server::Storage;
use sb_plugin_sdk::sb_proto::{
    AbortIncompleteRequest, AbortIncompleteResponse, DeleteRequest, DeleteResponse, GetRequest,
    ListRequest, ListResponse, PutRequest,
};
use sb_plugin_sdk::tonic::{Request, Response, Status};
use sb_plugin_sdk::{ProgresoStream, stream_de_progreso};

use crate::cliente::Estado;
use crate::put;

pub struct DestinoR2 {
    estado: Estado,
}

impl DestinoR2 {
    #[must_use]
    pub fn new(estado: Estado) -> Self {
        Self { estado }
    }
}

#[sb_plugin_sdk::tonic::async_trait]
impl Storage for DestinoR2 {
    type PutStream = ProgresoStream;
    type GetStream = ProgresoStream;

    async fn put(
        &self,
        peticion: Request<PutRequest>,
    ) -> Result<Response<Self::PutStream>, Status> {
        // Lo que se puede saber antes de mover un byte se resuelve aquí, con un
        // `?`: una vez arranca el trabajo, la respuesta del RPC ya se envió y el
        // error solo tendría el flujo de progreso para volver.
        let contexto = self.estado.resuelta()?;
        let PutRequest { key, data_socket } = peticion.into_inner();
        let clave = contexto.config.clave(&key);
        // `stream_de_progreso` responde al RPC **antes** de que el trabajo
        // toque el socket de datos, que es lo que el protocolo exige: el núcleo
        // espera esa respuesta para poner en marcha el otro extremo.
        Ok(stream_de_progreso(move |mut progreso| async move {
            put::subir(&contexto, &clave, &data_socket, &mut progreso).await?;
            progreso.terminar("artefacto almacenado").await;
            tracing::info!(clave = %clave, bytes = progreso.bytes(), "artefacto almacenado en R2");
            Ok(())
        }))
    }

    async fn get(
        &self,
        peticion: Request<GetRequest>,
    ) -> Result<Response<Self::GetStream>, Status> {
        let contexto = self.estado.resuelta()?;
        let clave = contexto.config.clave(&peticion.into_inner().key);
        Err(Status::unimplemented(format!(
            "el destino r2 todavía no sabe descargar `{clave}`"
        )))
    }

    async fn list(&self, peticion: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        let contexto = self.estado.resuelta()?;
        let prefijo = contexto.config.clave(&peticion.into_inner().prefix);
        Err(Status::unimplemented(format!(
            "el destino r2 todavía no sabe listar bajo `{prefijo}`"
        )))
    }

    async fn delete(
        &self,
        peticion: Request<DeleteRequest>,
    ) -> Result<Response<DeleteResponse>, Status> {
        let contexto = self.estado.resuelta()?;
        let clave = contexto.config.clave(&peticion.into_inner().key);
        Err(Status::unimplemented(format!(
            "el destino r2 todavía no sabe borrar `{clave}`"
        )))
    }

    async fn abort_incomplete(
        &self,
        _: Request<AbortIncompleteRequest>,
    ) -> Result<Response<AbortIncompleteResponse>, Status> {
        let _ = self.estado.resuelta()?;
        Err(Status::unimplemented(
            "el destino r2 todavía no sabe abortar subidas incompletas",
        ))
    }
}
