//! El destino R2. De momento solo sabe decir que todavía no sabe.
//!
//! Los cinco RPC están registrados —para que el núcleo vea la capacidad
//! `storage` y `doctor` pueda hablar con el plugin— pero mover bytes llega en
//! la tarea siguiente. Cada uno exige antes la configuración, así que un núcleo
//! que se saltara `Configure` se entera por el primer RPC que haga y no por el
//! segundo.

use sb_plugin_sdk::ProgresoStream;
use sb_plugin_sdk::sb_proto::storage_server::Storage;
use sb_plugin_sdk::sb_proto::{
    AbortIncompleteRequest, AbortIncompleteResponse, DeleteRequest, DeleteResponse, GetRequest,
    ListRequest, ListResponse, PutRequest,
};
use sb_plugin_sdk::tonic::{Request, Response, Status};

use crate::cliente::Estado;

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
        let contexto = self.estado.resuelta()?;
        let clave = contexto.config.clave(&peticion.into_inner().key);
        Err(Status::unimplemented(format!(
            "el destino r2 todavía no sabe subir `{clave}`"
        )))
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
