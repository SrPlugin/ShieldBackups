//! El destino R2.
//!
//! Los cinco RPC son finos a propósito: cada uno resuelve con un `?` lo que se
//! puede saber **antes** de mover un byte —la configuración, la clave, la
//! ausencia del objeto— y delega el resto en el módulo que lleva lo delicado
//! ([`crate::put`], [`crate::get`], [`crate::admin`]).
//!
//! Esa división no es estética. Una vez que [`stream_de_progreso`] responde al
//! RPC, el error ya no puede volver como `Status` de la llamada: solo por el
//! flujo de progreso, donde el núcleo lo trata como una transferencia cortada.
//! «Ese artefacto no existe» y «la descarga se cortó» son cosas distintas para
//! quien restaura, así que la primera se decide arriba.
//!
//! Cada RPC exige antes la configuración, así que un núcleo que se saltara
//! `Configure` se entera por el primer RPC que haga y no por el segundo.

use sb_plugin_sdk::sb_proto::storage_server::Storage;
use sb_plugin_sdk::sb_proto::{
    AbortIncompleteRequest, AbortIncompleteResponse, ArtifactMeta, DeleteRequest, DeleteResponse,
    GetRequest, ListRequest, ListResponse, PutRequest,
};
use sb_plugin_sdk::tonic::{Request, Response, Status};
use sb_plugin_sdk::{ProgresoStream, stream_de_progreso};

use crate::cliente::Estado;
use crate::{admin, get, put};

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
        let GetRequest { key, data_socket } = peticion.into_inner();
        let clave = contexto.config.clave(&key);
        // El `GetObject` se pide **antes** de responder, y solo se piden las
        // cabeceras: el cuerpo llega perezoso y se vuelca luego. Así un
        // artefacto que no está se contesta como `not_found` de la llamada, que
        // es lo que el núcleo sabe distinguir de un corte a mitad. Nada de esto
        // toca todavía el socket de datos, que es lo que el protocolo prohíbe
        // hacer antes de responder.
        let cuerpo = get::pedir(&contexto, &clave).await?;
        Ok(stream_de_progreso(move |mut progreso| async move {
            get::volcar(cuerpo, &data_socket, &mut progreso).await?;
            progreso.terminar("artefacto entregado").await;
            tracing::info!(clave = %clave, bytes = progreso.bytes(), "artefacto descargado de R2");
            Ok(())
        }))
    }

    async fn list(&self, peticion: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        let contexto = self.estado.resuelta()?;
        let prefijo = contexto.config.clave(&peticion.into_inner().prefix);
        // `admin::listar` recorre **todas** las páginas: una lista truncada no
        // se nota y haría que `verify --all` diera por buenos artefactos que ni
        // siquiera miró.
        let encontrados = admin::listar(&contexto, &prefijo).await?;
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
        let contexto = self.estado.resuelta()?;
        let clave = contexto.config.clave(&peticion.into_inner().key);
        admin::borrar(&contexto, &clave).await?;
        Ok(Response::new(DeleteResponse {}))
    }

    async fn abort_incomplete(
        &self,
        peticion: Request<AbortIncompleteRequest>,
    ) -> Result<Response<AbortIncompleteResponse>, Status> {
        let contexto = self.estado.resuelta()?;
        let prefijo = contexto.config.clave(&peticion.into_inner().prefix);
        let abortadas = admin::abortar_incompletos(&contexto, &prefijo).await?;
        if abortadas > 0 {
            tracing::warn!(
                abortadas,
                prefijo = %prefijo,
                "subidas multipart incompletas eliminadas: dejaban de facturarse ahora"
            );
        }
        Ok(Response::new(AbortIncompleteResponse {
            aborted: abortadas,
        }))
    }
}
