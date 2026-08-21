//! Que `Shutdown` termine el proceso, sin que el plugin tenga que acordarse.
//!
//! El núcleo llama a `Shutdown` esperando un cierre ordenado. Un plugin no
//! tiene forma de terminarse a sí mismo desde el cuerpo de un RPC —el que
//! decide cuándo se acaba el proceso es [`crate::PluginRuntime::serve`]—, así
//! que el SDK **intercepta** la llamada: envuelve el servicio `Plugin` del
//! plugin, delega en su implementación y, pase lo que pase, dispara la señal de
//! parada.
//!
//! Se eligió interceptar en vez de entregarle al plugin un handle que guardar y
//! usar: un handle se puede olvidar, y olvidarlo devuelve el fallo original —un
//! proceso que sobrevive a su propio `Shutdown` hasta que lo matan—. Aquí no
//! hay nada que olvidar, ni forma de desactivarlo.

use std::sync::Arc;

use sb_proto::plugin_server::Plugin;
use sb_proto::{
    ConfigureRequest, ConfigureResponse, InfoRequest, InfoResponse, PreflightRequest,
    PreflightResponse, SchemaRequest, SchemaResponse, ShutdownRequest, ShutdownResponse,
};
use tokio::sync::Notify;
use tonic::{Request, Response, Status};

/// Aviso de «hay que parar», de la interceptación de `Shutdown` a `serve`.
#[derive(Clone, Default)]
pub(crate) struct SenalDeCierre(Arc<Notify>);

impl SenalDeCierre {
    /// Pide la parada. Es idempotente y no bloquea.
    fn disparar(&self) {
        // `notify_one` guarda el permiso si todavía nadie espera, así que la
        // señal no se pierde aunque `serve` aún no haya llegado a su `select`.
        self.0.notify_one();
    }

    /// Se resuelve cuando alguien pidió la parada.
    pub(crate) async fn esperar(&self) {
        self.0.notified().await;
    }
}

/// El servicio `Plugin` del plugin, con `Shutdown` interceptado.
///
/// Los otros cuatro RPC pasan de largo: el envoltorio no añade nada a `Info`,
/// `Schema`, `Configure` ni `Preflight`, y se limita a delegar.
pub(crate) struct PluginConCierre<P> {
    interno: P,
    senal: SenalDeCierre,
}

impl<P> PluginConCierre<P> {
    pub(crate) fn nuevo(interno: P, senal: SenalDeCierre) -> Self {
        Self { interno, senal }
    }
}

#[tonic::async_trait]
impl<P: Plugin> Plugin for PluginConCierre<P> {
    async fn info(&self, p: Request<InfoRequest>) -> Result<Response<InfoResponse>, Status> {
        self.interno.info(p).await
    }

    async fn schema(&self, p: Request<SchemaRequest>) -> Result<Response<SchemaResponse>, Status> {
        self.interno.schema(p).await
    }

    async fn configure(
        &self,
        p: Request<ConfigureRequest>,
    ) -> Result<Response<ConfigureResponse>, Status> {
        self.interno.configure(p).await
    }

    async fn preflight(
        &self,
        p: Request<PreflightRequest>,
    ) -> Result<Response<PreflightResponse>, Status> {
        self.interno.preflight(p).await
    }

    /// Delega y **después** pide la parada.
    ///
    /// El orden importa: primero corre el `Shutdown` del plugin —cerrar
    /// conexiones, vaciar buffers—, y solo entonces se pide terminar. Además se
    /// pide **aunque la implementación devuelva error**: el contrato que ve el
    /// núcleo es «llamar a Shutdown termina el proceso», y un plugin que se
    /// quejara al cerrar no puede convertirse en un plugin que no se cierra.
    /// El error se le devuelve igualmente al núcleo, que así se entera de que
    /// el cierre no fue limpio.
    async fn shutdown(
        &self,
        p: Request<ShutdownRequest>,
    ) -> Result<Response<ShutdownResponse>, Status> {
        let resultado = self.interno.shutdown(p).await;
        if let Err(e) = &resultado {
            tracing::warn!(error = %e, "el plugin falló al cerrar; se termina igualmente");
        }
        self.senal.disparar();
        resultado
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// Un plugin que apunta si le llamaron y puede fingir un fallo al cerrar.
    #[derive(Default)]
    struct Espia {
        cerrado: AtomicBool,
        falla_al_cerrar: bool,
    }

    #[tonic::async_trait]
    impl Plugin for Espia {
        async fn info(&self, _: Request<InfoRequest>) -> Result<Response<InfoResponse>, Status> {
            Ok(Response::new(InfoResponse {
                name: "espia".into(),
                ..InfoResponse::default()
            }))
        }
        async fn schema(
            &self,
            _: Request<SchemaRequest>,
        ) -> Result<Response<SchemaResponse>, Status> {
            Ok(Response::new(SchemaResponse::default()))
        }
        async fn configure(
            &self,
            _: Request<ConfigureRequest>,
        ) -> Result<Response<ConfigureResponse>, Status> {
            Ok(Response::new(ConfigureResponse::default()))
        }
        async fn preflight(
            &self,
            _: Request<PreflightRequest>,
        ) -> Result<Response<PreflightResponse>, Status> {
            Ok(Response::new(PreflightResponse::default()))
        }
        async fn shutdown(
            &self,
            _: Request<ShutdownRequest>,
        ) -> Result<Response<ShutdownResponse>, Status> {
            self.cerrado.store(true, Ordering::SeqCst);
            if self.falla_al_cerrar {
                return Err(Status::internal("no pude cerrar"));
            }
            Ok(Response::new(ShutdownResponse::default()))
        }
    }

    /// `true` si la señal ya está disparada, sin quedarse colgado si no lo está.
    async fn disparada(senal: &SenalDeCierre) -> bool {
        tokio::time::timeout(Duration::from_millis(100), senal.esperar())
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn shutdown_dispara_la_senal_aunque_el_plugin_no_haga_nada() {
        // El plugin de humo no hace nada en su `shutdown` y aun así el proceso
        // debe terminar: esa es la razón de interceptar.
        let senal = SenalDeCierre::default();
        let envuelto = PluginConCierre::nuevo(Espia::default(), senal.clone());

        assert!(
            !disparada(&senal).await,
            "no debe estar disparada de salida"
        );
        envuelto
            .shutdown(Request::new(ShutdownRequest {}))
            .await
            .unwrap();
        assert!(disparada(&senal).await);
    }

    #[tokio::test]
    async fn el_shutdown_del_plugin_se_ejecuta_antes_de_parar() {
        let senal = SenalDeCierre::default();
        let envuelto = PluginConCierre::nuevo(Espia::default(), senal.clone());
        envuelto
            .shutdown(Request::new(ShutdownRequest {}))
            .await
            .unwrap();
        assert!(
            envuelto.interno.cerrado.load(Ordering::SeqCst),
            "el cierre del plugin debe correr antes de que se pida terminar"
        );
    }

    #[tokio::test]
    async fn un_plugin_que_falla_al_cerrar_termina_igualmente() {
        let senal = SenalDeCierre::default();
        let envuelto = PluginConCierre::nuevo(
            Espia {
                falla_al_cerrar: true,
                ..Espia::default()
            },
            senal.clone(),
        );
        let e = envuelto
            .shutdown(Request::new(ShutdownRequest {}))
            .await
            .unwrap_err();
        // El núcleo se entera de que el cierre no fue limpio...
        assert_eq!(e.code(), tonic::Code::Internal);
        // ...y el proceso se cierra de todas formas.
        assert!(disparada(&senal).await);
    }

    #[tokio::test]
    async fn los_demas_rpc_no_paran_el_plugin() {
        let senal = SenalDeCierre::default();
        let envuelto = PluginConCierre::nuevo(Espia::default(), senal.clone());

        assert_eq!(
            envuelto
                .info(Request::new(InfoRequest {}))
                .await
                .unwrap()
                .into_inner()
                .name,
            "espia"
        );
        envuelto
            .schema(Request::new(SchemaRequest {}))
            .await
            .unwrap();
        envuelto
            .configure(Request::new(ConfigureRequest::default()))
            .await
            .unwrap();
        envuelto
            .preflight(Request::new(PreflightRequest {}))
            .await
            .unwrap();

        assert!(!disparada(&senal).await, "solo Shutdown puede parar");
    }
}
