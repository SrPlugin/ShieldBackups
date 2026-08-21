//! Los cinco RPC que todo plugin implementa.

use sb_plugin_sdk::sb_proto::plugin_server::Plugin;
use sb_plugin_sdk::sb_proto::{
    Capability, Check, ConfigureRequest, ConfigureResponse, InfoRequest, InfoResponse,
    PROTOCOL_VERSION, PreflightRequest, PreflightResponse, SchemaRequest, SchemaResponse,
    ShutdownRequest, ShutdownResponse,
};
use sb_plugin_sdk::tonic::{Request, Response, Status};

use crate::cliente::{Contexto, Estado};
use crate::config::{self, R2Config};

/// Nombre con el que el plugin se identifica ante el núcleo.
pub const NOMBRE: &str = "r2";

pub struct PluginR2 {
    estado: Estado,
}

impl PluginR2 {
    #[must_use]
    pub fn new(estado: Estado) -> Self {
        Self { estado }
    }
}

#[sb_plugin_sdk::tonic::async_trait]
impl Plugin for PluginR2 {
    async fn info(&self, _: Request<InfoRequest>) -> Result<Response<InfoResponse>, Status> {
        Ok(Response::new(InfoResponse {
            name: NOMBRE.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            protocol_version: PROTOCOL_VERSION,
            // Solo destino: R2 guarda artefactos, no sabe volcar nada.
            capabilities: vec![Capability::Storage as i32],
        }))
    }

    async fn schema(&self, _: Request<SchemaRequest>) -> Result<Response<SchemaResponse>, Status> {
        Ok(Response::new(SchemaResponse {
            fields: config::esquema(),
        }))
    }

    async fn configure(
        &self,
        peticion: Request<ConfigureRequest>,
    ) -> Result<Response<ConfigureResponse>, Status> {
        let config = R2Config::from_values(&peticion.into_inner().config)?;
        // El cliente se construye aquí y no en cada RPC: es donde el núcleo
        // espera que la configuración se valide, y montar el pool de
        // conexiones una vez ahorra hacerlo por artefacto.
        let cliente = crate::cliente::construir(&config);
        tracing::info!(
            bucket = %config.bucket,
            endpoint = %config.endpoint(),
            part_size = config.part_size,
            clase = config.storage_class.como_str(),
            "plugin r2 configurado"
        );
        self.estado.guardar(Contexto { config, cliente });
        Ok(Response::new(ConfigureResponse {}))
    }

    async fn preflight(
        &self,
        _: Request<PreflightRequest>,
    ) -> Result<Response<PreflightResponse>, Status> {
        // Preflight **no** devuelve `failed_precondition` sin configuración: es
        // el RPC de diagnóstico y `doctor` necesita un informe que explique qué
        // falta, no un error que lo interrumpa.
        let Ok(contexto) = self.estado.resuelta() else {
            let check = Check {
                name: "configuración".into(),
                ok: false,
                detail: "el plugin todavía no recibió su configuración".into(),
                remediation: format!(
                    "llama a Configure con `{}`, `{}` y las dos claves antes de Preflight",
                    config::CAMPO_ACCOUNT_ID,
                    config::CAMPO_BUCKET
                ),
            };
            return Ok(Response::new(PreflightResponse {
                ok: false,
                checks: vec![check],
                server_version: String::new(),
            }));
        };

        let check = comprobar_bucket(&contexto).await;
        Ok(Response::new(PreflightResponse {
            ok: check.ok,
            checks: vec![check],
            server_version: format!("cloudflare-r2 ({})", contexto.config.endpoint()),
        }))
    }

    async fn shutdown(
        &self,
        _: Request<ShutdownRequest>,
    ) -> Result<Response<ShutdownResponse>, Status> {
        tracing::info!("cierre solicitado");
        Ok(Response::new(ShutdownResponse {}))
    }
}

/// El único requisito real del destino: que el bucket exista y que el token
/// tenga acceso.
///
/// `HeadBucket` es la comprobación más barata que distingue las tres cosas que
/// se pueden haber escrito mal —cuenta, bucket y credenciales— y no escribe
/// nada.
async fn comprobar_bucket(contexto: &Contexto) -> Check {
    let bucket = &contexto.config.bucket;
    match contexto
        .cliente
        .head_bucket()
        .bucket(bucket)
        .send()
        .await
        .map_err(|e| crate::cliente::traducir("HeadBucket", &e))
    {
        Ok(_) => Check {
            name: "bucket".into(),
            ok: true,
            detail: format!("`{bucket}` accesible en {}", contexto.config.endpoint()),
            remediation: String::new(),
        },
        Err(e) => Check {
            name: "bucket".into(),
            ok: false,
            detail: e.to_string(),
            remediation: format!(
                "comprueba que el bucket `{bucket}` existe en la cuenta `{}` y que el token de R2 tiene permiso de lectura y escritura sobre él",
                contexto.config.account_id
            ),
        },
    }
}
