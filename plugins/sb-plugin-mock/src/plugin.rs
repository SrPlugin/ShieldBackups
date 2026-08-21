//! Los cinco RPC que todo plugin implementa.

use sb_plugin_sdk::sb_proto::plugin_server::Plugin;
use sb_plugin_sdk::sb_proto::{
    Capability, Check, ConfigureRequest, ConfigureResponse, InfoRequest, InfoResponse,
    PROTOCOL_VERSION, PreflightRequest, PreflightResponse, SchemaRequest, SchemaResponse,
    ShutdownRequest, ShutdownResponse,
};
use sb_plugin_sdk::tonic::{Request, Response, Status};

use crate::config::{self, Config, Estado};

/// Nombre con el que el plugin se identifica ante el núcleo.
pub const NOMBRE: &str = "mock";

pub struct PluginMock {
    estado: Estado,
}

impl PluginMock {
    #[must_use]
    pub fn new(estado: Estado) -> Self {
        Self { estado }
    }
}

#[sb_plugin_sdk::tonic::async_trait]
impl Plugin for PluginMock {
    async fn info(&self, _: Request<InfoRequest>) -> Result<Response<InfoResponse>, Status> {
        Ok(Response::new(InfoResponse {
            name: NOMBRE.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            protocol_version: PROTOCOL_VERSION,
            capabilities: vec![Capability::Engine as i32, Capability::Storage as i32],
        }))
    }

    async fn schema(&self, _: Request<SchemaRequest>) -> Result<Response<SchemaResponse>, Status> {
        Ok(Response::new(SchemaResponse {
            fields: config::campos(),
        }))
    }

    async fn configure(
        &self,
        peticion: Request<ConfigureRequest>,
    ) -> Result<Response<ConfigureResponse>, Status> {
        let config = Config::desde_mapa(&peticion.into_inner().config)?;
        tracing::info!(
            dir = %config.dir.display(),
            seed = config.seed,
            size = config.size,
            "plugin mock configurado"
        );
        self.estado.guardar(config);
        Ok(Response::new(ConfigureResponse {}))
    }

    async fn preflight(
        &self,
        _: Request<PreflightRequest>,
    ) -> Result<Response<PreflightResponse>, Status> {
        // Preflight **no** devuelve `failed_precondition` sin configuración: es
        // el RPC de diagnóstico, y `doctor` necesita un informe que explique
        // qué falta, no un error que lo interrumpa.
        let check = match self.estado.resuelta() {
            Ok(config) => comprobar_directorio(&config),
            Err(_) => Check {
                name: "configuración".into(),
                ok: false,
                detail: "el plugin todavía no recibió su configuración".into(),
                remediation: format!(
                    "llama a Configure con el campo `{}` antes de Preflight",
                    config::CAMPO_DIR
                ),
            },
        };
        Ok(Response::new(PreflightResponse {
            ok: check.ok,
            checks: vec![check],
            server_version: NOMBRE.into(),
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

/// El único requisito real del plugin: poder escribir en `dir`.
fn comprobar_directorio(config: &Config) -> Check {
    let dir = &config.dir;
    if dir.is_dir() {
        return Check {
            name: "directorio".into(),
            ok: true,
            detail: format!("{} existe", dir.display()),
            remediation: String::new(),
        };
    }
    match std::fs::create_dir_all(dir) {
        Ok(()) => Check {
            name: "directorio".into(),
            ok: true,
            detail: format!("{} creado", dir.display()),
            remediation: String::new(),
        },
        Err(e) => Check {
            name: "directorio".into(),
            ok: false,
            detail: format!("no se pudo crear {}: {e}", dir.display()),
            remediation: format!(
                "crea {} a mano o apunta `{}` a una ruta donde este usuario pueda escribir",
                dir.display(),
                config::CAMPO_DIR
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn el_preflight_crea_el_directorio_si_falta() {
        let raiz = tempfile::tempdir().unwrap();
        let dir = raiz.path().join("sin/crear");
        let check = comprobar_directorio(&Config {
            dir: dir.clone(),
            seed: 1,
            size: 0,
        });
        assert!(check.ok, "{}", check.detail);
        assert!(dir.is_dir());
    }

    #[test]
    fn el_preflight_falla_con_remedio_si_no_puede_crearlo() {
        // Un fichero ocupando el sitio del directorio: no se puede crear.
        let raiz = tempfile::tempdir().unwrap();
        let estorbo = raiz.path().join("estorbo");
        std::fs::write(&estorbo, b"no soy un directorio").unwrap();
        let check = comprobar_directorio(&Config {
            dir: estorbo.join("dentro"),
            seed: 1,
            size: 0,
        });
        assert!(!check.ok);
        assert!(
            !check.remediation.is_empty(),
            "un check que falla sin remedio no sirve de nada"
        );
    }

    #[test]
    fn un_directorio_existente_pasa_sin_tocar_nada() {
        let raiz = tempfile::tempdir().unwrap();
        let check = comprobar_directorio(&Config {
            dir: PathBuf::from(raiz.path()),
            seed: 1,
            size: 0,
        });
        assert!(check.ok);
        assert!(check.remediation.is_empty());
    }
}
