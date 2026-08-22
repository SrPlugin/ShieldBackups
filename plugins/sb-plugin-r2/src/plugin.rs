//! Los cinco RPC que todo plugin implementa.

use aws_sdk_s3::primitives::ByteStream;
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
        self.estado.store(Contexto { config, cliente });
        Ok(Response::new(ConfigureResponse {}))
    }

    async fn preflight(
        &self,
        _: Request<PreflightRequest>,
    ) -> Result<Response<PreflightResponse>, Status> {
        // Preflight **no** devuelve `failed_precondition` sin configuración: es
        // el RPC de diagnóstico y `doctor` necesita un informe que explique qué
        // falta, no un error que lo interrumpa.
        let Ok(contexto) = self.estado.resolved() else {
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

        // Los tres en orden de dependencia: sin bucket accesible los otros dos
        // no dicen nada nuevo, pero se ejecutan igual porque `doctor` sirve
        // para ver **todo** lo que está mal de una vez, no lo primero.
        let checks = vec![
            comprobar_bucket(&contexto).await,
            comprobar_escritura(&contexto).await,
            comprobar_listado(&contexto).await,
        ];
        Ok(Response::new(PreflightResponse {
            ok: checks.iter().all(|c| c.ok),
            checks,
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

/// Prefijo bajo el que el preflight escribe su objeto de prueba.
///
/// Empieza por punto y se nombra a sí mismo para que, si alguna vez queda un
/// residuo, quien mire el bucket sepa de dónde salió y que puede borrarlo.
const PREFIJO_PREFLIGHT: &str = ".shieldbk-preflight";

/// Contenido del objeto de prueba. Diminuto: lo que se comprueba es el
/// permiso, no el ancho de banda.
const CUERPO_PREFLIGHT: &[u8] = b"shieldbk preflight\n";

/// La clave del objeto de prueba de este proceso.
///
/// Lleva el PID para que dos `doctor` a la vez —o uno en cada máquina— no se
/// pisen el objeto y se borren la prueba el uno al otro.
fn clave_de_prueba(contexto: &Contexto) -> String {
    contexto
        .config
        .clave(&format!("{PREFIJO_PREFLIGHT}/{}", std::process::id()))
}

/// Comprueba que se puede **escribir de verdad**, subiendo un objeto diminuto
/// y borrándolo después.
///
/// Es la única comprobación fiable, y por eso escribe en vez de preguntar. Un
/// token con `s3:ListBucket` concedido y `s3:PutObject` denegado responde que
/// sí a cualquier chequeo pasivo; una policy de bucket que exija SSE-KMS con
/// una clave a la que el rol no llega, también. Las dos revientan en el primer
/// `PUT`, a mitad del primer backup nocturno y con el volcado ya hecho.
///
/// Si el objeto se sube pero no se puede borrar, el check queda **en verde**
/// con la advertencia en el detalle: lo que se venía a comprobar se comprobó, y
/// lo único que queda es un objeto de veinte bytes que alguien tendrá que
/// quitar.
async fn comprobar_escritura(contexto: &Contexto) -> Check {
    let clave = clave_de_prueba(contexto);
    let bucket = &contexto.config.bucket;

    if let Err(e) = contexto
        .cliente
        .put_object()
        .bucket(bucket)
        .key(&clave)
        // Sin `storage_class`: va a la clase estándar aunque el destino esté
        // configurado como `InfrequentAccess`, porque esa clase factura un
        // mínimo de treinta días de almacenamiento y este objeto vive
        // segundos. Lo que se comprueba es el permiso de escritura, y ese es
        // el mismo para las dos clases.
        .body(ByteStream::from_static(CUERPO_PREFLIGHT))
        .send()
        .await
        .map_err(|e| crate::cliente::traducir("PutObject", &e))
    {
        return Check {
            name: "escritura".into(),
            ok: false,
            detail: format!("no se pudo escribir `{clave}`: {e}"),
            remediation: format!(
                "dale al token de R2 permiso de escritura (`PutObject`) sobre `{bucket}`; si el bucket tiene una policy que exige cifrado con una clave gestionada, comprueba que el token puede usarla"
            ),
        };
    }

    // Escrito. A partir de aquí el check ya es verde: lo que falte es residuo,
    // no un impedimento para hacer backups.
    match crate::admin::borrar(contexto, &clave).await {
        Ok(()) => Check {
            name: "escritura".into(),
            ok: true,
            detail: format!("objeto de prueba escrito y borrado en `{bucket}`"),
            remediation: String::new(),
        },
        Err(e) => Check {
            name: "escritura".into(),
            ok: true,
            detail: format!(
                "se pudo escribir en `{bucket}`, que es lo que se comprobaba, pero el objeto de prueba `{clave}` no se pudo borrar y queda ahí: {}",
                e.message()
            ),
            remediation: format!(
                "borra `{clave}` a mano y añade el permiso `DeleteObject` al token, que también lo necesita la retención"
            ),
        },
    }
}

/// Comprueba que se puede listar el bucket.
///
/// Pide una sola clave: lo que se comprueba es el permiso, y traerse mil
/// nombres para eso sería trabajo tirado. Sin listado no hay `verify --all` ni
/// retención, aunque los backups se sigan escribiendo.
async fn comprobar_listado(contexto: &Contexto) -> Check {
    let bucket = &contexto.config.bucket;
    match contexto
        .cliente
        .list_objects_v2()
        .bucket(bucket)
        .prefix(contexto.config.clave(""))
        .max_keys(1)
        .send()
        .await
        .map_err(|e| crate::cliente::traducir("ListObjectsV2", &e))
    {
        Ok(_) => Check {
            name: "listado".into(),
            ok: true,
            detail: format!("`{bucket}` se puede listar"),
            remediation: String::new(),
        },
        Err(e) => Check {
            name: "listado".into(),
            ok: false,
            detail: e.to_string(),
            remediation: format!(
                "dale al token de R2 permiso de listado (`ListBucket`) sobre `{bucket}`: sin él no hay `verify --all` ni retención, aunque los backups se sigan escribiendo"
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::R2Config;
    use sb_plugin_sdk::sb_proto::{Value, value::Kind};
    use std::collections::HashMap;

    fn contexto(prefijo: &str) -> Contexto {
        let valores: HashMap<String, Value> = [
            ("account_id", "abc123"),
            ("bucket", "backups"),
            ("access_key_id", "AKIAEJEMPLO"),
            ("secret_access_key", "secreta"),
            ("prefix", prefijo),
        ]
        .into_iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                Value {
                    kind: Some(Kind::StringValue(v.to_string())),
                },
            )
        })
        .collect();
        let config = R2Config::from_values(&valores).unwrap();
        let cliente = crate::cliente::construir(&config);
        Contexto { config, cliente }
    }

    #[test]
    fn el_objeto_de_prueba_vive_dentro_del_prefijo_configurado() {
        // Escribir fuera del prefijo es escribir en el bucket de otro: el
        // permiso del token puede estar acotado justo a este prefijo, y el
        // preflight fallaría por escribir donde no le toca.
        let clave = clave_de_prueba(&contexto("equipo/backups"));
        assert!(
            clave.starts_with("equipo/backups/"),
            "la clave de prueba se salió del prefijo: {clave}"
        );
        assert!(clave.contains(PREFIJO_PREFLIGHT));
    }

    #[test]
    fn dos_procesos_a_la_vez_no_se_pisan_el_objeto_de_prueba() {
        // El PID es lo que lo evita; aquí solo se comprueba que está.
        let clave = clave_de_prueba(&contexto(""));
        assert!(
            clave.ends_with(&std::process::id().to_string()),
            "la clave de prueba no lleva el PID: {clave}"
        );
    }

    #[test]
    fn el_cuerpo_de_prueba_es_diminuto() {
        // Se comprueba el permiso, no el ancho de banda: un preflight que
        // subiera megabytes se ejecutaría menos veces de las que hace falta.
        assert!(CUERPO_PREFLIGHT.len() < 128);
        assert!(!CUERPO_PREFLIGHT.is_empty(), "un objeto vacío prueba menos");
    }
}
