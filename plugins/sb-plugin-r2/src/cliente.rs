//! Construcción del cliente S3 que habla con Cloudflare R2.
//!
//! R2 expone el protocolo de S3, pero **no es S3**, y hay tres ajustes sin los
//! cuales el SDK de AWS genera peticiones que R2 rechaza. Están todos aquí, en
//! un único sitio, cada uno con el motivo por el que existe: descubrirlos
//! cuesta una tarde de errores 400 sin explicación.

use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Region, RequestChecksumCalculation, ResponseChecksumValidation};
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use sb_plugin_sdk::tonic::Status;

use crate::config::R2Config;

/// La región con la que se firma.
///
/// R2 no tiene regiones —hay un solo endpoint por cuenta—, pero `SigV4` mete la
/// región en la cadena que firma, así que hay que darle una. Cloudflare
/// documenta `auto` como la que su servicio espera; cualquier otra hace que la
/// firma no cuadre.
const REGION: &str = "auto";

/// Nombre con el que las credenciales se identifican en las trazas del SDK.
/// No es un secreto y no viaja en la petición.
const PROVEEDOR: &str = "shieldbk-r2";

/// Lo que puede fallar al hablar con R2.
///
/// Ninguna variante lleva dentro el error del SDK de AWS: ese error arrastra la
/// petición que lo provocó —cabeceras incluidas, y entre ellas la de
/// autorización— y acabaría en un log. De cada fallo se extrae solo lo que le
/// sirve a quien lo lea: la operación, el código que devolvió R2 y el estado
/// HTTP.
#[derive(Debug, thiserror::Error)]
pub enum ErrorDeR2 {
    #[error("R2 respondió a `{operacion}` con el estado HTTP {estado} y el código `{codigo}`")]
    Servicio {
        operacion: &'static str,
        estado: u16,
        codigo: String,
    },
    #[error("no se pudo contactar con el endpoint de R2 al ejecutar `{operacion}`")]
    Transporte { operacion: &'static str },
    #[error("`{operacion}` agotó su tiempo de espera contra R2")]
    Tiempo { operacion: &'static str },
    #[error("no se pudo construir la petición `{operacion}` para R2")]
    Peticion { operacion: &'static str },
    #[error("la respuesta de R2 a `{operacion}` no se pudo interpretar")]
    Respuesta { operacion: &'static str },
    #[error("`{operacion}` falló contra R2 por un motivo que este plugin no sabe clasificar")]
    Desconocido { operacion: &'static str },
}

impl ErrorDeR2 {
    /// Si el fallo es «eso no está»: un objeto que no existe.
    ///
    /// Lo usan la descarga —para responder `not_found` con la clave— y el
    /// borrado, que es idempotente y trata la ausencia como el resultado que se
    /// pedía.
    ///
    /// Se excluye `NoSuchBucket` a propósito: también viene con un 404, pero un
    /// bucket que falta es un problema de configuración y no puede pasar por
    /// «ese artefacto ya no estaba».
    #[must_use]
    pub fn es_ausencia(&self) -> bool {
        matches!(
            self,
            Self::Servicio {
                estado: 404,
                codigo,
                ..
            } if codigo != "NoSuchBucket"
        )
    }
}

/// Cómo llega al núcleo un fallo contra R2.
///
/// El mensaje es el de [`ErrorDeR2`], que ya está depurado; lo único que se
/// añade es el código gRPC, para que el núcleo sepa si tiene sentido
/// reintentar. Un 403 y un 500 de R2 no se parecen en nada desde el otro lado.
impl From<ErrorDeR2> for Status {
    fn from(e: ErrorDeR2) -> Self {
        let texto = e.to_string();
        match e {
            ErrorDeR2::Servicio { estado, .. } => match estado {
                401 | 403 => Self::permission_denied(texto),
                404 => Self::not_found(texto),
                // Un 5xx de R2 es el caso en el que reintentar sirve de algo.
                500..=599 => Self::unavailable(texto),
                _ => Self::internal(texto),
            },
            ErrorDeR2::Transporte { .. } => Self::unavailable(texto),
            ErrorDeR2::Tiempo { .. } => Self::deadline_exceeded(texto),
            _ => Self::internal(texto),
        }
    }
}

/// Traduce un error del SDK de AWS a uno nuestro, quedándose solo con lo que
/// se puede enseñar.
pub fn traducir<E: ProvideErrorMetadata>(
    operacion: &'static str,
    error: &SdkError<E>,
) -> ErrorDeR2 {
    match error {
        SdkError::ServiceError(e) => ErrorDeR2::Servicio {
            operacion,
            estado: e.raw().status().as_u16(),
            // `code()` es el código corto de S3 —`NoSuchBucket`,
            // `AccessDenied`—, que es texto del servicio y no de la petición.
            codigo: e.err().code().unwrap_or("desconocido").to_string(),
        },
        SdkError::DispatchFailure(_) => ErrorDeR2::Transporte { operacion },
        SdkError::TimeoutError(_) => ErrorDeR2::Tiempo { operacion },
        SdkError::ConstructionFailure(_) => ErrorDeR2::Peticion { operacion },
        SdkError::ResponseError(_) => ErrorDeR2::Respuesta { operacion },
        // `SdkError` es `non_exhaustive`: una variante nueva del SDK no puede
        // colarse con su mensaje original hacia el log.
        _ => ErrorDeR2::Desconocido { operacion },
    }
}

/// El cliente S3 apuntando a R2, con las credenciales de la configuración.
///
/// Las credenciales se pasan explícitas y no se consulta la cadena de
/// proveedores de AWS: un plugin recibe su configuración del núcleo, y dejar
/// que el entorno del proceso —variables, `~/.aws/credentials`, IMDS— pudiera
/// aportar otras haría que el backup se escribiera en una cuenta que nadie
/// pidió.
#[must_use]
pub fn construir(config: &R2Config) -> Client {
    let credenciales = Credentials::new(
        config.access_key_id(),
        config.secret_access_key(),
        None,
        None,
        PROVEEDOR,
    );

    let s3 = aws_sdk_s3::Config::builder()
        // Sin la feature `behavior-version-latest`, el SDK exige que la versión
        // de comportamiento se fije aquí en vez de deducirla.
        .behavior_version(BehaviorVersion::latest())
        // 1. R2 no tiene regiones, pero SigV4 firma incluyéndolas; `auto` es la
        //    que Cloudflare documenta.
        .region(Region::new(REGION))
        .endpoint_url(config.endpoint())
        .credentials_provider(credenciales)
        // 2. Estilo de ruta: el endpoint de R2 es de cuenta, no de bucket, así
        //    que el bucket va en la ruta. Con el estilo virtual el SDK lo
        //    metería en el host —`bucket.cuenta.r2.cloudflarestorage.com`— y
        //    ese nombre no resuelve.
        .force_path_style(true)
        // 3. Checksums solo cuando la operación los exige. Las versiones
        //    recientes del SDK añaden por defecto un checksum adicional
        //    (CRC32 en `x-amz-checksum-*`, y con cuerpos en streaming lo manda
        //    como trailer con `aws-chunked`) que R2 no siempre acepta: el
        //    fallo es un 400 sin explicación. No perdemos integridad: la que
        //    cuenta es el SHA-256 que el núcleo calcula sobre el artefacto
        //    cifrado y guarda en el manifiesto.
        .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
        .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
        .build();

    Client::from_conf(s3)
}

/// La configuración y el cliente que sale de ella, juntos.
///
/// Se construye una vez en `Configure` y la comparten el servicio `Plugin` y el
/// destino: construir el cliente en cada RPC volvería a montar el pool de
/// conexiones y el resolutor de endpoints en cada artefacto.
#[derive(Clone)]
pub struct Contexto {
    pub config: R2Config,
    pub cliente: Client,
}

/// El contexto compartido entre los servicios del plugin.
pub type Estado = sb_plugin_sdk::Configurado<Contexto>;

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::operation::head_bucket::HeadBucketError;
    use sb_plugin_sdk::sb_proto::{Value, value::Kind};
    use std::collections::HashMap;

    const SECRETO: &str = "clave-secreta-que-no-debe-salir";

    fn valores() -> HashMap<String, Value> {
        [
            ("account_id", "abc123"),
            ("bucket", "backups"),
            ("access_key_id", "AKIAEJEMPLO"),
            ("secret_access_key", SECRETO),
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
        .collect()
    }

    #[test]
    fn el_cliente_se_construye_con_la_configuracion_del_nucleo() {
        // Construirlo ya es una afirmación: sin `behavior_version` el SDK
        // entra en pánico al montar la configuración.
        let config = R2Config::from_values(&valores()).unwrap();
        let cliente = construir(&config);
        assert_eq!(cliente.config().signing_name(), "s3");
    }

    #[test]
    fn la_region_es_auto_porque_sigv4_exige_una() {
        let config = R2Config::from_values(&valores()).unwrap();
        let cliente = construir(&config);
        assert_eq!(cliente.config().region().map(Region::as_ref), Some(REGION));
    }

    #[test]
    fn los_checksums_solo_se_calculan_cuando_hacen_falta() {
        let config = R2Config::from_values(&valores()).unwrap();
        let cliente = construir(&config);
        assert_eq!(
            cliente.config().request_checksum_calculation(),
            Some(&RequestChecksumCalculation::WhenRequired)
        );
        assert_eq!(
            cliente.config().response_checksum_validation(),
            Some(&ResponseChecksumValidation::WhenRequired)
        );
    }

    #[test]
    fn un_error_del_sdk_no_arrastra_su_mensaje_original() {
        // El error de una librería de terceros puede llevar dentro la petición
        // que lo provocó, cabecera de autorización incluida. Se traduce, no se
        // propaga.
        #[derive(Debug)]
        struct Fuga(String);
        impl std::fmt::Display for Fuga {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "Authorization: AWS4-HMAC-SHA256 {}", self.0)
            }
        }
        impl std::error::Error for Fuga {}

        let original: SdkError<HeadBucketError> =
            SdkError::timeout_error(Box::new(Fuga(SECRETO.to_string())));
        assert!(original.to_string().contains("timeout") || !original.to_string().is_empty());

        let traducido = traducir("HeadBucket", &original);
        let texto = traducido.to_string();
        assert!(!texto.contains(SECRETO), "el secreto se filtró: {texto}");
        assert!(texto.contains("HeadBucket"), "debe decir qué operación fue");
    }

    #[test]
    fn el_codigo_grpc_distingue_lo_reintentable_de_lo_que_no() {
        // El núcleo decide con este código si reintentar; un 403 y un 500 de R2
        // no se parecen en nada desde el otro lado.
        let servicio = |estado| ErrorDeR2::Servicio {
            operacion: "PutObject",
            estado,
            codigo: "X".into(),
        };
        assert_eq!(
            Status::from(servicio(403)).code(),
            sb_plugin_sdk::tonic::Code::PermissionDenied
        );
        assert_eq!(
            Status::from(servicio(404)).code(),
            sb_plugin_sdk::tonic::Code::NotFound
        );
        assert_eq!(
            Status::from(servicio(503)).code(),
            sb_plugin_sdk::tonic::Code::Unavailable
        );
        assert_eq!(
            Status::from(servicio(400)).code(),
            sb_plugin_sdk::tonic::Code::Internal
        );
        assert_eq!(
            Status::from(ErrorDeR2::Transporte {
                operacion: "PutObject"
            })
            .code(),
            sb_plugin_sdk::tonic::Code::Unavailable
        );
        assert_eq!(
            Status::from(ErrorDeR2::Tiempo {
                operacion: "PutObject"
            })
            .code(),
            sb_plugin_sdk::tonic::Code::DeadlineExceeded
        );
    }

    #[test]
    fn un_404_de_objeto_es_ausencia_y_uno_de_bucket_no() {
        // El borrado idempotente y el `not_found` de la descarga cuelgan de
        // esta distinción: un bucket que falta no puede pasar por «ese
        // artefacto ya no estaba».
        let servicio = |codigo: &str| ErrorDeR2::Servicio {
            operacion: "GetObject",
            estado: 404,
            codigo: codigo.into(),
        };
        assert!(servicio("NoSuchKey").es_ausencia());
        assert!(!servicio("NoSuchBucket").es_ausencia());
        assert!(
            !ErrorDeR2::Servicio {
                operacion: "GetObject",
                estado: 403,
                codigo: "AccessDenied".into(),
            }
            .es_ausencia(),
            "un 403 no dice que el objeto no exista, dice que no se puede mirar"
        );
        assert!(
            !ErrorDeR2::Transporte {
                operacion: "GetObject"
            }
            .es_ausencia()
        );
    }

    #[test]
    fn el_status_que_viaja_al_nucleo_conserva_el_mensaje_depurado() {
        let e = ErrorDeR2::Servicio {
            operacion: "UploadPart",
            estado: 403,
            codigo: "AccessDenied".into(),
        };
        let texto = e.to_string();
        let status = Status::from(e);
        assert_eq!(status.message(), texto);
        assert!(status.message().contains("UploadPart"));
    }
}
