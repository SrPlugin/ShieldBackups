//! Esquema de configuración del plugin y la configuración ya resuelta.
//!
//! Aquí vive todo lo que el núcleo puede ajustar y nada más: los servicios de
//! datos leen un [`Config`] ya validado y no vuelven a mirar el mapa crudo.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use sb_plugin_sdk::sb_proto::{Field, FieldType, Value, value::Kind};
use sb_plugin_sdk::tonic::Status;

pub const CAMPO_DIR: &str = "dir";
pub const CAMPO_SEED: &str = "seed";
pub const CAMPO_SIZE: &str = "size";

/// Semilla por defecto del generador del motor.
pub const SEED_POR_DEFECTO: u64 = 42;
/// Tamaño por defecto del volcado: un mebibyte.
pub const SIZE_POR_DEFECTO: usize = 1_048_576;

/// Los campos que el plugin acepta, tal y como los publica `Schema`.
///
/// Ninguno es secreto: un plugin de pruebas que pidiera secretos obligaría a
/// los tests del núcleo a montar un almacén de credenciales.
#[must_use]
pub fn campos() -> Vec<Field> {
    vec![
        Field {
            name: CAMPO_DIR.into(),
            r#type: FieldType::Path as i32,
            required: true,
            secret: false,
            description:
                "Directorio donde el destino guarda los artefactos y el motor escribe lo restaurado"
                    .into(),
            default_value: String::new(),
        },
        Field {
            name: CAMPO_SEED.into(),
            r#type: FieldType::Int as i32,
            required: false,
            secret: false,
            description: "Semilla del generador determinista del motor".into(),
            default_value: SEED_POR_DEFECTO.to_string(),
        },
        Field {
            name: CAMPO_SIZE.into(),
            r#type: FieldType::Int as i32,
            required: false,
            secret: false,
            description: "Bytes que emite el motor en cada volcado".into(),
            default_value: SIZE_POR_DEFECTO.to_string(),
        },
    ]
}

/// Configuración validada. Solo existe si `Configure` tuvo éxito.
#[derive(Clone, Debug)]
pub struct Config {
    pub dir: PathBuf,
    pub seed: u64,
    pub size: usize,
}

impl Config {
    /// Valida el mapa que llega en `ConfigureRequest`.
    ///
    /// # Errors
    /// [`Status::invalid_argument`] si falta `dir`, si algún campo tiene un
    /// tipo que no le corresponde o si un número no cabe donde debe.
    pub fn desde_mapa(mapa: &HashMap<String, Value>) -> Result<Self, Status> {
        let dir = match mapa.get(CAMPO_DIR).and_then(|v| v.kind.as_ref()) {
            Some(Kind::StringValue(s)) if !s.is_empty() => PathBuf::from(s),
            Some(Kind::StringValue(_)) | None => {
                return Err(Status::invalid_argument(format!(
                    "falta el campo obligatorio `{CAMPO_DIR}`"
                )));
            }
            Some(_) => {
                return Err(Status::invalid_argument(format!(
                    "el campo `{CAMPO_DIR}` debe ser una ruta (cadena)"
                )));
            }
        };

        let seed = entero(mapa, CAMPO_SEED)?.map_or(Ok(SEED_POR_DEFECTO), |v| {
            u64::try_from(v).map_err(|_| {
                Status::invalid_argument(format!("`{CAMPO_SEED}` no puede ser negativo, es {v}"))
            })
        })?;

        let size = entero(mapa, CAMPO_SIZE)?.map_or(Ok(SIZE_POR_DEFECTO), |v| {
            usize::try_from(v).map_err(|_| {
                Status::invalid_argument(format!(
                    "`{CAMPO_SIZE}` debe estar entre 0 y {}, es {v}",
                    usize::MAX
                ))
            })
        })?;

        Ok(Self { dir, seed, size })
    }
}

/// Lee un campo entero opcional. `None` significa «no venía», no «venía mal».
fn entero(mapa: &HashMap<String, Value>, nombre: &str) -> Result<Option<i64>, Status> {
    match mapa.get(nombre).and_then(|v| v.kind.as_ref()) {
        None => Ok(None),
        Some(Kind::IntValue(v)) => Ok(Some(*v)),
        Some(_) => Err(Status::invalid_argument(format!(
            "el campo `{nombre}` debe ser un entero"
        ))),
    }
}

/// La configuración compartida entre los tres servicios del plugin.
///
/// `Configure` la escribe y el motor y el destino la leen. Antes de que se
/// escriba **no hay valores por defecto silenciosos**: leerla falla, porque un
/// volcado que se escribiera en un directorio que nadie pidió es peor que un
/// error claro.
#[derive(Clone, Default)]
pub struct Estado(Arc<Mutex<Option<Config>>>);

impl Estado {
    pub fn guardar(&self, config: Config) {
        // Un mutex envenenado significa que otro hilo panicó teniéndolo; el
        // dato de dentro sigue siendo un `Option<Config>` válido, así que se
        // recupera en vez de propagar el pánico a todo el plugin.
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(config);
    }

    /// La configuración actual.
    ///
    /// # Errors
    /// [`Status::failed_precondition`] si todavía no se llamó a `Configure`.
    pub fn resuelta(&self) -> Result<Config, Status> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                Status::failed_precondition(
                    "el plugin mock aún no está configurado: llama a Configure antes de cualquier RPC de datos",
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_plugin_sdk::tonic::Code;

    fn cadena(s: &str) -> Value {
        Value {
            kind: Some(Kind::StringValue(s.into())),
        }
    }
    fn numero(n: i64) -> Value {
        Value {
            kind: Some(Kind::IntValue(n)),
        }
    }

    #[test]
    fn el_esquema_publica_los_tres_campos_y_ninguno_es_secreto() {
        let campos = campos();
        let nombres: Vec<&str> = campos.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(nombres, vec![CAMPO_DIR, CAMPO_SEED, CAMPO_SIZE]);
        assert!(campos.iter().all(|c| !c.secret));
        assert!(campos[0].required);
        assert!(!campos[1].required && !campos[2].required);
    }

    #[test]
    fn seed_y_size_tienen_valores_por_defecto() {
        let mapa = HashMap::from([(CAMPO_DIR.to_string(), cadena("/tmp/x"))]);
        let c = Config::desde_mapa(&mapa).unwrap();
        assert_eq!(c.seed, SEED_POR_DEFECTO);
        assert_eq!(c.size, SIZE_POR_DEFECTO);
    }

    #[test]
    fn sin_dir_la_configuracion_se_rechaza() {
        let e = Config::desde_mapa(&HashMap::new()).unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument);
    }

    #[test]
    fn un_tipo_equivocado_se_rechaza_en_vez_de_ignorarse() {
        let mapa = HashMap::from([
            (CAMPO_DIR.to_string(), cadena("/tmp/x")),
            (CAMPO_SEED.to_string(), cadena("cuarenta y dos")),
        ]);
        assert_eq!(
            Config::desde_mapa(&mapa).unwrap_err().code(),
            Code::InvalidArgument
        );
    }

    #[test]
    fn un_size_negativo_se_rechaza() {
        let mapa = HashMap::from([
            (CAMPO_DIR.to_string(), cadena("/tmp/x")),
            (CAMPO_SIZE.to_string(), numero(-1)),
        ]);
        assert_eq!(
            Config::desde_mapa(&mapa).unwrap_err().code(),
            Code::InvalidArgument
        );
    }

    #[test]
    fn sin_configure_el_estado_falla_con_failed_precondition() {
        let e = Estado::default().resuelta().unwrap_err();
        assert_eq!(e.code(), Code::FailedPrecondition);
    }

    #[test]
    fn tras_configure_el_estado_devuelve_lo_guardado() {
        let estado = Estado::default();
        let mapa = HashMap::from([
            (CAMPO_DIR.to_string(), cadena("/tmp/mock")),
            (CAMPO_SEED.to_string(), numero(7)),
            (CAMPO_SIZE.to_string(), numero(10)),
        ]);
        estado.guardar(Config::desde_mapa(&mapa).unwrap());
        let c = estado.resuelta().unwrap();
        assert_eq!(c.dir, PathBuf::from("/tmp/mock"));
        assert_eq!(c.seed, 7);
        assert_eq!(c.size, 10);
    }
}
