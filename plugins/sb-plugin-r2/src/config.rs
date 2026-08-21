//! Esquema de configuración del destino R2 y la configuración ya validada.
//!
//! Todo lo que el usuario puede ajustar del plugin vive aquí, y aquí se
//! rechaza lo que no vaya a funcionar. La validación es deliberadamente
//! **madrugadora**: un `part_size_mb` que no da para el objeto más grande que
//! se espera subir es un fallo que, sin esta comprobación, aparecería tres
//! horas después de empezar la subida y con las partes ya facturadas.

use std::collections::HashMap;

use sb_plugin_sdk::sb_proto::{Field, FieldType, Value, value::Kind};
use sb_plugin_sdk::tonic::Status;

pub const CAMPO_ACCOUNT_ID: &str = "account_id";
pub const CAMPO_BUCKET: &str = "bucket";
pub const CAMPO_ACCESS_KEY_ID: &str = "access_key_id";
pub const CAMPO_SECRET_ACCESS_KEY: &str = "secret_access_key";
pub const CAMPO_ENDPOINT: &str = "endpoint";
pub const CAMPO_PREFIX: &str = "prefix";
pub const CAMPO_PART_SIZE_MB: &str = "part_size_mb";
pub const CAMPO_CONCURRENCY: &str = "concurrency";
pub const CAMPO_MAX_OBJECT_GB: &str = "max_object_gb";
pub const CAMPO_STORAGE_CLASS: &str = "storage_class";

const MIB: u64 = 1024 * 1024;
/// El gigabyte de `max_object_gb` es decimal, como el que usan Cloudflare y AWS
/// para facturar y para documentar sus topes. Mezclarlo con el mebibyte de
/// `part_size_mb` chirría, pero cada unidad es la que usa quien la publica.
const GB: u64 = 1_000_000_000;

/// Tamaño mínimo de parte que acepta el protocolo multipart de S3, en MiB.
/// La última parte puede ser menor; ninguna otra.
pub const PARTE_MINIMA_MB: u64 = 5;
/// Tamaño máximo de parte que acepta el protocolo multipart de S3, en MiB.
pub const PARTE_MAXIMA_MB: u64 = 5 * 1024;
/// Partes que admite una única subida multipart. Es un tope del protocolo, no
/// una elección nuestra: con él, `part_size_mb` fija el objeto más grande que
/// se puede subir.
pub const PARTES_MAXIMAS: u64 = 10_000;

const PART_SIZE_MB_POR_DEFECTO: i64 = 64;
const CONCURRENCY_POR_DEFECTO: i64 = 4;
const MAX_OBJECT_GB_POR_DEFECTO: i64 = 640;
const CONCURRENCY_MAXIMA: i64 = 256;
/// Tope de objeto que admite S3 —y R2—: 5 TiB, redondeado a GB decimales.
const MAX_OBJECT_GB_MAXIMO: i64 = 5_500;

/// Dominio bajo el que Cloudflare publica el endpoint S3 de cada cuenta.
const DOMINIO_R2: &str = "r2.cloudflarestorage.com";

/// Lo que puede ir mal al leer la configuración.
///
/// Ninguna variante lleva dentro el valor de un campo secreto: un error acaba
/// en un log, y un log con una clave dentro es una filtración.
#[derive(Debug, thiserror::Error)]
pub enum R2ConfigError {
    #[error("falta el campo obligatorio `{campo}`")]
    CampoObligatorio { campo: &'static str },
    #[error("el campo `{campo}` debe ser {esperado}")]
    TipoIncorrecto {
        campo: &'static str,
        esperado: &'static str,
    },
    #[error(
        "`{}` es de {mb} MiB y el mínimo del protocolo multipart de S3 es de {PARTE_MINIMA_MB} MiB: todas las partes salvo la última deben alcanzarlo",
        CAMPO_PART_SIZE_MB
    )]
    ParteDemasiadoPequena { mb: i64 },
    #[error(
        "con partes de {mb} MiB y un tope de {PARTES_MAXIMAS} partes solo se llega a {techo_gb} GB, por debajo de los {max_object_gb} GB de `{}`: sube `{}` hasta al menos {minimo_mb} MiB",
        CAMPO_MAX_OBJECT_GB,
        CAMPO_PART_SIZE_MB
    )]
    ParteInsuficienteParaTamano {
        mb: i64,
        max_object_gb: i64,
        techo_gb: u64,
        minimo_mb: u64,
    },
    #[error("el campo `{campo}` debe estar entre {minimo} y {maximo}, y vale {valor}")]
    FueraDeRango {
        campo: &'static str,
        valor: i64,
        minimo: i64,
        maximo: i64,
    },
    #[error(
        "`{}` solo admite `{}` o `{}`",
        CAMPO_STORAGE_CLASS,
        ClaseDeAlmacenamiento::ESTANDAR,
        ClaseDeAlmacenamiento::POCO_FRECUENTE
    )]
    ClaseDesconocida,
    #[error(
        "`{}` debe ser una URL absoluta con esquema `http://` o `https://`",
        CAMPO_ENDPOINT
    )]
    EndpointInvalido,
}

/// Un error de configuración es siempre culpa de lo que el núcleo mandó, así
/// que viaja como `invalid_argument` y no como un fallo interno.
impl From<R2ConfigError> for Status {
    fn from(e: R2ConfigError) -> Self {
        Self::invalid_argument(e.to_string())
    }
}

/// Las dos clases de almacenamiento que ofrece R2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaseDeAlmacenamiento {
    /// Acceso frecuente. Es la de por defecto.
    Estandar,
    /// Más barata de guardar y más cara de leer; para retenciones largas.
    PocoFrecuente,
}

impl ClaseDeAlmacenamiento {
    pub(crate) const ESTANDAR: &'static str = "Standard";
    pub(crate) const POCO_FRECUENTE: &'static str = "InfrequentAccess";

    /// El nombre tal y como lo espera la API de R2.
    #[must_use]
    pub fn como_str(self) -> &'static str {
        match self {
            Self::Estandar => Self::ESTANDAR,
            Self::PocoFrecuente => Self::POCO_FRECUENTE,
        }
    }

    fn analizar(valor: &str) -> Result<Self, R2ConfigError> {
        // Sin distinguir mayúsculas: el usuario escribe esto a mano en un TOML
        // y `standard` no debería costarle una ejecución fallida.
        if valor.eq_ignore_ascii_case(Self::ESTANDAR) {
            Ok(Self::Estandar)
        } else if valor.eq_ignore_ascii_case(Self::POCO_FRECUENTE) {
            Ok(Self::PocoFrecuente)
        } else {
            Err(R2ConfigError::ClaseDesconocida)
        }
    }
}

/// Los campos que el plugin acepta, tal y como los publica `Schema`.
///
/// Las dos claves van marcadas como secretas: el núcleo se niega a aceptar un
/// campo secreto como literal en el TOML del usuario y exige que venga de un
/// almacén de credenciales, así que marcarlas es lo que impide que acaben en
/// un fichero de configuración versionado.
#[must_use]
pub fn esquema() -> Vec<Field> {
    vec![
        texto(
            CAMPO_ACCOUNT_ID,
            true,
            false,
            "ID de la cuenta de Cloudflare; de él se deriva el endpoint de R2",
            String::new(),
        ),
        texto(
            CAMPO_BUCKET,
            true,
            false,
            "Bucket de R2 donde se guardan los artefactos",
            String::new(),
        ),
        texto(
            CAMPO_ACCESS_KEY_ID,
            true,
            true,
            "Clave de acceso del token de R2",
            String::new(),
        ),
        texto(
            CAMPO_SECRET_ACCESS_KEY,
            true,
            true,
            "Clave secreta del token de R2",
            String::new(),
        ),
        texto(
            CAMPO_ENDPOINT,
            false,
            false,
            "Endpoint explícito; sobrescribe el derivado del `account_id`. Para apuntar a un MinIO local en pruebas",
            String::new(),
        ),
        texto(
            CAMPO_PREFIX,
            false,
            false,
            "Prefijo común de todas las claves dentro del bucket, sin barra final",
            String::new(),
        ),
        entero_campo(
            CAMPO_PART_SIZE_MB,
            "Tamaño en MiB de cada parte de la subida multipart; el mínimo de S3 es 5",
            PART_SIZE_MB_POR_DEFECTO,
        ),
        entero_campo(
            CAMPO_CONCURRENCY,
            "Partes que se suben a la vez",
            CONCURRENCY_POR_DEFECTO,
        ),
        entero_campo(
            CAMPO_MAX_OBJECT_GB,
            "Tamaño máximo esperado de un artefacto en GB decimales; valida que `part_size_mb` dé para él",
            MAX_OBJECT_GB_POR_DEFECTO,
        ),
        texto(
            CAMPO_STORAGE_CLASS,
            false,
            false,
            "Clase de almacenamiento: `Standard` o `InfrequentAccess`",
            ClaseDeAlmacenamiento::ESTANDAR.to_string(),
        ),
    ]
}

fn texto(
    name: &str,
    required: bool,
    secret: bool,
    description: &str,
    default_value: String,
) -> Field {
    Field {
        name: name.into(),
        r#type: FieldType::String as i32,
        required,
        secret,
        description: description.into(),
        default_value,
    }
}

fn entero_campo(name: &str, description: &str, default_value: i64) -> Field {
    Field {
        name: name.into(),
        r#type: FieldType::Int as i32,
        required: false,
        secret: false,
        description: description.into(),
        default_value: default_value.to_string(),
    }
}

/// La configuración del destino, ya validada. Solo existe si `Configure` fue
/// aceptado.
///
/// Las credenciales se guardan privadas y solo salen por
/// [`R2Config::access_key_id`] y [`R2Config::secret_access_key`], que usa la
/// construcción del cliente. `Debug` está escrito a mano para que no salgan
/// por ahí.
#[derive(Clone)]
pub struct R2Config {
    pub account_id: String,
    pub bucket: String,
    access_key_id: String,
    secret_access_key: String,
    /// Endpoint explícito. `None` significa «derívalo del `account_id`».
    endpoint: Option<String>,
    /// Prefijo ya normalizado: sin barras sobrantes en los extremos.
    prefix: String,
    /// Tamaño de cada parte del multipart, en bytes.
    pub part_size: usize,
    /// Partes que se suben a la vez.
    pub concurrency: usize,
    /// Clase de almacenamiento con la que se crea cada objeto.
    pub storage_class: ClaseDeAlmacenamiento,
}

impl R2Config {
    /// Valida el mapa de `ConfigureRequest` y devuelve la configuración.
    ///
    /// # Errors
    ///
    /// [`R2ConfigError`] si falta un campo obligatorio, si alguno tiene un tipo
    /// que no le corresponde o si el tamaño de parte no es utilizable.
    pub fn from_values(valores: &HashMap<String, Value>) -> Result<Self, R2ConfigError> {
        let account_id = cadena_obligatoria(valores, CAMPO_ACCOUNT_ID)?;
        let bucket = cadena_obligatoria(valores, CAMPO_BUCKET)?;
        let access_key_id = cadena_obligatoria(valores, CAMPO_ACCESS_KEY_ID)?;
        let secret_access_key = cadena_obligatoria(valores, CAMPO_SECRET_ACCESS_KEY)?;

        let endpoint = match cadena_opcional(valores, CAMPO_ENDPOINT)? {
            Some(e) => Some(endpoint_validado(e)?),
            None => None,
        };

        // Un prefijo es un prefijo de clave, no una ruta: las barras de los
        // extremos son ruido y se quitan una sola vez, aquí, para que `clave`
        // no tenga que decidir nada.
        let prefix = cadena_opcional(valores, CAMPO_PREFIX)?
            .unwrap_or_default()
            .trim_matches('/')
            .to_string();

        let part_size_mb = entero(valores, CAMPO_PART_SIZE_MB)?.unwrap_or(PART_SIZE_MB_POR_DEFECTO);
        let max_object_gb =
            entero(valores, CAMPO_MAX_OBJECT_GB)?.unwrap_or(MAX_OBJECT_GB_POR_DEFECTO);
        let concurrency = entero(valores, CAMPO_CONCURRENCY)?.unwrap_or(CONCURRENCY_POR_DEFECTO);

        let part_size = tamano_de_parte(part_size_mb, max_object_gb)?;
        let concurrency = en_rango(CAMPO_CONCURRENCY, concurrency, 1, CONCURRENCY_MAXIMA)?;

        let storage_class = match cadena_opcional(valores, CAMPO_STORAGE_CLASS)? {
            Some(c) => ClaseDeAlmacenamiento::analizar(c)?,
            None => ClaseDeAlmacenamiento::Estandar,
        };

        Ok(Self {
            account_id: account_id.to_string(),
            bucket: bucket.to_string(),
            access_key_id: access_key_id.to_string(),
            secret_access_key: secret_access_key.to_string(),
            endpoint,
            prefix,
            part_size,
            concurrency: usize::try_from(concurrency).unwrap_or(1),
            storage_class,
        })
    }

    /// El endpoint contra el que se firma y se habla.
    ///
    /// R2 no publica un endpoint por bucket sino uno por cuenta, así que el
    /// caso normal es derivarlo; el explícito existe para apuntar a un `MinIO`
    /// en pruebas.
    #[must_use]
    pub fn endpoint(&self) -> String {
        match &self.endpoint {
            Some(e) => e.clone(),
            None => format!("https://{}.{DOMINIO_R2}", self.account_id),
        }
    }

    /// La clave completa dentro del bucket para un artefacto del núcleo.
    ///
    /// Une con una barra en vez de concatenar. Concatenar convertiría la clave
    /// `..foo` —legítima, porque `..` solo es peligroso como segmento
    /// completo— en un hermano del directorio de backups en vez de en algo
    /// dentro de él.
    #[must_use]
    pub fn clave(&self, clave: &str) -> String {
        let clave = clave.trim_start_matches('/');
        if self.prefix.is_empty() {
            clave.to_string()
        } else {
            format!("{}/{clave}", self.prefix)
        }
    }

    /// El prefijo ya normalizado, sin barras en los extremos.
    ///
    /// Lo necesita `List` para hacer el camino de vuelta con
    /// [`crate::claves::sin_prefijo`]: lo que R2 devuelve lleva el prefijo
    /// puesto y el núcleo nunca lo escribió.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    #[must_use]
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    #[must_use]
    pub fn secret_access_key(&self) -> &str {
        &self.secret_access_key
    }
}

/// `Debug` a mano: las dos claves salen redactadas.
///
/// Derivarlo haría que cualquier `tracing::debug!(?config)` —o el `Debug` de
/// una estructura que la contenga— volcase las credenciales al log.
impl std::fmt::Debug for R2Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("R2Config")
            .field("account_id", &self.account_id)
            .field("bucket", &self.bucket)
            .field("access_key_id", &"<redactado>")
            .field("secret_access_key", &"<redactado>")
            .field("endpoint", &self.endpoint())
            .field("prefix", &self.prefix)
            .field("part_size", &self.part_size)
            .field("concurrency", &self.concurrency)
            .field("storage_class", &self.storage_class)
            .finish()
    }
}

/// Valida `part_size_mb` contra el protocolo y contra el objeto más grande que
/// se espera subir, y lo devuelve en bytes.
fn tamano_de_parte(part_size_mb: i64, max_object_gb: i64) -> Result<usize, R2ConfigError> {
    if part_size_mb < i64::try_from(PARTE_MINIMA_MB).unwrap_or(i64::MAX) {
        return Err(R2ConfigError::ParteDemasiadoPequena { mb: part_size_mb });
    }
    let part_size_mb = en_rango(
        CAMPO_PART_SIZE_MB,
        part_size_mb,
        i64::try_from(PARTE_MINIMA_MB).unwrap_or(i64::MAX),
        i64::try_from(PARTE_MAXIMA_MB).unwrap_or(i64::MAX),
    )?;
    let max_object_gb = en_rango(CAMPO_MAX_OBJECT_GB, max_object_gb, 1, MAX_OBJECT_GB_MAXIMO)?;

    // Ambos caben en u64 tras pasar por `en_rango`, que ya descartó los
    // negativos.
    let bytes_por_parte = u64::try_from(part_size_mb).unwrap_or(PARTE_MINIMA_MB) * MIB;
    let objeto_maximo = u64::try_from(max_object_gb).unwrap_or(1) * GB;
    let techo = bytes_por_parte * PARTES_MAXIMAS;
    if techo < objeto_maximo {
        return Err(R2ConfigError::ParteInsuficienteParaTamano {
            mb: part_size_mb,
            max_object_gb,
            techo_gb: techo / GB,
            // Redondeo hacia arriba: la parte tiene que llegar, no acercarse.
            minimo_mb: objeto_maximo.div_ceil(PARTES_MAXIMAS).div_ceil(MIB),
        });
    }
    usize::try_from(bytes_por_parte).map_err(|_| R2ConfigError::FueraDeRango {
        campo: CAMPO_PART_SIZE_MB,
        valor: part_size_mb,
        minimo: i64::try_from(PARTE_MINIMA_MB).unwrap_or(i64::MAX),
        maximo: i64::try_from(PARTE_MAXIMA_MB).unwrap_or(i64::MAX),
    })
}

fn en_rango(
    campo: &'static str,
    valor: i64,
    minimo: i64,
    maximo: i64,
) -> Result<i64, R2ConfigError> {
    if valor < minimo || valor > maximo {
        return Err(R2ConfigError::FueraDeRango {
            campo,
            valor,
            minimo,
            maximo,
        });
    }
    Ok(valor)
}

/// Un endpoint que no es una URL absoluta se rechaza aquí y no al primer `Put`:
/// el SDK de AWS lo acepta sin rechistar y falla mucho más tarde.
fn endpoint_validado(valor: &str) -> Result<String, R2ConfigError> {
    let resto = valor
        .strip_prefix("https://")
        .or_else(|| valor.strip_prefix("http://"))
        .ok_or(R2ConfigError::EndpointInvalido)?;
    if resto.is_empty() {
        return Err(R2ConfigError::EndpointInvalido);
    }
    Ok(valor.trim_end_matches('/').to_string())
}

fn cadena_obligatoria<'a>(
    valores: &'a HashMap<String, Value>,
    campo: &'static str,
) -> Result<&'a str, R2ConfigError> {
    match cadena_opcional(valores, campo)? {
        Some(s) => Ok(s),
        None => Err(R2ConfigError::CampoObligatorio { campo }),
    }
}

/// Lee una cadena opcional. Una cadena vacía cuenta como ausente: un campo
/// puesto a `""` en el TOML es un campo que el usuario no llegó a rellenar.
fn cadena_opcional<'a>(
    valores: &'a HashMap<String, Value>,
    campo: &'static str,
) -> Result<Option<&'a str>, R2ConfigError> {
    match valores.get(campo).and_then(|v| v.kind.as_ref()) {
        None => Ok(None),
        Some(Kind::StringValue(s)) if s.is_empty() => Ok(None),
        Some(Kind::StringValue(s)) => Ok(Some(s)),
        Some(_) => Err(R2ConfigError::TipoIncorrecto {
            campo,
            esperado: "una cadena",
        }),
    }
}

/// Lee un entero opcional. `None` significa «no venía», no «venía mal».
fn entero(
    valores: &HashMap<String, Value>,
    campo: &'static str,
) -> Result<Option<i64>, R2ConfigError> {
    match valores.get(campo).and_then(|v| v.kind.as_ref()) {
        None => Ok(None),
        Some(Kind::IntValue(v)) => Ok(Some(*v)),
        Some(_) => Err(R2ConfigError::TipoIncorrecto {
            campo,
            esperado: "un entero",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_plugin_sdk::sb_proto::{Value, value::Kind};

    fn v_str(s: &str) -> Value {
        Value {
            kind: Some(Kind::StringValue(s.into())),
        }
    }
    fn v_int(i: i64) -> Value {
        Value {
            kind: Some(Kind::IntValue(i)),
        }
    }

    fn base() -> std::collections::HashMap<String, Value> {
        let mut m = std::collections::HashMap::new();
        m.insert("account_id".into(), v_str("abc123"));
        m.insert("bucket".into(), v_str("backups"));
        m.insert("access_key_id".into(), v_str("AKIA"));
        m.insert("secret_access_key".into(), v_str("SECRETO"));
        m
    }

    #[test]
    fn las_dos_claves_estan_marcadas_como_secretas() {
        // Si no lo estuvieran, la configuración las admitiría como literales
        // en el fichero TOML del usuario.
        let campos = esquema();
        for nombre in ["access_key_id", "secret_access_key"] {
            let f = campos.iter().find(|f| f.name == nombre).unwrap();
            assert!(f.secret, "«{nombre}» debe estar marcado como secreto");
        }
    }

    #[test]
    fn los_campos_no_sensibles_no_estan_marcados_como_secretos() {
        let campos = esquema();
        for nombre in ["account_id", "bucket", "prefix"] {
            let f = campos.iter().find(|f| f.name == nombre).unwrap();
            assert!(!f.secret, "«{nombre}» no es un secreto");
        }
    }

    #[test]
    fn todos_los_campos_tienen_descripcion() {
        // `shieldbk plugin docs r2` las imprime: un campo sin descripción es
        // un campo que el usuario tiene que adivinar.
        for f in esquema() {
            assert!(!f.description.is_empty(), "«{}» sin descripción", f.name);
        }
    }

    #[test]
    fn el_endpoint_se_deriva_del_account_id() {
        let c = R2Config::from_values(&base()).unwrap();
        assert_eq!(c.endpoint(), "https://abc123.r2.cloudflarestorage.com");
    }

    #[test]
    fn un_endpoint_explicito_gana() {
        // Necesario para probar contra MinIO.
        let mut m = base();
        m.insert("endpoint".into(), v_str("http://localhost:9000"));
        assert_eq!(
            R2Config::from_values(&m).unwrap().endpoint(),
            "http://localhost:9000"
        );
    }

    #[test]
    fn el_tamano_de_parte_por_defecto_es_de_64_mib() {
        assert_eq!(
            R2Config::from_values(&base()).unwrap().part_size,
            64 * 1024 * 1024
        );
    }

    #[test]
    fn se_rechaza_un_tamano_de_parte_por_debajo_del_minimo_de_s3() {
        let mut m = base();
        m.insert("part_size_mb".into(), v_int(1));
        let err = R2Config::from_values(&m).err().unwrap();
        assert!(matches!(err, R2ConfigError::ParteDemasiadoPequena { .. }));
        assert!(
            err.to_string().contains('5'),
            "debe decir cuál es el mínimo"
        );
    }

    #[test]
    fn se_rechaza_un_tamano_de_parte_que_no_alcanza_para_el_maximo_esperado() {
        // 10 000 partes es el máximo; con partes de 5 MiB el techo son ~48 GiB.
        // Avisar aquí es mejor que fallar a las tres horas de subida.
        let mut m = base();
        m.insert("part_size_mb".into(), v_int(5));
        m.insert("max_object_gb".into(), v_int(500));
        let err = R2Config::from_values(&m).err().unwrap();
        assert!(matches!(
            err,
            R2ConfigError::ParteInsuficienteParaTamano { .. }
        ));
        assert!(
            err.to_string().contains("part_size_mb"),
            "debe decir qué subir"
        );
    }

    #[test]
    fn el_tamano_por_defecto_alcanza_para_el_maximo_por_defecto() {
        // Que la configuración por defecto sea coherente consigo misma.
        assert!(R2Config::from_values(&base()).is_ok());
    }

    #[test]
    fn la_configuracion_no_expone_las_claves_al_imprimirse() {
        let c = R2Config::from_values(&base()).unwrap();
        let texto = format!("{c:?}");
        assert!(!texto.contains("SECRETO"));
        assert!(!texto.contains("AKIA"));
    }

    #[test]
    fn falta_el_bucket() {
        let mut m = base();
        m.remove("bucket");
        let err = R2Config::from_values(&m).err().unwrap();
        assert!(
            err.to_string().contains("bucket"),
            "debe nombrar el campo que falta"
        );
    }

    #[test]
    fn falta_la_clave_secreta() {
        let mut m = base();
        m.remove("secret_access_key");
        assert!(R2Config::from_values(&m).is_err());
    }

    #[test]
    fn el_prefijo_se_une_a_la_clave_con_una_sola_barra() {
        // Concatenar sin separador convertiría la clave «..foo» —legítima,
        // porque «..» solo es peligroso como segmento completo— en
        // «/backups..foo»: hermano del directorio de backups, no dentro.
        let mut m = base();
        m.insert("prefix".into(), v_str("equipo/backups"));
        let c = R2Config::from_values(&m).unwrap();
        assert_eq!(c.clave("x.age"), "equipo/backups/x.age");
        assert_eq!(c.clave("..foo.age"), "equipo/backups/..foo.age");
    }

    #[test]
    fn una_barra_sobrante_en_el_prefijo_no_duplica_el_separador() {
        let mut m = base();
        m.insert("prefix".into(), v_str("equipo/"));
        assert_eq!(
            R2Config::from_values(&m).unwrap().clave("x.age"),
            "equipo/x.age"
        );
    }

    #[test]
    fn sin_prefijo_la_clave_no_cambia() {
        assert_eq!(
            R2Config::from_values(&base()).unwrap().clave("x.age"),
            "x.age"
        );
    }
}
