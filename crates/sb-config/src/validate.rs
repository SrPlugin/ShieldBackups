//! Validación de una tabla de configuración contra el esquema del plugin.
//!
//! Aquí se cierra el círculo de la arquitectura de plugins: el núcleo no sabe
//! qué campos necesita un motor de base de datos ni un destino en la nube, así
//! que toma el esquema que el plugin declaró por gRPC y comprueba contra él lo que
//! el usuario escribió en el TOML. Lo que sale son los [`Value`] del
//! protocolo, listos para viajar en `Configure`.
//!
//! Dos reglas simétricas gobiernan los secretos:
//!
//! 1. **Un campo secreto no admite un valor literal.** Si el plugin dice que
//!    un campo es sensible, en el fichero solo cabe una referencia a su origen
//!    (`env`, `file`, `keyring`, `command`). Permitir el literal convertiría el
//!    fichero de configuración —que se versiona y se copia— en un almacén de
//!    contraseñas.
//! 2. **Un campo público no admite una referencia a secreto.** Resolverla
//!    gastaría una lectura del llavero o una ejecución de comando para algo
//!    que no es sensible, y sobre todo despistaría a quien lea la
//!    configuración sobre qué datos hay que proteger de verdad.
//!
//! El secreto se resuelve *aquí*, no en el plugin: el plugin recibe el valor y
//! nunca sabe de dónde salió. Ningún mensaje de error de este módulo contiene
//! el valor de un secreto, ni siquiera el encadenado como `source`.

use std::collections::HashMap;

use sb_proto::{Field, FieldType, StringList, Value, value::Kind};

use crate::model::{ConfigTable, ConfigValue, SecretRef};
use crate::secrets::{SecretError, resolver};

/// Distancia de edición máxima para considerar que un campo desconocido es una
/// errata de otro.
///
/// Con 1 se escapan las transposiciones más un carácter de más; con 3 empieza
/// a sugerir cosas que no tienen nada que ver («ssl» por «url»), y una
/// sugerencia equivocada cuesta más tiempo que ninguna.
const DISTANCIA_MAXIMA: usize = 2;

/// Por qué se rechaza una configuración.
///
/// **Ninguna variante contiene el valor de un secreto.** Las que hablan de uno
/// nombran el campo o el origen —lo que hace falta para arreglarlo— y la
/// única que encadena otro error lo hace sobre [`SecretError`], que tiene la
/// misma garantía.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    /// El esquema declara el campo como obligatorio y no está en la tabla.
    #[error("falta el campo obligatorio «{campo}» en la sección «{seccion}»")]
    CampoRequeridoAusente {
        /// Sección del fichero: `engine` o `storage`.
        seccion: String,
        /// Campo que el plugin exige.
        campo: String,
    },

    /// La tabla trae un campo que el plugin no declara.
    ///
    /// Se rechaza en vez de ignorarse: un campo que el plugin no lee es casi
    /// siempre una errata, y aceptarlo en silencio deja al usuario creyendo
    /// que ha configurado algo que no está en efecto.
    #[error("el campo «{campo}» no existe en la sección «{seccion}»; {sugerencia}")]
    CampoDesconocido {
        /// Sección del fichero: `engine` o `storage`.
        seccion: String,
        /// Campo desconocido, tal como lo escribió el usuario.
        campo: String,
        /// Pista: el campo parecido, o la lista de los que sí existen.
        sugerencia: String,
    },

    /// El valor escrito no encaja con el tipo que declara el esquema.
    #[error("el campo «{campo}» de la sección «{seccion}» debe ser {esperado}")]
    TipoIncorrecto {
        /// Sección del fichero: `engine` o `storage`.
        seccion: String,
        /// Campo con el valor mal tipado.
        campo: String,
        /// Descripción del tipo que esperaba el plugin.
        esperado: String,
    },

    /// Un campo secreto trae un valor literal.
    ///
    /// El mensaje enumera las formas válidas y **no** incluye el valor
    /// rechazado: sería filtrar por el error justo lo que se intenta proteger.
    #[error(
        "el campo «{campo}» de la sección «{seccion}» es secreto y no admite un valor \
         literal en el fichero de configuración; escribe de dónde sacarlo: \
         {{ env = \"VARIABLE\" }}, {{ file = \"/ruta/al/secreto\" }}, \
         {{ keyring = \"servicio/usuario\" }} o {{ command = [\"programa\", \"argumento\"] }}"
    )]
    SecretoLiteral {
        /// Sección del fichero: `engine` o `storage`.
        seccion: String,
        /// Campo secreto que traía el literal.
        campo: String,
    },

    /// Un campo que no es secreto trae una referencia a secreto.
    #[error(
        "el campo «{campo}» de la sección «{seccion}» no es secreto: escribe su valor \
         directamente, sin una referencia a env, file, keyring o command"
    )]
    ReferenciaEnCampoPublico {
        /// Sección del fichero: `engine` o `storage`.
        seccion: String,
        /// Campo público que traía la referencia.
        campo: String,
    },

    /// La referencia era correcta, pero el secreto no se pudo obtener.
    ///
    /// El campo va en el mensaje porque una configuración puede tener varios
    /// secretos y «la variable no está definida» sin más obliga a adivinar
    /// cuál. La causa se encadena como `source`.
    #[error("no se pudo resolver el secreto del campo «{campo}»")]
    SecretoNoResuelto {
        /// Campo cuyo secreto no se pudo obtener.
        campo: String,
        /// Fallo de la resolución. Nunca contiene el valor.
        #[source]
        fuente: SecretError,
    },
}

/// Comprueba la configuración contra el esquema del plugin y la convierte a
/// los [`Value`] del protocolo, resolviendo los secretos por el camino.
///
/// `seccion` es `"engine"` o `"storage"`, y solo alimenta los mensajes de
/// error: en un backup hay dos plugins configurados, y «falta el campo host»
/// sin decir de cuál es obliga a adivinar.
///
/// Los campos opcionales ausentes no aparecen en el resultado: el plugin
/// aplica su propio valor por defecto, que es quien lo conoce.
///
/// # Errors
///
/// Devuelve [`ValidationError`] si sobra un campo, falta uno obligatorio, un
/// valor no encaja con su tipo, un secreto se escribió como literal, un campo
/// público trae una referencia a secreto, o un secreto no se pudo resolver.
pub fn validar_y_convertir(
    cfg: &ConfigTable,
    esquema: &[Field],
    seccion: &str,
) -> Result<HashMap<String, Value>, ValidationError> {
    // Primero lo que sobra: un campo desconocido suele ser una errata del
    // campo que el usuario cree haber puesto, así que avisar de que «falta
    // host» cuando escribió «hosst» sería contarle la mitad de la historia.
    for nombre in cfg.keys() {
        if !esquema.iter().any(|campo| &campo.name == nombre) {
            return Err(ValidationError::CampoDesconocido {
                seccion: seccion.to_owned(),
                campo: nombre.clone(),
                sugerencia: sugerir(nombre, esquema),
            });
        }
    }

    let mut salida = HashMap::with_capacity(cfg.len());

    for campo in esquema {
        let Some(valor) = cfg.get(&campo.name) else {
            if campo.required {
                return Err(ValidationError::CampoRequeridoAusente {
                    seccion: seccion.to_owned(),
                    campo: campo.name.clone(),
                });
            }
            continue;
        };

        salida.insert(campo.name.clone(), convertir(campo, valor, seccion)?);
    }

    Ok(salida)
}

/// Convierte un valor ya emparejado con su campo del esquema.
fn convertir(campo: &Field, valor: &ConfigValue, seccion: &str) -> Result<Value, ValidationError> {
    if campo.secret {
        return convertir_secreto(campo, valor, seccion);
    }

    if let ConfigValue::Secret(_) = valor {
        return Err(ValidationError::ReferenciaEnCampoPublico {
            seccion: seccion.to_owned(),
            campo: campo.name.clone(),
        });
    }

    let tipo = FieldType::try_from(campo.r#type).unwrap_or(FieldType::Unspecified);

    let kind = match (tipo, valor) {
        // `Path` y `Duration` viajan como texto: su semántica —qué es una ruta
        // válida, cómo se escribe «30s»— la interpreta el plugin, que es quien
        // la conoce. El núcleo solo transporta.
        (FieldType::String | FieldType::Path | FieldType::Duration, ConfigValue::String(s)) => {
            Kind::StringValue(s.clone())
        }
        (FieldType::Int, ConfigValue::Int(n)) => Kind::IntValue(*n),
        (FieldType::Bool, ConfigValue::Bool(b)) => Kind::BoolValue(*b),
        (FieldType::List, ConfigValue::List(l)) => {
            Kind::ListValue(StringList { values: l.clone() })
        }
        _ => {
            return Err(ValidationError::TipoIncorrecto {
                seccion: seccion.to_owned(),
                campo: campo.name.clone(),
                esperado: descripcion(tipo).to_owned(),
            });
        }
    };

    Ok(Value { kind: Some(kind) })
}

/// Resuelve el secreto de un campo sensible.
///
/// Lo que sale es el valor, no la referencia: el plugin recibe la contraseña y
/// nunca el nombre de la variable ni la ruta del archivo. Saber de dónde
/// salió no le sirve de nada y le daría un camino para ir a buscar más.
fn convertir_secreto(
    campo: &Field,
    valor: &ConfigValue,
    seccion: &str,
) -> Result<Value, ValidationError> {
    let ConfigValue::Secret(referencia) = valor else {
        // El valor rechazado no entra en el error, ni siquiera recortado: es
        // exactamente el dato que este módulo existe para proteger.
        return Err(ValidationError::SecretoLiteral {
            seccion: seccion.to_owned(),
            campo: campo.name.clone(),
        });
    };

    resolver_referencia(referencia, &campo.name)
}

/// Obtiene el valor de una referencia y lo mete en un [`Value`] del protocolo.
///
/// El error nombra el campo —una configuración puede tener varios secretos— y
/// encadena el [`SecretError`], que tampoco contiene el valor.
fn resolver_referencia(referencia: &SecretRef, campo: &str) -> Result<Value, ValidationError> {
    let secreto = resolver(referencia).map_err(|fuente| ValidationError::SecretoNoResuelto {
        campo: campo.to_owned(),
        fuente,
    })?;

    Ok(Value {
        kind: Some(Kind::StringValue(secreto.expose().clone())),
    })
}

/// Cómo se llama un tipo del esquema en un mensaje de error.
fn descripcion(tipo: FieldType) -> &'static str {
    match tipo {
        FieldType::String => "una cadena",
        FieldType::Int => "un entero",
        FieldType::Bool => "un booleano (true o false)",
        FieldType::Duration => "una duración escrita como cadena (por ejemplo «30s»)",
        FieldType::Path => "una ruta escrita como cadena",
        FieldType::List => "una lista de cadenas",
        FieldType::Unspecified => "de un tipo que el plugin no declara; es un fallo del plugin",
    }
}

/// Pista para un campo que el esquema no declara.
///
/// Con un parecido razonable se nombra: casi siempre es la errata. Sin él,
/// sugerir el «menos lejano» sería ruido —el usuario no escribió mal `host`,
/// escribió otra cosa— y lo útil es enseñarle qué campos existen.
fn sugerir(desconocido: &str, esquema: &[Field]) -> String {
    if esquema.is_empty() {
        return "este plugin no declara ningún campo de configuración".to_owned();
    }

    let parecido = esquema
        .iter()
        .map(|campo| (distancia(desconocido, &campo.name), &campo.name))
        .filter(|(d, _)| *d <= DISTANCIA_MAXIMA)
        .min_by_key(|(d, _)| *d);

    if let Some((_, nombre)) = parecido {
        return format!("¿quisiste decir «{nombre}»?");
    }

    let disponibles: Vec<&str> = esquema.iter().map(|campo| campo.name.as_str()).collect();
    format!("los campos disponibles son: {}", disponibles.join(", "))
}

/// Distancia de Levenshtein entre dos cadenas, en caracteres.
///
/// Se cuenta por `char` y no por byte para que una errata en un nombre con
/// acentos no se mida como si fueran dos cambios.
fn distancia(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();

    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }

    // Solo hacen falta dos filas de la matriz: la anterior y la que se está
    // calculando.
    let mut anterior: Vec<usize> = (0..=b.len()).collect();
    let mut actual: Vec<usize> = vec![0; b.len() + 1];

    for (i, ca) in a.iter().enumerate() {
        actual[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let sustitucion = anterior[j] + usize::from(ca != cb);
            let borrado = anterior[j + 1] + 1;
            let insercion = actual[j] + 1;
            actual[j + 1] = sustitucion.min(borrado).min(insercion);
        }
        std::mem::swap(&mut anterior, &mut actual);
    }

    anterior[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_proto::{Field, FieldType};

    fn campo(nombre: &str, tipo: FieldType, requerido: bool, secreto: bool) -> Field {
        Field {
            name: nombre.into(),
            r#type: tipo as i32,
            required: requerido,
            secret: secreto,
            description: String::new(),
            default_value: String::new(),
        }
    }

    fn esquema() -> Vec<Field> {
        vec![
            campo("host", FieldType::String, true, false),
            campo("port", FieldType::Int, false, false),
            campo("password", FieldType::String, true, true),
            campo("ssl", FieldType::Bool, false, false),
            campo("ruta", FieldType::Path, false, false),
            campo("excluir", FieldType::List, false, false),
        ]
    }

    fn tabla(pares: Vec<(&str, ConfigValue)>) -> ConfigTable {
        pares.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    /// Configuración mínima válida: los dos campos requeridos.
    fn minima() -> ConfigTable {
        tabla(vec![
            ("host", ConfigValue::String("db".into())),
            (
                "password",
                ConfigValue::Secret(SecretRef::Env("PATH".into())),
            ),
        ])
    }

    #[test]
    fn acepta_una_configuracion_correcta() {
        let r = validar_y_convertir(&minima(), &esquema(), "engine").unwrap();
        assert!(r.contains_key("host"));
        assert!(r.contains_key("password"));
    }

    #[test]
    fn el_secreto_llega_resuelto_no_como_referencia() {
        // El plugin recibe el valor, nunca la ruta ni el nombre de la variable.
        let r = validar_y_convertir(&minima(), &esquema(), "engine").unwrap();
        let v = r.get("password").unwrap();
        match &v.kind {
            Some(sb_proto::value::Kind::StringValue(s)) => {
                assert!(!s.is_empty());
                assert!(
                    !s.contains("PATH"),
                    "no debe viajar el nombre de la variable"
                );
            }
            otro => panic!("se esperaba una cadena, llegó {otro:?}"),
        }
    }

    #[test]
    fn falta_un_campo_requerido() {
        let cfg = tabla(vec![("host", ConfigValue::String("db".into()))]);
        let err = validar_y_convertir(&cfg, &esquema(), "engine")
            .err()
            .unwrap();
        assert!(
            matches!(err, ValidationError::CampoRequeridoAusente { ref campo, .. } if campo == "password")
        );
    }

    #[test]
    fn un_campo_desconocido_se_rechaza_y_sugiere_el_parecido() {
        let mut cfg = minima();
        cfg.insert("hosst".into(), ConfigValue::String("db".into()));
        let err = validar_y_convertir(&cfg, &esquema(), "engine")
            .err()
            .unwrap();
        let texto = err.to_string();
        assert!(texto.contains("hosst"));
        assert!(
            texto.contains("host"),
            "debe sugerir el campo que sí existe"
        );
    }

    #[test]
    fn un_campo_desconocido_muy_distinto_lista_los_disponibles() {
        // Sin un parecido razonable, sugerir cualquiera sería ruido; mejor
        // enseñar qué campos existen.
        let mut cfg = minima();
        cfg.insert("zzzzzzzz".into(), ConfigValue::String("x".into()));
        let texto = validar_y_convertir(&cfg, &esquema(), "engine")
            .err()
            .unwrap()
            .to_string();
        assert!(
            texto.contains("host") && texto.contains("port"),
            "debe listar los campos disponibles"
        );
    }

    #[test]
    fn un_tipo_incorrecto_se_rechaza() {
        let mut cfg = minima();
        cfg.insert("port".into(), ConfigValue::String("no-es-un-numero".into()));
        assert!(matches!(
            validar_y_convertir(&cfg, &esquema(), "engine")
                .err()
                .unwrap(),
            ValidationError::TipoIncorrecto { .. }
        ));
    }

    #[test]
    fn un_campo_secreto_no_admite_valor_literal() {
        // La regla más importante del módulo.
        let cfg = tabla(vec![
            ("host", ConfigValue::String("db".into())),
            ("password", ConfigValue::String("hunter2".into())),
        ]);
        let err = validar_y_convertir(&cfg, &esquema(), "engine")
            .err()
            .unwrap();
        assert!(matches!(err, ValidationError::SecretoLiteral { .. }));
        assert!(
            !err.to_string().contains("hunter2"),
            "el error no puede filtrar el secreto"
        );
    }

    #[test]
    fn el_error_de_secreto_literal_dice_las_alternativas() {
        let cfg = tabla(vec![
            ("host", ConfigValue::String("db".into())),
            ("password", ConfigValue::String("x".into())),
        ]);
        let texto = validar_y_convertir(&cfg, &esquema(), "engine")
            .err()
            .unwrap()
            .to_string();
        assert!(texto.contains("env"), "debe decir cómo hacerlo bien");
        assert!(texto.contains("file"));
    }

    #[test]
    fn un_campo_no_secreto_no_admite_referencia_a_secreto() {
        let mut cfg = minima();
        cfg.insert(
            "host".into(),
            ConfigValue::Secret(SecretRef::Env("PATH".into())),
        );
        assert!(matches!(
            validar_y_convertir(&cfg, &esquema(), "engine")
                .err()
                .unwrap(),
            ValidationError::ReferenciaEnCampoPublico { .. }
        ));
    }

    #[test]
    fn los_campos_opcionales_ausentes_no_estorban() {
        let r = validar_y_convertir(&minima(), &esquema(), "engine").unwrap();
        assert!(!r.contains_key("port"));
        assert!(!r.contains_key("ssl"));
    }

    #[test]
    fn los_tipos_path_y_duration_viajan_como_texto() {
        // Su semántica la interpreta el plugin, no el núcleo.
        let mut cfg = minima();
        cfg.insert("ruta".into(), ConfigValue::String("/var/lib/x".into()));
        let r = validar_y_convertir(&cfg, &esquema(), "engine").unwrap();
        assert!(matches!(
            r.get("ruta").unwrap().kind,
            Some(sb_proto::value::Kind::StringValue(_))
        ));
    }

    #[test]
    fn una_lista_viaja_como_lista() {
        let mut cfg = minima();
        cfg.insert(
            "excluir".into(),
            ConfigValue::List(vec!["a".into(), "b".into()]),
        );
        let r = validar_y_convertir(&cfg, &esquema(), "engine").unwrap();
        match &r.get("excluir").unwrap().kind {
            Some(sb_proto::value::Kind::ListValue(l)) => assert_eq!(l.values.len(), 2),
            otro => panic!("se esperaba una lista, llegó {otro:?}"),
        }
    }

    #[test]
    fn un_booleano_viaja_como_booleano() {
        let mut cfg = minima();
        cfg.insert("ssl".into(), ConfigValue::Bool(true));
        let r = validar_y_convertir(&cfg, &esquema(), "engine").unwrap();
        assert!(matches!(
            r.get("ssl").unwrap().kind,
            Some(sb_proto::value::Kind::BoolValue(true))
        ));
    }

    #[test]
    fn el_error_nombra_la_seccion() {
        // En un backup hay dos plugins configurados. «falta el campo host» sin
        // decir si es del motor o del destino obliga a adivinar.
        let cfg = ConfigTable::new();
        let texto = validar_y_convertir(&cfg, &esquema(), "storage")
            .err()
            .unwrap()
            .to_string();
        assert!(texto.contains("storage"));
    }

    #[test]
    fn un_secreto_que_no_se_puede_resolver_da_un_error_util() {
        let cfg = tabla(vec![
            ("host", ConfigValue::String("db".into())),
            (
                "password",
                ConfigValue::Secret(SecretRef::Env("SB_NO_EXISTE_ABC_999".into())),
            ),
        ]);
        let err = validar_y_convertir(&cfg, &esquema(), "engine")
            .err()
            .unwrap();
        let texto = err.to_string();
        assert!(texto.contains("password"), "debe decir qué campo falló");
    }

    #[test]
    fn un_esquema_vacio_rechaza_cualquier_campo() {
        let cfg = tabla(vec![("lo_que_sea", ConfigValue::String("x".into()))]);
        assert!(validar_y_convertir(&cfg, &[], "engine").is_err());
    }

    #[test]
    fn un_esquema_vacio_acepta_una_configuracion_vacia() {
        assert!(
            validar_y_convertir(&ConfigTable::new(), &[], "engine")
                .unwrap()
                .is_empty()
        );
    }
}
