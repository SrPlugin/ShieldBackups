//! Cómo se cuenta el resultado: para una persona o para un programa.
//!
//! Los dos formatos no son dos estilos del mismo texto, son dos contratos
//! distintos. El humano puede cambiar entre versiones sin avisar; el JSON no,
//! porque hay un `jq` apuntándole. Y hay una regla que los une y que este
//! módulo es el encargado de sostener: **en `--format json`, la salida estándar
//! contiene un único documento JSON y nada más**, incluso cuando el comando
//! falla. Un script que no puede parsear la salida de un fallo se queda sin
//! saber qué pasó justo cuando más falta le hace.
//!
//! De ahí que [`Informe`] pueda llevar un fallo dentro en vez de tener que
//! elegir entre informe **o** error. Es la diferencia entre un `doctor` que
//! dice «hay problemas» y uno que dice cuáles: si el fallo sustituyera al
//! informe, el comando cuyo trabajo es enumerar problemas perdería su salida
//! exactamente el día que encuentra alguno.

use std::io::Write as _;

use crate::error::CliError;

/// Lo que un comando tiene que contar, en los dos idiomas a la vez.
///
/// Los dos se construyen juntos y no uno a partir del otro: derivar el texto
/// del JSON daría frases telegráficas, y derivar el JSON del texto sería
/// adivinar. Cada comando sabe qué destacar en cada caso.
pub struct Informe {
    /// Lo que lee una persona. Sin salto final: lo pone la emisión.
    pub humano: String,
    /// Lo que lee un programa. Se le añade el veredicto al emitirlo.
    pub json: serde_json::Value,
    /// El fallo, si el comando hizo su trabajo y lo que encontró fue malo.
    pub fallo: Option<CliError>,
}

impl Informe {
    pub fn new(humano: impl Into<String>, json: serde_json::Value) -> Self {
        Self {
            humano: humano.into(),
            json,
            fallo: None,
        }
    }

    /// El mismo informe, pero con veredicto negativo.
    #[must_use]
    pub fn con_fallo(mut self, fallo: CliError) -> Self {
        self.fallo = Some(fallo);
        self
    }

    /// El código con el que termina el proceso: cero si no hubo fallo.
    #[must_use]
    pub fn codigo(&self) -> i32 {
        self.fallo.as_ref().map_or(0, CliError::codigo)
    }
}

/// Los dos formatos de salida.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "lower")]
pub enum Formato {
    /// Texto para leer.
    Human,
    /// Un documento JSON por ejecución.
    Json,
}

/// El emisor del resultado.
pub struct Salida {
    formato: Formato,
}

impl Salida {
    #[must_use]
    pub fn new(formato: Formato) -> Self {
        Self { formato }
    }

    /// Emite un informe, con o sin fallo dentro.
    ///
    /// En modo humano el texto va a stdout y el fallo a stderr, que es donde
    /// una persona lo busca y donde no contamina lo que hubiera podido salir
    /// por la tubería. En modo JSON todo va al único documento de stdout,
    /// porque ahí el contrato es que stdout **siempre** lo trae: un script que
    /// tuviera que leer stderr para enterarse de un fallo estaría leyendo texto
    /// sin formato, que es justo lo que pidió evitar.
    pub fn emitir(&self, informe: &Informe) {
        match self.formato {
            Formato::Human => {
                if !informe.humano.is_empty() {
                    println!("{}", informe.humano);
                }
                if let Some(fallo) = &informe.fallo {
                    let mut err = std::io::stderr().lock();
                    let _ = writeln!(err, "error: {fallo}");
                }
            }
            Formato::Json => {
                escribir_json(&envolver(informe.json.clone(), informe.fallo.as_ref()));
            }
        }
    }

    /// Emite un fallo que ocurrió **antes** de que hubiera nada que informar.
    ///
    /// Es el caso de la configuración que no se puede leer: no hay comando que
    /// haya llegado a producir un informe, pero el contrato de stdout en modo
    /// JSON sigue en pie.
    pub fn fallo(&self, error: &CliError) {
        self.emitir(&Informe::new("", serde_json::json!({})).con_fallo(error.duplicar()));
    }
}

/// Añade el veredicto —y el fallo, si lo hay— al documento del comando.
///
/// `ok` va en la raíz y siempre, aunque el comando ya cuente lo suyo: es lo
/// primero que mira un script y no debería tener que aprenderse un campo
/// distinto por comando.
fn envolver(cuerpo: serde_json::Value, fallo: Option<&CliError>) -> serde_json::Value {
    let mut documento = match cuerpo {
        serde_json::Value::Object(mapa) => mapa,
        otro => {
            let mut mapa = serde_json::Map::new();
            mapa.insert("resultado".into(), otro);
            mapa
        }
    };
    documento.insert("ok".into(), serde_json::Value::Bool(fallo.is_none()));
    if let Some(fallo) = fallo {
        documento.insert("clase".into(), fallo.clase().into());
        documento.insert("codigo".into(), fallo.codigo().into());
        documento.insert("error".into(), fallo.to_string().into());
    }
    serde_json::Value::Object(documento)
}

/// Escribe el documento y **nada más** en la salida estándar.
///
/// Serializar no puede fallar con los valores que se construyen aquí, pero si
/// fallara lo que no puede ocurrir es quedarse callado: un stdout vacío en modo
/// JSON rompe al script sin decirle por qué.
fn escribir_json(documento: &serde_json::Value) {
    let texto = serde_json::to_string(documento).unwrap_or_else(|fuente| {
        format!(
            r#"{{"ok":false,"clase":"operacion","error":"no se pudo serializar la salida: {fuente}"}}"#
        )
    });
    let mut salida = std::io::stdout().lock();
    let _ = writeln!(salida, "{texto}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_veredicto_se_anade_a_la_raiz_del_documento() {
        let documento = envolver(serde_json::json!({ "targets": [] }), None);
        assert_eq!(documento["ok"], serde_json::Value::Bool(true));
        assert!(documento["targets"].is_array(), "y no pisa lo que había");
        assert!(documento.get("error").is_none());
    }

    #[test]
    fn un_informe_con_fallo_conserva_su_contenido_ademas_del_error() {
        // Es el caso de `doctor`: el día que encuentra problemas es justo el
        // día en que su informe hace falta.
        let fallo = CliError::operacion("2 de 3 targets tienen problemas");
        let documento = envolver(serde_json::json!({ "targets": [1, 2, 3] }), Some(&fallo));
        assert_eq!(documento["ok"], serde_json::Value::Bool(false));
        assert_eq!(documento["clase"], "operacion");
        assert_eq!(documento["codigo"], 4);
        assert_eq!(documento["targets"].as_array().map(Vec::len), Some(3));
    }

    #[test]
    fn un_cuerpo_que_no_es_objeto_se_envuelve_igual() {
        // Un script tiene que poder mirar `.ok` sin saber qué comando corrió.
        let documento = envolver(serde_json::json!("texto suelto"), None);
        assert_eq!(documento["ok"], serde_json::Value::Bool(true));
        assert_eq!(documento["resultado"], "texto suelto");
    }

    #[test]
    fn el_codigo_de_un_informe_sin_fallo_es_cero() {
        let informe = Informe::new("todo bien", serde_json::json!({}));
        assert_eq!(informe.codigo(), 0);
        assert_eq!(
            informe.con_fallo(CliError::plugin("x")).codigo(),
            crate::error::CODIGO_PLUGIN
        );
    }
}
