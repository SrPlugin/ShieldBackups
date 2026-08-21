//! La operación de `doctor`: enterarse de lo que está mal **antes** del backup.
//!
//! Las otras tres operaciones abortan al primer problema, y hacen bien: a
//! mitad de un volcado no hay nada que seguir haciendo. Esta es lo contrario, y
//! por eso vive aparte. `doctor` existe para que un backup de dos horas no se
//! rompa a la hora y media por una credencial caducada, y para eso tiene que
//! contarlo **todo** de una vez: un plugin que no contesta es una línea del
//! informe, no el final del diagnóstico. Si abortara, el usuario arreglaría un
//! problema para descubrir el siguiente, y así una vez por intento.
//!
//! De ahí la firma: [`ejecutar_doctor`] no devuelve `Result`. No es que sus
//! fallos se ignoren —cada uno acaba en el informe, con su origen y su
//! remedio—, es que no hay ninguno que impida emitirlo.

use crate::plugin::{Capacidad, PluginClient};

/// Nombre de la comprobación que lleva la versión de la fuente.
///
/// El motor la reporta en su `Preflight` y el manifiesto de un backup la
/// necesita, así que viaja como una comprobación más en vez de como un campo
/// aparte: es información de diagnóstico —«contra qué versión de `PostgreSQL`
/// estoy hablando»— y el usuario quiere verla en el informe, no solo el
/// programa.
const CHECK_VERSION_FUENTE: &str = "versión de la fuente";

/// Una comprobación ya hecha, con su veredicto y con **de quién es**.
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// "engine" o "storage": de qué plugin viene la comprobación.
    ///
    /// Un backup tiene dos plugins vivos a la vez; «falta permiso» sin decir
    /// cuál de los dos obliga a adivinar.
    pub origen: String,
    pub nombre: String,
    pub ok: bool,
    /// Qué se vio: la ruta que no existe, el error que devolvió el servidor.
    pub detalle: String,
    /// Qué hacer para arreglarlo. Vacío si no hay nada que arreglar.
    pub remedio: String,
}

/// Todo lo que se pudo averiguar sobre un target, junto.
#[derive(Debug, Clone)]
pub struct DoctorReport {
    pub target: String,
    pub checks: Vec<CheckResult>,
}

impl DoctorReport {
    /// Un informe **sin comprobaciones no está bien**: significa que algo no
    /// llegó a ejecutarse.
    ///
    /// La alternativa —`all()` sobre una lista vacía, que es cierto— diría
    /// «todo en orden» sin haber mirado nada, y ese es el único veredicto peor
    /// que un fallo: el usuario se iría tranquilo a lanzar el backup.
    #[must_use]
    pub fn ok(&self) -> bool {
        !self.checks.is_empty() && self.checks.iter().all(|c| c.ok)
    }

    /// Las comprobaciones que fallaron, **todas**.
    #[must_use]
    pub fn fallos(&self) -> Vec<&CheckResult> {
        self.checks.iter().filter(|c| !c.ok).collect()
    }

    /// Versión de la fuente detectada por el motor, si la reportó.
    #[must_use]
    pub fn server_version(&self) -> Option<&str> {
        self.checks
            .iter()
            .find(|c| {
                c.origen == Capacidad::Engine.como_cadena() && c.nombre == CHECK_VERSION_FUENTE
            })
            .map(|c| c.detalle.as_str())
    }
}

/// Ejecuta el preflight de ambos plugins y junta los resultados.
///
/// **Nunca aborta por un plugin que falle**: un plugin que no responde es un
/// hallazgo del informe, no un error de la operación. El usuario quiere ver
/// todo lo que está mal de una vez.
///
/// Los dos se preguntan en serie y no en paralelo a propósito: son dos RPC
/// cortos, ganar unos milisegundos no compensa que los mensajes de un plugin
/// se entremezclen con los del otro en el log, y el informe sale con el motor
/// primero, que es como se lee.
pub async fn ejecutar_doctor(
    target: &str,
    engine: &PluginClient,
    storage: &PluginClient,
) -> DoctorReport {
    let mut checks = Vec::new();
    interrogar(&mut checks, Capacidad::Engine, engine).await;
    interrogar(&mut checks, Capacidad::Storage, storage).await;

    DoctorReport {
        target: target.to_string(),
        checks,
    }
}

/// Le pide el preflight a un plugin y vuelca lo que diga —o lo que falle— en
/// el informe.
async fn interrogar(checks: &mut Vec<CheckResult>, papel: Capacidad, plugin: &PluginClient) {
    let origen = papel.como_cadena();

    let respuesta = match plugin.preflight().await {
        Ok(respuesta) => respuesta,
        Err(error) => {
            // Aquí es donde `doctor` se separa de las demás operaciones: este
            // `Err` no sale de la función, se convierte en una línea más.
            checks.push(CheckResult {
                origen: origen.to_string(),
                nombre: "preflight".to_string(),
                ok: false,
                detalle: error.to_string(),
                remedio: format!(
                    "revisa que el plugin «{}» esté instalado, sea ejecutable y siga vivo",
                    plugin.nombre()
                ),
            });
            return;
        }
    };

    if papel == Capacidad::Engine && !respuesta.server_version.is_empty() {
        checks.push(CheckResult {
            origen: origen.to_string(),
            nombre: CHECK_VERSION_FUENTE.to_string(),
            ok: true,
            detalle: respuesta.server_version,
            remedio: String::new(),
        });
    }

    let alguno_falla = respuesta.checks.iter().any(|c| !c.ok);
    checks.extend(respuesta.checks.into_iter().map(|c| CheckResult {
        origen: origen.to_string(),
        nombre: c.name,
        ok: c.ok,
        detalle: c.detail,
        remedio: c.remediation,
    }));

    // Un plugin que dice «no estoy bien» sin decir en qué no puede colarse
    // como informe limpio: sin esto, un `ok: false` con la lista de checks
    // vacía —o con todas en verde— haría que `doctor` diera el visto bueno.
    if !respuesta.ok && !alguno_falla {
        checks.push(CheckResult {
            origen: origen.to_string(),
            nombre: "veredicto".to_string(),
            ok: false,
            detalle: format!(
                "el plugin «{}» se declara no preparado pero no dijo qué comprobación falla",
                plugin.nombre()
            ),
            remedio: "mira los registros del plugin: el fallo está ahí pero no llegó al informe"
                .to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(origen: &str, nombre: &str, ok: bool, remedio: &str) -> CheckResult {
        CheckResult {
            origen: origen.into(),
            nombre: nombre.into(),
            ok,
            detalle: String::new(),
            remedio: remedio.into(),
        }
    }

    #[test]
    fn un_informe_sin_fallos_esta_ok() {
        let informe = DoctorReport {
            target: "t".into(),
            checks: vec![
                check("engine", "binario", true, ""),
                check("storage", "bucket", true, ""),
            ],
        };
        assert!(informe.ok());
        assert!(informe.fallos().is_empty());
    }

    #[test]
    fn un_solo_fallo_tumba_el_informe() {
        let informe = DoctorReport {
            target: "t".into(),
            checks: vec![
                check("engine", "a", true, ""),
                check("storage", "b", false, "concede s3:PutObject"),
            ],
        };
        assert!(!informe.ok());
        assert_eq!(informe.fallos().len(), 1);
        assert_eq!(informe.fallos()[0].remedio, "concede s3:PutObject");
    }

    #[test]
    fn un_informe_vacio_no_se_considera_correcto() {
        // Cero comprobaciones significa que algo no llegó a ejecutarse, no que
        // todo vaya bien. Un `doctor` que dice «ok» sin haber comprobado nada
        // es peor que uno que falla.
        let informe = DoctorReport {
            target: "t".into(),
            checks: vec![],
        };
        assert!(!informe.ok());
    }

    #[test]
    fn el_informe_conserva_todos_los_fallos_no_solo_el_primero() {
        // El usuario quiere ver todo lo que está mal de una vez, no arreglar
        // un problema para descubrir el siguiente.
        let informe = DoctorReport {
            target: "t".into(),
            checks: vec![
                check("engine", "a", false, "arregla a"),
                check("engine", "b", false, "arregla b"),
                check("storage", "c", false, "arregla c"),
            ],
        };
        assert_eq!(informe.fallos().len(), 3);
    }

    #[test]
    fn los_fallos_conservan_de_que_plugin_vienen() {
        // En un backup hay dos plugins; «falta permiso» sin decir cuál obliga
        // a adivinar.
        let informe = DoctorReport {
            target: "t".into(),
            checks: vec![check("storage", "permisos", false, "x")],
        };
        assert_eq!(informe.fallos()[0].origen, "storage");
    }
}
