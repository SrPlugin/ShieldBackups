//! `shieldbk doctor [target]`.
//!
//! `doctor` no aborta. Nunca. Un plugin que no arranca es una línea del
//! informe, no el final del diagnóstico: si abortara, el usuario arreglaría un
//! problema para descubrir el siguiente, y así una vez por intento. Por eso
//! este comando envuelve incluso los fallos de arranque —que en cualquier otro
//! comando serían un error de plugin y un código de salida 3— en un
//! `CheckResult` más.
//!
//! La comprobación que añade la CLI y no puede añadir el núcleo es la del
//! `recipient`. Es barata —parsear una cadena— y convierte una errata en la
//! clave pública en un fallo inmediato en vez de en un artefacto que nadie
//! podrá descifrar jamás. Con origen `config`, porque lo que hay que arreglar
//! está en el fichero y no en ningún plugin.

use sb_config::Target;
use sb_core::ops::doctor::{CheckResult, DoctorReport, run_doctor};
use sb_core::plugin::PluginClient;
use sb_crypto::Recipient;

use crate::commands::concurrencia::por_lotes;
use crate::context::Contexto;
use crate::error::CliError;
use crate::output::Informe;
use crate::plugins::{self, Papel};

/// Origen de las comprobaciones que salen de la configuración y no de un
/// plugin.
const ORIGEN_CONFIG: &str = "config";

/// # Errors
/// Devuelve [`CliError::Config`] si el target no existe. Nada más: un plugin
/// que no arranca es una línea del informe, no un error de este comando.
pub async fn ejecutar(ctx: &Contexto, target: Option<&str>) -> Result<Informe, CliError> {
    let targets = ctx.targets(target)?;
    let informes = por_lotes(targets, ctx.jobs, |t| diagnosticar(ctx, t)).await;

    let con_fallos = informes.iter().filter(|i| !i.ok()).count();
    let informe = componer(&informes, con_fallos);

    if con_fallos == 0 {
        return Ok(informe);
    }
    // El informe **no** se sustituye por el error: el día que `doctor`
    // encuentra problemas es justo el día en que su lista hace falta.
    Ok(informe.con_fallo(CliError::operacion(format!(
        "{con_fallos} de {} targets tienen problemas:\n{}",
        informes.len(),
        detalle_de_fallos(&informes)
    ))))
}

/// Diagnostica un target entero, sin dejar que nada aborte.
async fn diagnosticar(ctx: &Contexto, target: &Target) -> DoctorReport {
    let mut checks = vec![comprobar_recipient(target)];

    // Los plugins se arrancan de uno en uno y sus fallos se anotan: aquí, un
    // plugin que no está es un hallazgo, no una excepción.
    let motor = arrancar(ctx, target, Papel::Motor, &mut checks).await;
    let destino = arrancar(ctx, target, Papel::Destino, &mut checks).await;

    if let (Some(motor), Some(destino)) = (&motor, &destino) {
        checks.extend(run_doctor(&target.name, motor, destino).await.checks);
    }

    if let Some(motor) = motor {
        plugins::cerrar(motor).await;
    }
    if let Some(destino) = destino {
        plugins::cerrar(destino).await;
    }

    DoctorReport {
        target: target.name.clone(),
        checks,
    }
}

/// Arranca un plugin y anota el resultado en vez de propagarlo.
async fn arrancar(
    ctx: &Contexto,
    target: &Target,
    papel: Papel,
    checks: &mut Vec<CheckResult>,
) -> Option<PluginClient> {
    match plugins::arrancar_para(ctx, target, papel).await {
        Ok(cliente) => Some(cliente),
        Err(fuente) => {
            checks.push(CheckResult {
                origin: papel.seccion().to_owned(),
                name: "arranque".to_owned(),
                ok: false,
                detail: fuente.to_string(),
                remedy: "el diagnóstico del plugin no se pudo hacer porque el plugin no llegó a \
                          arrancar: arregla esto primero"
                    .to_owned(),
            });
            None
        }
    }
}

/// La única comprobación que no viene de un plugin: que la clave pública a la
/// que se cifra existe de verdad.
fn comprobar_recipient(target: &Target) -> CheckResult {
    match Recipient::parse(&target.recipient) {
        Ok(_) => CheckResult {
            origin: ORIGEN_CONFIG.to_owned(),
            name: "recipient".to_owned(),
            ok: true,
            // Se muestra la clave **pública**: no es un secreto, y verla es la
            // única forma de notar que es la de otro sistema.
            detail: target.recipient.clone(),
            remedy: String::new(),
        },
        Err(fuente) => CheckResult {
            origin: ORIGEN_CONFIG.to_owned(),
            name: "recipient".to_owned(),
            ok: false,
            detail: format!(
                "«{}» no es una clave age válida: {fuente}",
                target.recipient
            ),
            remedy: format!(
                "corrige `recipient` en el target «{}»: tiene que ser la clave pública `age1…` \
                 que imprimió `age-keygen`. Con una clave inválida el backup no se puede cifrar, \
                 y con la clave equivocada no se podrá descifrar nunca",
                target.name
            ),
        },
    }
}

fn componer(informes: &[DoctorReport], con_fallos: usize) -> Informe {
    let mut lineas = Vec::new();
    let mut json = Vec::with_capacity(informes.len());

    for informe in informes {
        lineas.push(format!(
            "{} — {}",
            informe.target,
            if informe.ok() {
                "correcto"
            } else {
                "CON FALLOS"
            }
        ));
        for check in &informe.checks {
            let marca = if check.ok { "  ok " } else { "  ✗  " };
            lineas.push(format!(
                "{marca}[{}] {}: {}",
                check.origin, check.name, check.detail
            ));
            if !check.ok && !check.remedy.is_empty() {
                lineas.push(format!("       remedio: {}", check.remedy));
            }
        }

        json.push(serde_json::json!({
            "target": informe.target,
            "ok": informe.ok(),
            "server_version": informe.server_version(),
            "checks": informe.checks.iter().map(|c| serde_json::json!({
                "origen": c.origin,
                "nombre": c.name,
                "ok": c.ok,
                "detalle": c.detail,
                "remedio": c.remedy,
            })).collect::<Vec<_>>(),
        }));
    }

    Informe::new(
        lineas.join("\n"),
        serde_json::json!({
            "comando": "doctor",
            "total": informes.len(),
            "con_fallos": con_fallos,
            "targets": json,
        }),
    )
}

fn detalle_de_fallos(informes: &[DoctorReport]) -> String {
    informes
        .iter()
        .filter(|i| !i.ok())
        .flat_map(|i| {
            i.failures()
                .into_iter()
                .map(move |c| format!("  {} [{}] {}: {}", i.target, c.origin, c.name, c.detail))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target_con(recipient: &str) -> Target {
        Target {
            name: "prod".into(),
            engine: "postgres".into(),
            storage: "r2".into(),
            recipient: recipient.into(),
            engine_config: sb_config::ConfigTable::new(),
            storage_config: sb_config::ConfigTable::new(),
            compression_level: None,
            artifact_template: None,
        }
    }

    #[test]
    fn una_clave_publica_valida_pasa_la_comprobacion() {
        let publica = sb_crypto::Identity::generate().to_recipient().to_string();
        let check = comprobar_recipient(&target_con(&publica));
        assert!(check.ok, "{}", check.detail);
        assert_eq!(check.origin, ORIGEN_CONFIG);
        assert_eq!(check.name, "recipient");
    }

    #[test]
    fn una_errata_en_la_clave_publica_se_detecta_con_remedio() {
        // Es toda la razón de esta comprobación: una letra de más aquí no da
        // ningún error hasta que alguien intenta restaurar, y entonces ya no
        // hay nada que hacer.
        let check = comprobar_recipient(&target_con("age1esto-no-es-una-clave"));
        assert!(!check.ok);
        assert_eq!(check.origin, ORIGEN_CONFIG);
        assert!(
            check.remedy.contains("age-keygen"),
            "un check que falla sin decir qué hacer no sirve: {}",
            check.remedy
        );
        assert!(check.detail.contains("age1esto-no-es-una-clave"));
    }

    #[test]
    fn un_recipient_vacio_tambien_falla() {
        assert!(!comprobar_recipient(&target_con("")).ok);
    }

    #[test]
    fn el_informe_json_lleva_el_origen_de_cada_comprobacion() {
        // Un backup tiene dos plugins vivos: «falta permiso» sin decir de cuál
        // obliga a adivinar.
        let informe = DoctorReport {
            target: "prod".into(),
            checks: vec![
                comprobar_recipient(&target_con("no vale")),
                CheckResult {
                    origin: "storage".into(),
                    name: "bucket".into(),
                    ok: true,
                    detail: "existe".into(),
                    remedy: String::new(),
                },
            ],
        };
        let salida = componer(std::slice::from_ref(&informe), 1);
        assert_eq!(salida.json["targets"][0]["checks"][0]["origen"], "config");
        assert_eq!(salida.json["targets"][0]["checks"][1]["origen"], "storage");
        assert_eq!(salida.json["targets"][0]["ok"], false);
        assert!(salida.humano.contains("remedio:"));
    }
}
