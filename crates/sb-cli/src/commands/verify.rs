//! `shieldbk verify <target> [artifact]`.
//!
//! Este comando arranca **solo el plugin de destino**, y eso no es un ahorro:
//! es la propiedad que justifica que el pipeline hashee el texto cifrado y no
//! el plano. Verificar no descifra nada, así que una máquina puede comprobar
//! que sus backups siguen íntegros sin tener con qué leerlos y sin molestar a
//! la base de datos que respalda.
//!
//! Sin artefacto se comprueban todos los del target. Es el uso que de verdad
//! importa —un `cron` semanal contra todo el repositorio— y por eso un
//! artefacto que no cuadra no interrumpe al siguiente: el informe tiene que
//! decir cuántos pasaron, no cuál fue el primero que falló.

use sb_core::ops::verify::run_verify;
use sb_core::plugin::PluginClient;

use crate::artifacts;
use crate::context::Contexto;
use crate::error::CliError;
use crate::output::Informe;
use crate::plugins::{self, Papel};

/// El veredicto sobre un artefacto, ya listo para contarlo.
struct Veredicto {
    clave: String,
    ok: bool,
    detalle: String,
}

/// # Errors
/// Devuelve [`CliError::Config`] si el target no existe y [`CliError::Plugin`]
/// si el destino no arranca. Un artefacto que no cuadra **no** interrumpe la
/// comprobación: el veredicto negativo viaja dentro del informe.
pub async fn ejecutar(
    ctx: &Contexto,
    target: &str,
    artifact: Option<&str>,
) -> Result<Informe, CliError> {
    let target = ctx.target(target)?;
    let destino = plugins::arrancar_para(ctx, target, Papel::Destino).await?;

    // Sin artefacto se comprueban todos los del target, que es el uso que de
    // verdad importa: un `cron` semanal contra todo el repositorio.
    let claves = if let Some(clave) = artifact {
        Ok(vec![clave.to_owned()])
    } else {
        let prefijo = artifacts::prefijo_de(target, &ctx.config.defaults);
        artifacts::listar(&destino, &prefijo)
            .await
            .map(|metas| metas.into_iter().map(|m| m.key).collect())
    };

    // El destino se cierra pase lo que pase, también si el listado falló: un
    // plugin vivo al que ya nadie va a pedirle nada es un proceso con material
    // criptográfico de sesión en memoria.
    let resultado = match claves {
        Ok(claves) => Ok(comprobar(&destino, claves).await),
        Err(error) => Err(error),
    };
    plugins::cerrar(destino).await;

    let veredictos = resultado?;
    let fallidos = veredictos.iter().filter(|v| !v.ok).count();
    let informe = componer(&target.name, &veredictos, fallidos);

    if fallidos == 0 {
        return Ok(informe);
    }
    // El fallo viaja **dentro** del informe: quien pregunta «¿cuántos backups
    // tengo de verdad?» necesita la lista completa, no solo el veredicto.
    Ok(informe.con_fallo(CliError::operacion(format!(
        "{fallidos} de {} artefactos del target «{}» no cuadran:\n{}",
        veredictos.len(),
        target.name,
        detalle_de_fallos(&veredictos)
    ))))
}

/// Comprueba las claves una a una. Ninguna interrumpe a la siguiente: la
/// pregunta que hay que responder es «¿cuántos backups tengo de verdad?».
async fn comprobar(destino: &PluginClient, claves: Vec<String>) -> Vec<Veredicto> {
    let mut veredictos = Vec::with_capacity(claves.len());
    for clave in claves {
        veredictos.push(match run_verify(destino, &clave).await {
            Ok(salida) if salida.ok => Veredicto {
                clave,
                ok: true,
                detalle: format!("{} bytes", salida.bytes),
            },
            Ok(salida) => Veredicto {
                clave,
                ok: false,
                detalle: format!(
                    "el manifiesto esperaba sha256 {} y el destino sirvió {} ({} bytes)",
                    salida.expected_digest, salida.actual_digest, salida.bytes
                ),
            },
            // No poder emitir un veredicto es un veredicto negativo: un
            // artefacto sin manifiesto no es un backup del que fiarse.
            Err(fuente) => Veredicto {
                clave,
                ok: false,
                detalle: fuente.to_string(),
            },
        });
    }
    veredictos
}

fn componer(target: &str, veredictos: &[Veredicto], fallidos: usize) -> Informe {
    let total = veredictos.len();
    let mut lineas: Vec<String> = veredictos
        .iter()
        .map(|v| {
            let marca = if v.ok { "ok" } else { "FALLÓ" };
            format!("{marca} {}: {}", v.clave, v.detalle)
        })
        .collect();
    lineas.push(format!(
        "{}/{total} artefactos de «{target}» verificados",
        total - fallidos
    ));

    let json: Vec<serde_json::Value> = veredictos
        .iter()
        .map(|v| {
            serde_json::json!({
                "artifact_key": v.clave,
                "ok": v.ok,
                "detalle": v.detalle,
            })
        })
        .collect();

    Informe::new(
        lineas.join("\n"),
        serde_json::json!({
            "comando": "verify",
            "target": target,
            "total": total,
            "fallidos": fallidos,
            "artefactos": json,
        }),
    )
}

fn detalle_de_fallos(veredictos: &[Veredicto]) -> String {
    veredictos
        .iter()
        .filter(|v| !v.ok)
        .map(|v| format!("  {}: {}", v.clave, v.detalle))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn veredicto(clave: &str, ok: bool) -> Veredicto {
        Veredicto {
            clave: clave.into(),
            ok,
            detalle: if ok { "100 bytes" } else { "no cuadra" }.into(),
        }
    }

    #[test]
    fn el_informe_cuenta_cuantos_pasaron() {
        // Es la pregunta que responde este comando: no «¿falló algo?» sino
        // «¿cuántos backups tengo de verdad?».
        let informe = componer(
            "prod",
            &[
                veredicto("a", true),
                veredicto("b", false),
                veredicto("c", true),
            ],
            1,
        );
        assert_eq!(informe.json["total"], 3);
        assert_eq!(informe.json["fallidos"], 1);
        assert!(informe.humano.contains("2/3 artefactos"));
    }

    #[test]
    fn cero_artefactos_no_es_un_fallo_pero_se_ve() {
        // Un target recién creado todavía no tiene backups, y decir «0/0» es
        // más honesto que callarse.
        let informe = componer("nuevo", &[], 0);
        assert_eq!(informe.json["total"], 0);
        assert!(informe.humano.contains("0/0"));
    }

    #[test]
    fn los_fallos_se_detallan_uno_a_uno() {
        let texto = detalle_de_fallos(&[veredicto("a", true), veredicto("b", false)]);
        assert!(texto.contains('b'));
        assert!(!texto.contains("a:"), "los que pasaron no son fallos");
    }
}
