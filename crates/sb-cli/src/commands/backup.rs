//! `shieldbk backup [target]`.
//!
//! Lo único que este comando decide y nadie más puede decidir por él es **cómo
//! se llama el artefacto**: el núcleo recibe la clave ya calculada, porque una
//! operación que mirase el reloj por su cuenta no se podría probar. Aquí es
//! donde se mira, una sola vez por target, y en UTC: un backup nocturno no
//! puede cambiar de nombre porque el servidor entre en horario de verano.
//!
//! Lo segundo es que **un target que falla no se lleva por delante a los
//! demás**. Quien respalda diez bases de datos con un `cron` quiere que las
//! nueve que van bien se hagan igual, y enterarse al final de cuál fue la que
//! no. El código de salida sigue siendo de error si alguna falló.

use sb_config::Target;
use sb_core::naming::{NamingContext, render};
use sb_core::ops::backup::{BackupRequest, run_backup};
use sb_crypto::{CompressionLevel, Recipient};
use time::OffsetDateTime;

use crate::commands::concurrencia::por_lotes;
use crate::context::Contexto;
use crate::error::CliError;
use crate::output::Informe;
use crate::plugins::{self, Papel};

/// Lo que queda de respaldar un target, bien o mal.
struct Resultado {
    target: String,
    /// La clave solo existe si el backup llegó a nombrarse.
    clave: Option<String>,
    /// El fallo se guarda entero, no como texto: su clase es lo que decide el
    /// código de salida, y un plugin sin registrar tiene que salir con el
    /// código de plugin aunque el fallo se haya descubierto respaldando.
    fallo: Option<CliError>,
    plaintext: u64,
    ciphertext: u64,
    digest: String,
}

/// # Errors
/// Devuelve [`CliError::Config`] si el target no existe. Los backups que fallan
/// **no** se propagan como error: viajan dentro del informe, para que el que
/// respalda diez bases de datos vea las nueve que fueron bien.
pub async fn ejecutar(ctx: &Contexto, target: Option<&str>) -> Result<Informe, CliError> {
    let targets = ctx.targets(target)?;
    let total = targets.len();

    let resultados = por_lotes(targets, ctx.jobs, |t| respaldar(ctx, t)).await;

    let fallos: Vec<CliError> = resultados
        .iter()
        .filter_map(|r| r.fallo.as_ref().map(CliError::duplicar))
        .collect();
    let informe = componer(&resultados, total, fallos.len());

    let resumen = format!(
        "{} de {total} backups fallaron:\n{}",
        fallos.len(),
        detalle_de_fallos(&resultados)
    );
    Ok(match CliError::agrupar(resumen, &fallos) {
        Some(fallo) => informe.con_fallo(fallo),
        None => informe,
    })
}

/// Respalda un target de principio a fin. Nunca propaga: devuelve el fallo
/// dentro del resultado para que el resto de targets siga su curso.
async fn respaldar(ctx: &Contexto, target: &Target) -> Resultado {
    match intentar(ctx, target).await {
        Ok(resultado) => resultado,
        Err(fallo) => {
            tracing::error!(target = %target.name, %fallo, "el backup falló");
            Resultado {
                target: target.name.clone(),
                clave: None,
                fallo: Some(fallo),
                plaintext: 0,
                ciphertext: 0,
                digest: String::new(),
            }
        }
    }
}

async fn intentar(ctx: &Contexto, target: &Target) -> Result<Resultado, CliError> {
    // El destinatario se comprueba **antes** de arrancar ningún plugin: una
    // errata en la clave pública cuesta un segundo descubrirla aquí y cuesta un
    // artefacto ilegible para siempre descubrirla luego.
    let recipient = Recipient::parse(&target.recipient).map_err(|fuente| {
        CliError::config(format!(
            "el `recipient` del target «{}» no es una clave age válida: {fuente}",
            target.name
        ))
    })?;

    let nivel =
        CompressionLevel::new(target.nivel_efectivo(&ctx.config.defaults)).map_err(|fuente| {
            CliError::config(format!(
                "el nivel de compresión del target «{}» no vale: {fuente}",
                target.name
            ))
        })?;

    let ahora = OffsetDateTime::now_utc();
    let contexto = NamingContext::new(
        &target.name,
        &target.engine,
        &target.storage,
        ahora.unix_timestamp(),
    );
    let clave = render(target.plantilla_efectiva(&ctx.config.defaults), &contexto)?;

    let motor = plugins::arrancar_para(ctx, target, Papel::Motor).await?;
    let destino = match plugins::arrancar_para(ctx, target, Papel::Destino).await {
        Ok(destino) => destino,
        Err(error) => {
            plugins::cerrar(motor).await;
            return Err(error);
        }
    };

    let resultado = ejecutar_con(&motor, &destino, target, clave, recipient, nivel, ahora).await;

    plugins::cerrar(motor).await;
    plugins::cerrar(destino).await;
    resultado
}

async fn ejecutar_con(
    motor: &sb_core::plugin::PluginClient,
    destino: &sb_core::plugin::PluginClient,
    target: &Target,
    clave: String,
    recipient: Recipient,
    nivel: CompressionLevel,
    ahora: OffsetDateTime,
) -> Result<Resultado, CliError> {
    // La versión del plugin y la del servidor van al manifiesto. La segunda la
    // reporta el motor en su preflight, que además es la comprobación barata
    // que descarta una credencial caducada antes de mover un byte.
    let version_plugin = motor.info().await?.version;
    let version_servidor = motor.preflight().await?.server_version;

    let salida = run_backup(BackupRequest {
        target: target.name.clone(),
        engine: motor,
        storage: destino,
        artifact_key: clave,
        recipient,
        level: nivel,
        engine_version: version_plugin,
        server_version: version_servidor,
        created_at: iso8601_utc(ahora),
    })
    .await?;

    Ok(Resultado {
        target: target.name.clone(),
        clave: Some(salida.artifact_key),
        fallo: None,
        plaintext: salida.summary.plaintext_bytes,
        ciphertext: salida.summary.ciphertext_bytes,
        digest: salida.summary.ciphertext_sha256.to_hex(),
    })
}

/// La marca que va al manifiesto, en UTC y sin depender de la localización.
///
/// Se compone a mano en vez de con el formateador de `time` para no arrastrar
/// sus features de `formatting`: el formato es fijo y el manifiesto lo lee un
/// programa.
fn iso8601_utc(momento: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        momento.year(),
        u8::from(momento.month()),
        momento.day(),
        momento.hour(),
        momento.minute(),
        momento.second()
    )
}

fn componer(resultados: &[Resultado], total: usize, fallidos: usize) -> Informe {
    let mut lineas = Vec::with_capacity(resultados.len() + 1);
    let mut json = Vec::with_capacity(resultados.len());

    for r in resultados {
        match (&r.clave, &r.fallo) {
            (Some(clave), _) => {
                lineas.push(format!(
                    "{}: {clave} ({} bytes en claro → {} cifrados)",
                    r.target, r.plaintext, r.ciphertext
                ));
                json.push(serde_json::json!({
                    "target": r.target,
                    "ok": true,
                    "artifact_key": clave,
                    "plaintext_bytes": r.plaintext,
                    "ciphertext_bytes": r.ciphertext,
                    "ciphertext_sha256": r.digest,
                }));
            }
            (None, fallo) => {
                let motivo = fallo.as_ref().map(ToString::to_string).unwrap_or_default();
                lineas.push(format!("{}: FALLÓ — {motivo}", r.target));
                json.push(serde_json::json!({
                    "target": r.target,
                    "ok": false,
                    "error": motivo,
                }));
            }
        }
    }

    lineas.push(format!("{}/{total} backups completados", total - fallidos));

    Informe::new(
        lineas.join("\n"),
        serde_json::json!({
            "comando": "backup",
            "total": total,
            "fallidos": fallidos,
            "targets": json,
        }),
    )
}

fn detalle_de_fallos(resultados: &[Resultado]) -> String {
    resultados
        .iter()
        .filter_map(|r| r.fallo.as_ref().map(|f| format!("  {}: {f}", r.target)))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(target: &str, clave: &str) -> Resultado {
        Resultado {
            target: target.into(),
            clave: Some(clave.into()),
            fallo: None,
            plaintext: 10,
            ciphertext: 5,
            digest: "abc".into(),
        }
    }

    fn mal(target: &str, motivo: &str) -> Resultado {
        Resultado {
            target: target.into(),
            clave: None,
            fallo: Some(CliError::operacion(motivo)),
            plaintext: 0,
            ciphertext: 0,
            digest: String::new(),
        }
    }

    #[test]
    fn la_marca_de_tiempo_es_iso8601_en_utc() {
        // El manifiesto la lee un programa: el formato tiene que ser fijo y no
        // depender de la localización del servidor.
        let momento = OffsetDateTime::from_unix_timestamp(1_755_770_400).unwrap();
        let texto = iso8601_utc(momento);
        assert_eq!(texto.len(), 20, "{texto}");
        assert!(texto.ends_with('Z'), "{texto}");
        assert_eq!(&texto[4..5], "-");
        assert_eq!(&texto[10..11], "T");
    }

    #[test]
    fn el_json_lleva_la_clave_de_cada_artefacto() {
        // Es lo que un script busca: `jq '.targets[].artifact_key'`.
        let informe = componer(&[ok("prod", "prod/2026/x.age")], 1, 0);
        assert_eq!(
            informe.json["targets"][0]["artifact_key"],
            "prod/2026/x.age"
        );
        assert_eq!(informe.json["fallidos"], 0);
    }

    #[test]
    fn un_target_que_falla_no_borra_a_los_que_fueron_bien() {
        // Quien respalda diez bases de datos quiere las nueve buenas hechas y
        // saber cuál fue la décima.
        let informe = componer(&[ok("a", "a.age"), mal("b", "sin espacio")], 2, 1);
        assert_eq!(informe.json["targets"][0]["ok"], true);
        assert_eq!(informe.json["targets"][1]["ok"], false);
        assert_eq!(informe.json["targets"][1]["error"], "sin espacio");
        assert!(informe.humano.contains("1/2 backups completados"));
    }

    #[test]
    fn el_detalle_de_los_fallos_nombra_su_target() {
        let texto = detalle_de_fallos(&[ok("a", "a.age"), mal("b", "disco lleno")]);
        assert!(texto.contains('b'), "{texto}");
        assert!(texto.contains("disco lleno"), "{texto}");
        assert!(
            !texto.contains("a.age"),
            "los que fueron bien no son fallos"
        );
    }
}
