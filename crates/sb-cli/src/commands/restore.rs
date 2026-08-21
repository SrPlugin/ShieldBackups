//! `shieldbk restore <target> <artifact> --identity <ruta>`.
//!
//! Es el único comando que necesita la clave privada, y por eso es el único que
//! la pide explícitamente en un argumento en vez de sacarla de la
//! configuración: una clave privada referenciada desde un fichero que se
//! versiona acabaría, antes o después, dentro del repositorio.
//!
//! Antes de mover un byte se lee el manifiesto para saber qué digest debe
//! tener el artefacto que el destino va a servir. No es redundante con el AEAD
//! de age: un artefacto **ajeno** pero bien formado y dirigido a la misma
//! identidad se descifraría sin protestar, y sin el digest nadie se enteraría
//! de que la base de datos se ha restaurado con el backup de otro sistema.

use std::path::Path;

use sb_core::ops::restore::{RestoreRequest, ejecutar_restore};
use sb_core::ops::verify::leer_manifiesto;
use sb_crypto::{Digest, Identity};

use crate::context::Contexto;
use crate::error::CliError;
use crate::output::Informe;
use crate::plugins::{self, Papel};

/// # Errors
/// Devuelve [`CliError::Config`] si el target no existe o la identidad no se
/// puede leer, [`CliError::Plugin`] si algún plugin no arranca y
/// [`CliError::Operacion`] si la restauración falla.
pub async fn ejecutar(
    ctx: &Contexto,
    target: &str,
    artifact: &str,
    identity: &Path,
) -> Result<Informe, CliError> {
    let target = ctx.target(target)?;
    let identidad = leer_identidad(identity)?;

    let motor = plugins::arrancar_para(ctx, target, Papel::Motor).await?;
    let destino = match plugins::arrancar_para(ctx, target, Papel::Destino).await {
        Ok(destino) => destino,
        Err(error) => {
            plugins::cerrar(motor).await;
            return Err(error);
        }
    };

    let resultado = restaurar(&motor, &destino, artifact, &identidad).await;

    plugins::cerrar(motor).await;
    plugins::cerrar(destino).await;

    let escritos = resultado?;
    Ok(Informe::new(
        format!(
            "{}: restaurados {escritos} bytes desde {artifact}",
            target.name
        ),
        serde_json::json!({
            "comando": "restore",
            "target": target.name,
            "artifact_key": artifact,
            "plaintext_bytes": escritos,
        }),
    ))
}

async fn restaurar(
    motor: &sb_core::plugin::PluginClient,
    destino: &sb_core::plugin::PluginClient,
    artifact: &str,
    identidad: &Identity,
) -> Result<u64, CliError> {
    // El manifiesto puede no estar —un artefacto copiado a mano, un destino a
    // medio migrar— y eso no puede impedir la restauración: si falta, se avisa
    // y se sigue sin la comprobación extra. Negarse sería dejar sin recuperar
    // datos que sí se pueden recuperar.
    let esperado = match leer_manifiesto(destino, artifact).await {
        Ok(manifiesto) => Digest::from_hex(&manifiesto.ciphertext_sha256).ok(),
        Err(fuente) => {
            tracing::warn!(
                clave = artifact,
                %fuente,
                "sin manifiesto: se restaura sin comprobar que el destino sirvió el artefacto \
                 que se pidió"
            );
            None
        }
    };

    Ok(ejecutar_restore(RestoreRequest {
        engine: motor,
        storage: destino,
        artifact_key: artifact.to_owned(),
        identity: identidad,
        expected_ciphertext_sha256: esperado,
    })
    .await?)
}

/// Lee el fichero de clave privada.
///
/// El error nombra la ruta pero **nunca el contenido**: lo que se estaba
/// leyendo es una clave privada, y un mensaje que la citara la dejaría escrita
/// en el log de quien se equivocó de fichero.
fn leer_identidad(ruta: &Path) -> Result<Identity, CliError> {
    let texto = std::fs::read_to_string(ruta).map_err(|fuente| {
        CliError::config(format!(
            "no se pudo leer la clave privada «{}»: {fuente}",
            ruta.display()
        ))
    })?;

    Identity::parse(&texto).map_err(|fuente| {
        CliError::config(format!(
            "«{}» no contiene una clave privada age: {fuente}",
            ruta.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn una_identidad_se_lee_del_fichero_que_escribe_age_keygen() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("clave.txt");
        let original = Identity::generate();
        std::fs::write(
            &ruta,
            format!(
                "# created: 2026-08-21T00:00:00Z\n# public key: {}\n{}\n",
                original.to_recipient(),
                original.to_secret_string().expose()
            ),
        )
        .unwrap();

        let leida = leer_identidad(&ruta).unwrap();
        assert_eq!(
            leida.to_recipient().to_string(),
            original.to_recipient().to_string()
        );
    }

    #[test]
    fn un_fichero_que_no_existe_se_explica_nombrando_la_ruta() {
        let error = leer_identidad(Path::new("/no/existe/clave.txt"))
            .err()
            .unwrap();
        assert_eq!(error.clase(), "config");
        assert!(error.to_string().contains("/no/existe/clave.txt"));
    }

    #[test]
    fn un_fichero_que_no_es_una_clave_no_delata_su_contenido() {
        // El caso real: alguien apunta `--identity` a un fichero equivocado que
        // resulta contener otro secreto.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("otro.txt");
        std::fs::write(&ruta, "contrasena-de-produccion-1234").unwrap();

        let error = leer_identidad(&ruta).err().unwrap();
        assert_eq!(error.clase(), "config");
        assert!(
            !error.to_string().contains("contrasena-de-produccion-1234"),
            "el mensaje no puede repetir lo que había dentro: {error}"
        );
    }
}
