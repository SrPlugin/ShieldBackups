//! La operación de verify: comprobar un artefacto **sin poder leerlo**.
//!
//! ```text
//! plugin-destino ──[socket datos]──▶ núcleo ──▶ SHA-256 ──▶ /dev/null
//! ```
//!
//! Esta operación es la razón de que el pipeline hashee el texto cifrado y no
//! el plano. El digest del plaintext obligaría a descifrar para comprobar
//! cualquier cosa, y descifrar exige la clave privada; hasheando el ciphertext,
//! **una máquina puede comprobar que sus backups siguen íntegros sin tener con
//! qué leerlos**. Por eso [`ejecutar_verify`] no recibe ninguna `Identity`: no
//! es que no la use, es que no puede.
//!
//! Lo segundo que define esta operación es lo que **no** hace: no carga el
//! artefacto en memoria. Los bytes van de la tubería al hasher y de ahí a
//! [`tokio::io::sink`], así que verificar un artefacto de trescientos gigabytes
//! cuesta lo mismo en RAM que verificar uno de tres kilobytes.

use sb_crypto::Sha256Reader;

use crate::model::{Manifest, manifest_key_de};
use crate::ops::canal::{
    BackupError, OP_GET, aceptar, crear_canal, descargar_blob, esperar_progreso, iniciar_get,
};
use crate::plugin::{Capacidad, PluginClient};

/// El veredicto sobre un artefacto.
///
/// Los dos digests van dentro aunque coincidan: un informe que solo dijera
/// `ok: false` no le sirve de nada a quien tiene que decidir si el problema es
/// el artefacto, el manifiesto o el destino.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOutcome {
    /// Cierto solo si coinciden **el digest y el número de bytes**.
    pub ok: bool,
    /// El que dice el manifiesto.
    pub digest_esperado: String,
    /// El que se ha calculado leyendo el artefacto del destino.
    pub digest_obtenido: String,
    /// Los bytes que el destino sirvió de verdad.
    pub bytes: u64,
}

/// Trae del destino el manifiesto que describe a `artifact_key`.
///
/// Es lo primero que hace [`ejecutar_verify`], y está aparte porque no es solo
/// suyo: `restore` necesita el mismo manifiesto —para saber qué digest debe
/// tener el artefacto que le sirvan— y sin esto tendría que repetir la regla de
/// cómo se deriva la clave y cómo se interpreta el contenido.
///
/// # Errors
/// Devuelve [`BackupError::SinManifiesto`] si no se pudo traer —el mensaje
/// nombra la clave exacta que se buscó— o [`BackupError::Manifiesto`] si no se
/// entiende.
pub async fn leer_manifiesto(
    storage: &PluginClient,
    artifact_key: &str,
) -> Result<Manifest, BackupError> {
    let clave_manifiesto = manifest_key_de(artifact_key);
    let crudo = descargar_blob(storage, &clave_manifiesto)
        .await
        .map_err(|fuente| BackupError::SinManifiesto {
            plugin: storage.nombre().to_string(),
            clave: clave_manifiesto.clone(),
            motivo: fuente.to_string(),
        })?;
    let texto = String::from_utf8(crudo).map_err(|_| BackupError::SinManifiesto {
        plugin: storage.nombre().to_string(),
        clave: clave_manifiesto.clone(),
        motivo: "no es texto UTF-8".to_string(),
    })?;
    Ok(Manifest::parse(&texto)?)
}

/// Descarga el artefacto y comprueba su digest contra el manifiesto.
///
/// Que un artefacto no cuadre **no** es un error de esta función: es su
/// respuesta, y es justo lo que hay que enseñarle a quien la llamó. Solo falla
/// si no se puede llegar a emitir un veredicto: si el manifiesto no está, si no
/// se entiende, o si la descarga se rompe.
///
/// # Por qué se lee el manifiesto primero
///
/// Sin él no hay contra qué comparar, y descargar cien gigabytes para
/// descubrirlo al final es un coste que ya no se puede devolver. Además, la
/// asimetría del fallo importa: «no encuentro el manifiesto» tiene un remedio
/// —buscarlo, restaurarlo, mirar si la clave era otra— y el mensaje dice qué
/// clave exacta se buscó para que ese remedio sea posible.
///
/// # Errors
/// Devuelve [`BackupError::SinManifiesto`] si el manifiesto no se pudo traer
/// —el mensaje nombra la clave—, [`BackupError::Manifiesto`] si no se entiende,
/// y las variantes de transferencia si la descarga del artefacto se rompe.
pub async fn ejecutar_verify(
    storage: &PluginClient,
    artifact_key: &str,
) -> Result<VerifyOutcome, BackupError> {
    storage.exigir_capacidad(Capacidad::Storage)?;

    // 1. El manifiesto primero: es pequeño y es lo único que dice qué se
    //    espera. Va a memoria porque cabe; el artefacto no.
    let manifiesto = leer_manifiesto(storage, artifact_key).await?;

    // 2. El artefacto se lee **en flujo**, contra un sumidero que lo tira. Lo
    //    único que interesa es lo que el hasher va acumulando por el camino:
    //    cargar el artefacto en memoria haría que verificar un backup grande
    //    fuera imposible justo en la máquina pequeña que más lo necesita.
    let canal = crear_canal(storage)?;
    let descarga = iniciar_get(storage, artifact_key, &canal).await?;
    let fuente = aceptar(&canal, storage.nombre(), OP_GET).await?;

    let mut lector = Sha256Reader::new(fuente);
    let bytes = tokio::io::copy(&mut lector, &mut tokio::io::sink())
        .await
        .map_err(|fuente| BackupError::Io {
            plugin: storage.nombre().to_string(),
            fuente,
        })?;
    let obtenido = lector.digest().to_hex();

    // 3. El plugin puede tener aún algo que decir: un `Get` que se rompió a
    //    mitad llega por el flujo de progreso y no por la tubería, donde solo
    //    se ve un fin de flujo prematuro que parecería un artefacto corto.
    esperar_progreso(descarga, storage.nombre(), OP_GET).await?;

    // 4. Los dos criterios, no uno: el digest cubre el contenido y el tamaño
    //    cubre el caso degenerado de un destino que sirviera menos de lo que
    //    dice tener. Que el segundo sea redundante en la práctica no lo hace
    //    inútil: es la comprobación barata que además explica el fallo.
    let ok = obtenido == manifiesto.ciphertext_sha256 && bytes == manifiesto.ciphertext_bytes;
    if !ok {
        tracing::warn!(
            clave = %artifact_key,
            esperado = %manifiesto.ciphertext_sha256,
            obtenido = %obtenido,
            bytes,
            esperados = manifiesto.ciphertext_bytes,
            "el artefacto no coincide con su manifiesto"
        );
    }

    Ok(VerifyOutcome {
        ok,
        digest_esperado: manifiesto.ciphertext_sha256,
        digest_obtenido: obtenido,
        bytes,
    })
}
