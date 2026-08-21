//! La operación de backup: motor → núcleo → destino, en un solo paso y sin
//! tocar el disco local.
//!
//! ```text
//! plugin-motor ──[socket datos]──▶ núcleo ──[socket datos]──▶ plugin-destino
//!                               zstd → age → SHA-256
//! ```
//!
//! Los bytes cruzan **dos veces** el límite de proceso y en ningún momento se
//! materializan enteros: la memoria que usa un backup de un terabyte es la
//! misma que la de uno de un megabyte.
//!
//! # El orden de las llamadas
//!
//! Se llama primero a `Storage.Put` y **después** a `Engine.Dump`, que es justo
//! al revés de como se lee el diagrama. La razón está en [`ejecutar_backup`] y
//! no es una preferencia estilística: es la diferencia entre un backup que
//! termina y uno que se cuelga.

use sb_crypto::{BackupOptions, BackupSummary, CompressionLevel, Recipient};

use crate::model::{CompressionInfo, EncryptionInfo, EngineInfo, MANIFEST_VERSION, Manifest};
use crate::ops::canal::{
    OP_DUMP, OP_PUT, aceptar, crear_canal, esperar_progreso, iniciar_dump, iniciar_put, subir_blob,
};
use crate::plugin::{Capacidad, PluginClient};

// El error y la mecánica de las transferencias son de las tres operaciones, no
// solo de esta: viven en `ops/canal.rs`. Se reexporta aquí porque
// `ops::backup::BackupError` es el camino por el que ya se le conoce.
pub use crate::ops::canal::BackupError;

/// Algoritmo de compresión que registra el manifiesto. Lo fija el pipeline de
/// `sb-crypto`, no la configuración.
const ALGORITMO_COMPRESION: &str = "zstd";
/// Algoritmo de cifrado, por el mismo motivo.
const ALGORITMO_CIFRADO: &str = "age";

/// Todo lo que hace falta para un backup, ya resuelto.
///
/// Los plugins llegan **arrancados y configurados**: esta operación no decide
/// qué plugin usar ni cómo configurarlo, solo los pone a hablar.
pub struct BackupRequest<'a> {
    pub target: String,
    pub engine: &'a PluginClient,
    pub storage: &'a PluginClient,
    pub artifact_key: String,
    pub recipient: Recipient,
    pub level: CompressionLevel,
    pub engine_version: String,
    pub server_version: String,
    /// Marca ISO-8601 en UTC. La calcula quien llama, para que la operación
    /// sea determinista y testeable.
    pub created_at: String,
}

/// Lo que queda de un backup que salió bien.
#[derive(Debug, Clone)]
pub struct BackupOutcome {
    pub summary: BackupSummary,
    pub artifact_key: String,
}

/// Ejecuta un backup completo y deja el artefacto y su manifiesto en el destino.
///
/// # El orden de `Put` y `Dump`, que es contraintuitivo a propósito
///
/// `Storage.Put` se llama **antes** que `Engine.Dump`. Leyendo el diagrama de
/// arriba se diría que el productor va primero, y es exactamente el cambio que
/// alguien intentará hacer algún día.
///
/// No lo hagas, y esta es la razón con lo que se sabe medido detrás.
///
/// El socket del volcado tiene un búfer del kernel de unos 208 KiB
/// (`net.core.wmem_default`). Si el motor arranca antes de que el destino esté
/// colocado, escribe en un socket que todavía nadie va a drenar y se bloquea en
/// su `write` en cuanto ese búfer se llena. **Lo que ocurre después depende de
/// algo que este código no controla: de cómo esté escrito el plugin.**
///
/// Se probó a invertir el orden y los tests de `tests/backup_mock.rs` siguen
/// pasando, incluso metiendo tres segundos de retardo entre las dos llamadas:
/// con plugins como el mock —cuyo `Dump` devuelve las cabeceras del RPC de
/// inmediato y hace el trabajo en una tarea aparte— el motor no se cuelga, solo
/// se queda parado en su `write` hasta que el núcleo llega al `accept` y el
/// pipeline empieza a drenar. Que aquí no se vea no significa que dé igual:
///
/// * Un plugin cuyo `Dump` escriba **antes** de devolver la respuesta del RPC
///   —el protocolo no lo prohíbe— nunca contestaría, y `Dump` primero
///   significaría que `Put` no llega a llamarse jamás. Eso sí es el bloqueo, y
///   solo lo corta el plazo de apertura de `ops::canal`.
/// * Con `Dump` primero, un `Put` que falle —clave inválida, destino caído—
///   deja detrás un motor ya lanzado, escribiendo contra un socket que se va a
///   cerrar debajo. Poner `Put` delante hace que ese fallo ocurra antes de
///   haber movido un solo byte.
///
/// La regla que hay debajo es la que vale la pena recordar: **el consumidor se
/// coloca antes que el productor**, siempre. Es gratis y quita de en medio una
/// clase entera de cuelgues que, por definición, no se manifiestan en las
/// pruebas donde todo va bien.
///
/// # Errors
/// Devuelve [`BackupError`] si algún plugin no tiene la capacidad que se le
/// pide, si no se conecta a su canal de datos dentro del plazo, si la
/// transferencia se rompe o si falla el pipeline.
pub async fn ejecutar_backup(req: BackupRequest<'_>) -> Result<BackupOutcome, BackupError> {
    // 1. Antes de nada: que cada plugin sepa hacer el papel que se le asigna.
    //    Descubrirlo aquí cuesta una comparación de cadenas; descubrirlo a
    //    mitad del volcado cuesta el volcado.
    req.engine.exigir_capacidad(Capacidad::Engine)?;
    req.storage.exigir_capacidad(Capacidad::Storage)?;

    // 2. Un canal por plugin, cada uno dentro del directorio de ejecución de su
    //    dueño: es el único sitio al que ese proceso tiene acceso garantizado.
    let canal_volcado = crear_canal(req.engine)?;
    let canal_subida = crear_canal(req.storage)?;

    // 3 y 4. EL CONSUMIDOR PRIMERO. Ver la nota de arriba antes de tocar esto.
    let subida = iniciar_put(req.storage, &req.artifact_key, &canal_subida).await?;
    let volcado = iniciar_dump(req.engine, &canal_volcado).await?;

    // 6. Ambos plugins tienen ya su orden; ahora deben aparecer por el socket.
    let fuente = aceptar(&canal_volcado, req.engine.nombre(), OP_DUMP).await?;
    let sumidero = aceptar(&canal_subida, req.storage.nombre(), OP_PUT).await?;

    // 7. El núcleo no es más que el tramo de tubería entre los dos sockets.
    let recipiente = req.recipient.to_string();
    let summary = sb_crypto::backup(
        fuente,
        sumidero,
        &BackupOptions {
            recipient: req.recipient,
            level: req.level,
        },
    )
    .await?;

    // 8. El pipeline ha terminado, pero los plugins no tienen por qué: el
    //    destino aún puede estar cerrando su fichero. Sin esperar aquí, el
    //    manifiesto podría describir un artefacto que todavía no está entero.
    esperar_progreso(volcado, req.engine.nombre(), OP_DUMP).await?;
    esperar_progreso(subida, req.storage.nombre(), OP_PUT).await?;

    // 9. El manifiesto sube por el mismo camino que el artefacto —otro canal,
    //    otro `Put`—. Un segundo camino (un RPC aparte que escribiera el JSON)
    //    sería más corto, pero permitiría que artefacto y manifiesto acabaran
    //    en sitios distintos o con permisos distintos sin que nadie lo notase.
    let manifiesto = Manifest {
        version: MANIFEST_VERSION,
        target: req.target,
        engine: EngineInfo {
            plugin: req.engine.nombre().to_string(),
            plugin_version: req.engine_version,
            server_version: req.server_version,
        },
        created_at: req.created_at,
        artifact_key: req.artifact_key.clone(),
        plaintext_bytes: summary.plaintext_bytes,
        ciphertext_bytes: summary.ciphertext_bytes,
        plaintext_sha256: summary.plaintext_sha256.to_hex(),
        ciphertext_sha256: summary.ciphertext_sha256.to_hex(),
        compression: CompressionInfo {
            algorithm: ALGORITMO_COMPRESION.to_string(),
            level: req.level.get(),
        },
        encryption: EncryptionInfo {
            algorithm: ALGORITMO_CIFRADO.to_string(),
            recipient: recipiente,
        },
    };
    subir_blob(
        req.storage,
        &manifiesto.manifest_key(),
        manifiesto.to_json()?.as_bytes(),
    )
    .await?;

    tracing::info!(
        clave = %req.artifact_key,
        plaintext = summary.plaintext_bytes,
        ciphertext = summary.ciphertext_bytes,
        "backup completado"
    );

    Ok(BackupOutcome {
        summary,
        artifact_key: req.artifact_key,
    })
}
