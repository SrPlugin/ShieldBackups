//! La operación de restore: destino → núcleo → motor, el backup del revés.
//!
//! ```text
//! plugin-destino ──[socket datos]──▶ núcleo ──[socket datos]──▶ plugin-motor
//!                             SHA-256 → age⁻¹ → zstd⁻¹
//! ```
//!
//! Igual que en el backup, los bytes cruzan **dos veces** el límite de proceso
//! sin materializarse enteros en ningún sitio.
//!
//! # El orden de las llamadas
//!
//! Aquí el consumidor es el **motor** —es quien recibe el volcado—, así que se
//! llama a `Engine.Restore` **antes** que a `Storage.Get`. Es la misma regla
//! que en [`crate::ops::backup::ejecutar_backup`], cuyo doc-comment tiene el
//! razonamiento medido: el consumidor se coloca antes que el productor.

use sb_crypto::{Digest, Identity, RestoreOptions};
use tokio::io::AsyncWriteExt as _;

use crate::ops::canal::{
    BackupError, OP_GET, OP_RESTORE, aceptar, crear_canal, esperar_progreso, iniciar_get,
    iniciar_restore,
};
use crate::plugin::{Capacidad, PluginClient};

/// Todo lo que hace falta para una restauración, ya resuelto.
///
/// Los plugins llegan **arrancados y configurados**, como en el backup: esta
/// operación no elige plugin ni resuelve configuración, solo los pone a hablar.
pub struct RestoreRequest<'a> {
    pub engine: &'a PluginClient,
    pub storage: &'a PluginClient,
    pub artifact_key: String,
    /// La clave privada. Sin ella no hay restauración posible: es justo lo que
    /// `verify` **no** necesita.
    pub identity: &'a Identity,
    /// El digest que el manifiesto dice que debe tener el artefacto.
    ///
    /// Es opcional porque el manifiesto puede no estar —o quien llama puede
    /// haberlo comprobado ya con `verify`—, pero omitirlo renuncia a detectar
    /// que el destino sirvió un artefacto **distinto** del que se pidió. El AEAD
    /// de age no cubre ese caso: un artefacto ajeno bien formado y dirigido a la
    /// misma identidad se descifraría sin protestar.
    pub expected_ciphertext_sha256: Option<Digest>,
}

/// Descarga el artefacto, lo verifica, lo descifra, lo descomprime y se lo
/// entrega al motor.
///
/// Devuelve los bytes de plaintext entregados.
///
/// # Advertencia: un error puede dejar plaintext parcial en el motor
///
/// age entrega los bloques AEAD **ya verificados** de forma incremental, así
/// que ante un artefacto truncado la lectura falla después de haber escrito
/// todo lo que venía antes del corte: plaintext legítimo, pero parcial (se
/// midieron 65 536 bytes). Lo mismo vale, y peor, para
/// [`RestoreRequest::expected_ciphertext_sha256`]: el digest solo se puede
/// comprobar cuando ya se ha leído el flujo entero, es decir, cuando el motor
/// ya lo ha recibido todo.
///
/// El núcleo hace aquí lo único que puede hacer: **no** cerrar ordenadamente el
/// canal del motor cuando algo falla —el motor ve el corte, no un fin de flujo
/// normal—, abandonar las transferencias y devolver error sin esperar a que los
/// plugins digan que terminaron bien.
///
/// Eso no basta, y conviene decirlo claro: **descartar lo escrito es
/// responsabilidad del motor**, porque es el único que sabe qué significa
/// deshacerlo. En la Fase 1 la defensa concreta es que `pg_restore` corre con
/// `--single-transaction`, de modo que un volcado a medias no se confirma. Es
/// una defensa **del plugin**, no del núcleo: un motor futuro que escriba
/// ficheros directamente tendrá que traer la suya.
///
/// # Errors
/// Devuelve [`BackupError`] si algún plugin no tiene la capacidad que se le
/// pide, si no se conecta a su canal de datos dentro del plazo, si la
/// transferencia se rompe, si el artefacto no está dirigido a `identity`, si
/// está corrupto o truncado, o si su digest no es el esperado.
pub async fn ejecutar_restore(req: RestoreRequest<'_>) -> Result<u64, BackupError> {
    // 1. Antes de nada: que cada plugin sepa hacer el papel que se le asigna.
    //    Descubrirlo aquí cuesta una comparación de cadenas; descubrirlo a
    //    mitad de la restauración cuesta la base de datos a medio escribir.
    req.engine.exigir_capacidad(Capacidad::Engine)?;
    req.storage.exigir_capacidad(Capacidad::Storage)?;

    // 2. Un canal por plugin, cada uno dentro del directorio de ejecución de su
    //    dueño: es el único sitio al que ese proceso tiene acceso garantizado.
    let canal_motor = crear_canal(req.engine)?;
    let canal_descarga = crear_canal(req.storage)?;

    // 3 y 4. EL CONSUMIDOR PRIMERO, que aquí es el motor. La razón, medida,
    //    está en el doc-comment de `ejecutar_backup`.
    let escritura = iniciar_restore(req.engine, &canal_motor).await?;
    let descarga = iniciar_get(req.storage, &req.artifact_key, &canal_descarga).await?;

    // 5. Ambos plugins tienen ya su orden; ahora deben aparecer por el socket.
    let fuente = aceptar(&canal_descarga, req.storage.nombre(), OP_GET).await?;
    let mut sumidero = aceptar(&canal_motor, req.engine.nombre(), OP_RESTORE).await?;

    // 6. El núcleo no es más que el tramo de tubería entre los dos sockets.
    //    El sumidero se presta en vez de cederse: hace falta conservarlo para
    //    decidir **cómo** se cierra, que es lo único que distingue un volcado
    //    completo de uno cortado a mitad.
    let opciones = RestoreOptions {
        identity: req.identity,
        expected_ciphertext_sha256: req.expected_ciphertext_sha256,
    };
    let escritos = match sb_crypto::restore(fuente, &mut sumidero, &opciones).await {
        Ok(escritos) => escritos,
        Err(fallo) => {
            // El motor puede tener ya plaintext parcial. Se le corta el canal
            // sin el `shutdown` ordenado y se abandonan ambas transferencias:
            // lo que no puede pasar es que esto devuelva `Ok`.
            escritura.abort();
            descarga.abort();
            drop(sumidero);
            tracing::error!(
                clave = %req.artifact_key,
                error = %fallo,
                "restauración abortada: el motor puede haber recibido datos incompletos"
            );
            return Err(fallo.into());
        }
    };

    // 7. El cierre del lado de escritura es lo que el motor ve como fin de
    //    flujo, y por tanto como «esto está entero». Solo se hace cuando de
    //    verdad lo está.
    sumidero
        .shutdown()
        .await
        .map_err(|fuente| BackupError::Io {
            plugin: req.engine.nombre().to_string(),
            fuente,
        })?;

    // 8. El pipeline ha terminado, pero los plugins no tienen por qué: el motor
    //    aún puede estar cerrando lo suyo. Sin esperar aquí, un restore podría
    //    darse por bueno mientras el motor todavía está a medias.
    esperar_progreso(escritura, req.engine.nombre(), OP_RESTORE).await?;
    esperar_progreso(descarga, req.storage.nombre(), OP_GET).await?;

    tracing::info!(
        clave = %req.artifact_key,
        plaintext = escritos,
        "restauración completada"
    );

    Ok(escritos)
}
