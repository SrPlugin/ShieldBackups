//! Composición de las tres capas: `zstd → age → SHA-256`.

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    AgeError, CompressionLevel, Digest, Recipient, Sha256Reader, Sha256Writer, compressor,
    encrypt_to,
};

#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Age(#[from] AgeError),
    #[error("el digest no coincide: esperado {esperado}, obtenido {obtenido}")]
    DigestNoCoincide { esperado: String, obtenido: String },
}

pub struct BackupOptions {
    pub recipient: Recipient,
    pub level: CompressionLevel,
}

/// Lo que hay que guardar en el manifiesto para poder verificar y restaurar.
#[derive(Debug, Clone, Copy)]
pub struct BackupSummary {
    pub plaintext_bytes: u64,
    pub ciphertext_bytes: u64,
    pub plaintext_sha256: Digest,
    pub ciphertext_sha256: Digest,
}

/// Lee de `source`, comprime, cifra, hashea y escribe en `sink`.
///
/// La memoria usada es constante e independiente del tamaño de la entrada.
///
/// El orden de las capas es `zstd → age → SHA-256`: se hashea el texto
/// cifrado, de modo que un artefacto se puede verificar en el destino sin
/// disponer de la clave privada.
///
/// El orden de **cierre** es igual de importante y es la razón del bloque
/// anidado: zstd debe emitir su frame final dentro de la capa age, y age debe
/// cerrar su último bloque AEAD antes de que se cuente el último byte
/// hasheado. Invertirlo produce un artefacto truncado cuyo fallo no aparece
/// hasta el restore.
///
/// # Errors
/// Devuelve error si falla la lectura, el cifrado o la escritura.
pub async fn backup<R, W>(
    source: R,
    sink: W,
    opts: &BackupOptions,
) -> Result<BackupSummary, PipelineError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut fuente = Sha256Reader::new(source);
    let mut hasher = Sha256Writer::new(sink);

    let plaintext_bytes = {
        let cifrador = encrypt_to(&mut hasher, &opts.recipient).await?;
        let mut compresor = compressor(cifrador, opts.level);

        let copiados = tokio::io::copy(&mut fuente, &mut compresor).await?;

        // Cierre en orden: primero zstd (emite su frame final dentro de age),
        // después age (cierra el bloque AEAD y escribe al hasher).
        compresor.shutdown().await?;
        let mut cifrador = compresor.into_inner();
        cifrador.shutdown().await?;

        copiados
    };

    hasher.shutdown().await?;
    let (_, ciphertext_sha256, ciphertext_bytes) = hasher.into_parts();

    Ok(BackupSummary {
        plaintext_bytes,
        ciphertext_bytes,
        plaintext_sha256: fuente.digest(),
        ciphertext_sha256,
    })
}

#[cfg(test)]
// Los `use` locales dentro de los tests son deliberados: acotan el trait de
// extensión al bloque que lo necesita.
#[allow(clippy::items_after_statements)]
mod tests {
    use super::*;
    use crate::{CompressionLevel, Identity, Sha256Writer};

    #[tokio::test]
    async fn produce_ambos_digests_y_los_tamanos() {
        let id = Identity::generate();
        let datos = b"contenido ".repeat(1000);
        let mut destino = Vec::new();

        let resumen = backup(
            &datos[..],
            &mut destino,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        assert_eq!(resumen.plaintext_bytes, datos.len() as u64);
        assert_eq!(resumen.ciphertext_bytes, destino.len() as u64);
        assert_ne!(resumen.plaintext_sha256, resumen.ciphertext_sha256);

        // El digest del ciphertext debe corresponder a lo que se escribió de verdad.
        use tokio::io::AsyncWriteExt;
        let mut w = Sha256Writer::new(Vec::new());
        w.write_all(&destino).await.unwrap();
        w.shutdown().await.unwrap();
        assert_eq!(w.into_parts().1, resumen.ciphertext_sha256);
    }

    #[tokio::test]
    async fn el_digest_del_plaintext_es_el_de_la_entrada() {
        // Sin esto, `plaintext_sha256` podría ser cualquier cosa y nadie se
        // enteraría: es el único dato del manifiesto que no se puede
        // recalcular desde el artefacto sin la clave privada.
        let id = Identity::generate();
        let datos = b"entrada conocida".repeat(100);

        let mut esperado = Sha256Writer::new(Vec::new());
        {
            use tokio::io::AsyncWriteExt;
            esperado.write_all(&datos).await.unwrap();
            esperado.shutdown().await.unwrap();
        }
        let digest_esperado = esperado.into_parts().1;

        let mut destino = Vec::new();
        let resumen = backup(
            &datos[..],
            &mut destino,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        assert_eq!(resumen.plaintext_sha256, digest_esperado);
    }

    #[tokio::test]
    async fn el_artefacto_esta_comprimido_y_cifrado() {
        let id = Identity::generate();
        let datos = vec![0_u8; 500_000];
        let mut destino = Vec::new();

        backup(
            &datos[..],
            &mut destino,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        assert!(
            destino.len() < 10_000,
            "500 KB de ceros deben comprimirse muchísimo"
        );
        assert!(
            !destino.windows(4).any(|w| w == [0, 0, 0, 0]),
            "un artefacto cifrado no debe tener rachas largas de ceros"
        );
    }

    #[tokio::test]
    async fn funciona_con_entrada_vacia() {
        let id = Identity::generate();
        let mut destino = Vec::new();

        let resumen = backup(
            &b""[..],
            &mut destino,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        assert_eq!(resumen.plaintext_bytes, 0);
        assert!(
            !destino.is_empty(),
            "debe emitirse cabecera age y frame zstd"
        );
    }

    #[tokio::test]
    async fn dos_backups_del_mismo_contenido_dan_el_mismo_digest_de_plaintext() {
        // El ciphertext difiere entre ejecuciones (age usa una clave de fichero
        // aleatoria), pero el digest del plano no puede depender de eso.
        let id = Identity::generate();
        let datos = b"contenido estable".repeat(50);

        let mut d1 = Vec::new();
        let r1 = backup(
            &datos[..],
            &mut d1,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        let mut d2 = Vec::new();
        let r2 = backup(
            &datos[..],
            &mut d2,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        assert_eq!(r1.plaintext_sha256, r2.plaintext_sha256);
        assert_ne!(r1.ciphertext_sha256, r2.ciphertext_sha256);
    }

    #[tokio::test]
    async fn el_nivel_de_compresion_llega_a_la_capa_zstd() {
        let id = Identity::generate();
        let datos = b"texto con estructura repetida ".repeat(3000);

        let mut bajo = Vec::new();
        backup(
            &datos[..],
            &mut bajo,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::new(1).unwrap(),
            },
        )
        .await
        .unwrap();

        let mut alto = Vec::new();
        backup(
            &datos[..],
            &mut alto,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::new(19).unwrap(),
            },
        )
        .await
        .unwrap();

        assert!(
            alto.len() <= bajo.len(),
            "el nivel debe estar llegando de verdad a zstd"
        );
    }
}
