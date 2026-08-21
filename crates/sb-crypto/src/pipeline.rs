//! Composición de las tres capas: `zstd → age → SHA-256`.

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    AgeError, CompressionLevel, Digest, Identity, Recipient, Sha256Reader, Sha256Writer,
    compressor, decompressor, decrypt_from, encrypt_to,
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

pub struct RestoreOptions<'a> {
    pub identity: &'a Identity,
    /// Si se aporta, se comprueba contra el digest del artefacto leído y el
    /// restore falla si no coincide.
    pub expected_ciphertext_sha256: Option<Digest>,
}

/// Lee un artefacto de `source`, descifra, descomprime y escribe en `sink`.
///
/// # Integridad, y por qué hacen falta dos comprobaciones
///
/// El AEAD de age verifica cada bloque durante la lectura, así que un
/// ciphertext manipulado falla al leer. La comprobación adicional del digest
/// detecta algo distinto: que el destino haya servido un artefacto **diferente**
/// del que registró el manifiesto.
///
/// El digest solo se puede comprobar **después** de leer todo el flujo, porque
/// hasta entonces no está completo. Para entonces `sink` ya ha recibido datos.
///
/// # Advertencia para quien consuma esta función
///
/// age entrega los bloques AEAD ya verificados de forma incremental. Ante un
/// artefacto truncado, la lectura falla **después** de haber escrito en `sink`
/// todo lo que venía antes del corte — plaintext legítimo, pero parcial.
///
/// Por tanto: **si esta función devuelve `Err`, hay que descartar todo lo
/// escrito en `sink`, no solo dejar de escribir.** Quedarse con lo que llegó
/// antes del fallo significa quedarse con media base de datos sin ninguna
/// señal de que lo es.
///
/// # Errors
/// Devuelve error si el artefacto no está dirigido a `identity`, si está
/// corrupto o truncado, o si el digest no coincide con el esperado.
pub async fn restore<R, W>(
    source: R,
    sink: W,
    opts: &RestoreOptions<'_>,
) -> Result<u64, PipelineError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut fuente = Sha256Reader::new(source);
    let mut sink = sink;

    let escritos = {
        let descifrador = decrypt_from(&mut fuente, opts.identity).await?;
        let mut descompresor = decompressor(descifrador);
        tokio::io::copy(&mut descompresor, &mut sink).await?
    };
    sink.flush().await?;

    if let Some(esperado) = opts.expected_ciphertext_sha256 {
        let obtenido = fuente.digest();
        if obtenido != esperado {
            return Err(PipelineError::DigestNoCoincide {
                esperado: esperado.to_hex(),
                obtenido: obtenido.to_hex(),
            });
        }
    }

    Ok(escritos)
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
        // La entrada es deliberadamente grande y sólo parcialmente comprimible.
        // Una versión anterior de este test usaba 90 KB de texto repetido y era
        // intermitente: el artefacto quedaba en 300-400 bytes, donde la varianza
        // del framing de zstd domina sobre la diferencia real entre niveles y la
        // comparación se convertía en una moneda al aire. Con varios megabytes
        // de contenido tipo dump, la diferencia entre nivel 1 y 19 es de órdenes
        // muy superiores a ese ruido.
        let id = Identity::generate();
        let datos = datos_tipo_dump(4 * 1024 * 1024);

        let comprimir_con = |nivel: i32| {
            let datos = &datos;
            let rec = id.to_recipient();
            async move {
                let mut salida = Vec::new();
                backup(
                    &datos[..],
                    &mut salida,
                    &BackupOptions {
                        recipient: rec,
                        level: CompressionLevel::new(nivel).unwrap(),
                    },
                )
                .await
                .unwrap();
                salida.len()
            }
        };

        let bajo = comprimir_con(1).await;
        let alto = comprimir_con(19).await;

        assert!(
            alto < bajo,
            "el nivel no está llegando a zstd: nivel 1 dio {bajo} bytes y nivel 19 dio {alto}"
        );
    }

    /// Contenido parecido a un dump de base de datos: vocabulario acotado y muy
    /// repetitivo, pero con suficiente variación para que el nivel de
    /// compresión cambie el resultado de forma medible.
    fn datos_tipo_dump(bytes: usize) -> Vec<u8> {
        let mut salida = Vec::with_capacity(bytes + 128);
        let mut x: u32 = 0x1234_5678;
        while salida.len() < bytes {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let n = x % 10_000;
            salida.extend_from_slice(
                format!("INSERT INTO clientes VALUES ({n}, 'cliente-{n}', '2026-08-21');\n")
                    .as_bytes(),
            );
        }
        salida.truncate(bytes);
        salida
    }

    #[tokio::test]
    async fn ida_y_vuelta_completa() {
        let id = Identity::generate();
        let datos = b"cualquier contenido de base de datos ".repeat(2000);

        let mut artefacto = Vec::new();
        let resumen = backup(
            &datos[..],
            &mut artefacto,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        let mut restaurado = Vec::new();
        restore(
            &artefacto[..],
            &mut restaurado,
            &RestoreOptions {
                identity: &id,
                expected_ciphertext_sha256: Some(resumen.ciphertext_sha256),
            },
        )
        .await
        .unwrap();

        assert_eq!(restaurado, datos);
    }

    #[tokio::test]
    async fn ida_y_vuelta_de_entrada_vacia() {
        // El caso que revela un cierre de capa omitido: un artefacto truncado
        // tiene forma correcta pero no restaura.
        let id = Identity::generate();
        let mut artefacto = Vec::new();
        let resumen = backup(
            &b""[..],
            &mut artefacto,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        let mut restaurado = Vec::new();
        let escritos = restore(
            &artefacto[..],
            &mut restaurado,
            &RestoreOptions {
                identity: &id,
                expected_ciphertext_sha256: Some(resumen.ciphertext_sha256),
            },
        )
        .await
        .unwrap();

        assert_eq!(escritos, 0);
        assert!(restaurado.is_empty());
    }

    #[tokio::test]
    async fn ida_y_vuelta_con_volumen_y_varios_niveles() {
        // Fuerza varios bloques AEAD y varios frames zstd.
        let id = Identity::generate();
        let datos: Vec<u8> = (0..400_000_u32).map(|i| (i % 251) as u8).collect();

        for nivel in [1_i32, 3, 19] {
            let mut artefacto = Vec::new();
            let resumen = backup(
                &datos[..],
                &mut artefacto,
                &BackupOptions {
                    recipient: id.to_recipient(),
                    level: CompressionLevel::new(nivel).unwrap(),
                },
            )
            .await
            .unwrap();

            let mut restaurado = Vec::new();
            restore(
                &artefacto[..],
                &mut restaurado,
                &RestoreOptions {
                    identity: &id,
                    expected_ciphertext_sha256: Some(resumen.ciphertext_sha256),
                },
            )
            .await
            .unwrap();

            assert_eq!(restaurado, datos, "falló con nivel {nivel}");
        }
    }

    #[tokio::test]
    async fn un_digest_que_no_coincide_aborta_el_restore() {
        let id = Identity::generate();
        let mut artefacto = Vec::new();
        backup(
            &b"datos"[..],
            &mut artefacto,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        let falso =
            Digest::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();

        let mut restaurado = Vec::new();
        let err = restore(
            &artefacto[..],
            &mut restaurado,
            &RestoreOptions {
                identity: &id,
                expected_ciphertext_sha256: Some(falso),
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(err, PipelineError::DigestNoCoincide { .. }));
    }

    #[tokio::test]
    async fn un_artefacto_truncado_falla() {
        let id = Identity::generate();
        let mut artefacto = Vec::new();
        backup(
            &vec![3_u8; 200_000][..],
            &mut artefacto,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        artefacto.truncate(artefacto.len() / 2);

        let mut restaurado = Vec::new();
        assert!(
            restore(
                &artefacto[..],
                &mut restaurado,
                &RestoreOptions {
                    identity: &id,
                    expected_ciphertext_sha256: None,
                }
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn una_identidad_ajena_no_puede_restaurar() {
        let id = Identity::generate();
        let intrusa = Identity::generate();
        let mut artefacto = Vec::new();
        backup(
            &b"secreto"[..],
            &mut artefacto,
            &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            },
        )
        .await
        .unwrap();

        let mut restaurado = Vec::new();
        assert!(
            restore(
                &artefacto[..],
                &mut restaurado,
                &RestoreOptions {
                    identity: &intrusa,
                    expected_ciphertext_sha256: None,
                }
            )
            .await
            .is_err()
        );
    }
}
