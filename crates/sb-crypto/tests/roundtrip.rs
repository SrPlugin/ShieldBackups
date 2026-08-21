//! Los tests que justifican el proyecto.
//!
//! Los tests basados en ejemplos comprueban los casos que a alguien se le
//! ocurrieron. Estos comprueban propiedades sobre entradas arbitrarias, que es
//! donde aparecen los bugs que nadie previó.

use proptest::prelude::*;
use sb_crypto::{BackupOptions, CompressionLevel, Identity, RestoreOptions, backup, restore};

// `expect` no está permitido fuera de funciones `#[test]`, y este ayudante no
// lo es: fallar aquí no es un fallo de la propiedad, sino del entorno.
fn runtime() -> tokio::runtime::Runtime {
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => panic!("no se pudo construir el runtime de tokio: {e}"),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Cualquier secuencia de bytes sobrevive a backup + restore, con
    /// cualquier nivel de compresión.
    #[test]
    fn cualquier_entrada_sobrevive_al_ciclo(
        datos in prop::collection::vec(any::<u8>(), 0..200_000),
        nivel in 1_i32..=9,
    ) {
        runtime().block_on(async {
            let id = Identity::generate();
            let level = CompressionLevel::new(nivel).unwrap();

            let mut artefacto = Vec::new();
            let resumen = backup(&datos[..], &mut artefacto, &BackupOptions {
                recipient: id.to_recipient(),
                level,
            })
            .await
            .unwrap();

            prop_assert_eq!(resumen.plaintext_bytes, datos.len() as u64);
            prop_assert_eq!(resumen.ciphertext_bytes, artefacto.len() as u64);

            let mut restaurado = Vec::new();
            restore(&artefacto[..], &mut restaurado, &RestoreOptions {
                identity: &id,
                expected_ciphertext_sha256: Some(resumen.ciphertext_sha256),
            })
            .await
            .unwrap();

            prop_assert_eq!(restaurado, datos);
            Ok(())
        })?;
    }

    /// Manipular cualquier byte del artefacto hace que el restore falle.
    /// Es la propiedad que convierte "cifrado" en "cifrado autenticado", y la
    /// que impide restaurar en silencio una copia alterada.
    #[test]
    fn manipular_un_byte_siempre_se_detecta(
        datos in prop::collection::vec(any::<u8>(), 1..20_000),
        posicion in any::<prop::sample::Index>(),
        mascara in 1_u8..=255,
    ) {
        runtime().block_on(async {
            let id = Identity::generate();
            let mut artefacto = Vec::new();
            backup(&datos[..], &mut artefacto, &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            })
            .await
            .unwrap();

            let idx = posicion.index(artefacto.len());
            artefacto[idx] ^= mascara;

            let mut restaurado = Vec::new();
            let resultado = restore(&artefacto[..], &mut restaurado, &RestoreOptions {
                identity: &id,
                expected_ciphertext_sha256: None,
            })
            .await;

            prop_assert!(
                resultado.is_err(),
                "un artefacto manipulado en el byte {} nunca debe restaurarse",
                idx
            );
            Ok(())
        })?;
    }

    /// Truncar el artefacto por cualquier punto siempre se detecta.
    /// Cubre la subida interrumpida, que es un fallo mucho más frecuente en
    /// producción que la manipulación deliberada.
    #[test]
    fn truncar_por_cualquier_punto_se_detecta(
        datos in prop::collection::vec(any::<u8>(), 5_000..50_000),
        corte in any::<prop::sample::Index>(),
    ) {
        runtime().block_on(async {
            let id = Identity::generate();
            let mut artefacto = Vec::new();
            backup(&datos[..], &mut artefacto, &BackupOptions {
                recipient: id.to_recipient(),
                level: CompressionLevel::default(),
            })
            .await
            .unwrap();

            // Cualquier corte estricto: desde 0 hasta len-1 bytes conservados.
            // `Index::index(len)` devuelve siempre un valor en `0..len`, así
            // que el corte nunca deja el artefacto intacto.
            let original = artefacto.len();
            let hasta = corte.index(original);
            artefacto.truncate(hasta);

            let mut restaurado = Vec::new();
            let resultado = restore(&artefacto[..], &mut restaurado, &RestoreOptions {
                identity: &id,
                expected_ciphertext_sha256: None,
            })
            .await;

            prop_assert!(
                resultado.is_err(),
                "un artefacto truncado a {} de {} bytes nunca debe restaurarse como válido",
                hasta, original
            );
            Ok(())
        })?;
    }

    /// Ninguna identidad ajena puede leer un artefacto, sea cual sea el contenido.
    #[test]
    fn una_identidad_ajena_nunca_puede_restaurar(
        datos in prop::collection::vec(any::<u8>(), 0..10_000),
    ) {
        runtime().block_on(async {
            let destinataria = Identity::generate();
            let intrusa = Identity::generate();

            let mut artefacto = Vec::new();
            backup(&datos[..], &mut artefacto, &BackupOptions {
                recipient: destinataria.to_recipient(),
                level: CompressionLevel::default(),
            })
            .await
            .unwrap();

            let mut restaurado = Vec::new();
            let resultado = restore(&artefacto[..], &mut restaurado, &RestoreOptions {
                identity: &intrusa,
                expected_ciphertext_sha256: None,
            })
            .await;

            prop_assert!(resultado.is_err(), "una identidad ajena no puede descifrar");
            prop_assert!(restaurado.is_empty(), "y no debe haber escrito nada");
            Ok(())
        })?;
    }
}
