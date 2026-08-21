use async_compression::Level;
use async_compression::tokio::bufread::ZstdDecoder;
use async_compression::tokio::write::ZstdEncoder;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader};

/// Nivel de compresión zstd válido (1..=22).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressionLevel(i32);

#[derive(Debug, thiserror::Error)]
#[error("nivel de compresión {0} fuera de rango: debe estar entre 1 y 22")]
pub struct InvalidLevel(i32);

impl CompressionLevel {
    /// # Errors
    /// Devuelve `InvalidLevel` si el nivel está fuera del rango 1..=22.
    pub fn new(nivel: i32) -> Result<Self, InvalidLevel> {
        if (1..=22).contains(&nivel) {
            Ok(Self(nivel))
        } else {
            Err(InvalidLevel(nivel))
        }
    }

    #[must_use]
    pub fn get(self) -> i32 {
        self.0
    }
}

impl Default for CompressionLevel {
    /// Nivel 3: el punto donde zstd deja de ser gratis pero todavía es rápido.
    /// Subirlo cuesta CPU en el servidor de base de datos, que suele importar
    /// más que los megabytes ahorrados.
    fn default() -> Self {
        Self(3)
    }
}

/// Envuelve un sumidero para que lo escrito en él salga comprimido.
///
/// **Hay que llamar a `shutdown()`** sobre el valor devuelto para que se emita
/// el frame final de zstd. Sin eso el artefacto queda truncado, y el fallo no
/// aparece hasta que alguien intenta restaurarlo.
#[must_use]
pub fn compressor<W: AsyncWrite + Unpin>(sink: W, nivel: CompressionLevel) -> ZstdEncoder<W> {
    ZstdEncoder::with_quality(sink, Level::Precise(nivel.get()))
}

/// Envuelve una fuente comprimida para leerla descomprimida.
#[must_use]
pub fn decompressor<R: AsyncRead + Unpin>(source: R) -> ZstdDecoder<BufReader<R>> {
    ZstdDecoder::new(BufReader::new(source))
}

/// Igual que [`decompressor`] pero para fuentes que ya están bufferizadas.
#[must_use]
pub fn decompressor_buffered<R: AsyncBufRead + Unpin>(source: R) -> ZstdDecoder<R> {
    ZstdDecoder::new(source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn comprimir(datos: &[u8], nivel: CompressionLevel) -> Vec<u8> {
        let mut enc = compressor(Vec::new(), nivel);
        enc.write_all(datos).await.unwrap();
        enc.shutdown().await.unwrap();
        enc.into_inner()
    }

    async fn descomprimir(datos: &[u8]) -> Vec<u8> {
        let mut dec = decompressor(datos);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn ida_y_vuelta_con_datos_normales() {
        let datos = b"contenido de prueba repetido ".repeat(500);
        let comprimido = comprimir(&datos, CompressionLevel::default()).await;
        assert_eq!(descomprimir(&comprimido).await, datos);
    }

    #[tokio::test]
    async fn ida_y_vuelta_con_cero_bytes() {
        // Este es el caso que revienta si se olvida el shutdown(): sin frame
        // final, el descompresor no encuentra nada que leer.
        let comprimido = comprimir(b"", CompressionLevel::default()).await;
        assert!(
            !comprimido.is_empty(),
            "zstd debe emitir un frame aunque no haya datos"
        );
        assert_eq!(descomprimir(&comprimido).await, b"");
    }

    #[tokio::test]
    async fn datos_repetitivos_se_comprimen_de_verdad() {
        let datos = vec![0_u8; 1_000_000];
        let comprimido = comprimir(&datos, CompressionLevel::default()).await;
        assert!(
            comprimido.len() < datos.len() / 100,
            "1 MB de ceros debe quedar en muy poco"
        );
    }

    #[tokio::test]
    async fn un_nivel_alto_comprime_al_menos_tanto_como_uno_bajo() {
        let datos = b"texto con algo de estructura y repeticion ".repeat(2000);
        let bajo = comprimir(&datos, CompressionLevel::new(1).unwrap()).await;
        let alto = comprimir(&datos, CompressionLevel::new(19).unwrap()).await;
        assert!(
            alto.len() <= bajo.len(),
            "nivel 19 no debería comprimir peor que nivel 1"
        );
        // Y ambos deben descomprimirse al mismo original.
        assert_eq!(descomprimir(&bajo).await, datos);
        assert_eq!(descomprimir(&alto).await, datos);
    }

    #[test]
    fn el_nivel_se_valida_al_construirlo() {
        assert!(CompressionLevel::new(3).is_ok());
        assert!(CompressionLevel::new(1).is_ok());
        assert!(CompressionLevel::new(22).is_ok());
        assert!(CompressionLevel::new(0).is_err());
        assert!(CompressionLevel::new(23).is_err());
        assert!(CompressionLevel::new(-5).is_err());
    }

    #[test]
    fn el_nivel_por_defecto_es_valido_y_moderado() {
        let d = CompressionLevel::default();
        assert!(CompressionLevel::new(d.get()).is_ok());
        assert!(
            (1..=9).contains(&d.get()),
            "el defecto debe ser rápido, no máximo"
        );
    }
}
