use async_compression::Level;
use async_compression::tokio::bufread::ZstdDecoder;
use async_compression::tokio::write::ZstdEncoder;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader};

/// A valid zstd compression level (1..=22).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressionLevel(i32);

#[derive(Debug, thiserror::Error)]
#[error("compression level {0} is out of range: it must be between 1 and 22")]
pub struct InvalidLevel(i32);

impl CompressionLevel {
    /// # Errors
    /// Returns `InvalidLevel` if the level falls outside the range 1..=22.
    pub fn new(level: i32) -> Result<Self, InvalidLevel> {
        if (1..=22).contains(&level) {
            Ok(Self(level))
        } else {
            Err(InvalidLevel(level))
        }
    }

    #[must_use]
    pub fn get(self) -> i32 {
        self.0
    }
}

impl Default for CompressionLevel {
    /// Level 3: the point where zstd stops being free but is still fast. Going
    /// higher costs CPU on the database server, which usually matters more than
    /// the megabytes saved.
    fn default() -> Self {
        Self(3)
    }
}

/// Wraps a sink so that whatever is written to it comes out compressed.
///
/// **You must call `shutdown()`** on the returned value so that zstd emits its
/// final frame. Without that the artifact is truncated, and the failure does
/// not surface until someone tries to restore it.
#[must_use]
pub fn compressor<W: AsyncWrite + Unpin>(sink: W, level: CompressionLevel) -> ZstdEncoder<W> {
    ZstdEncoder::with_quality(sink, Level::Precise(level.get()))
}

/// Wraps a compressed source so it reads back decompressed.
#[must_use]
pub fn decompressor<R: AsyncRead + Unpin>(source: R) -> ZstdDecoder<BufReader<R>> {
    ZstdDecoder::new(BufReader::new(source))
}

/// Same as [`decompressor`] but for sources that are already buffered.
#[must_use]
pub fn decompressor_buffered<R: AsyncBufRead + Unpin>(source: R) -> ZstdDecoder<R> {
    ZstdDecoder::new(source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn compress(data: &[u8], level: CompressionLevel) -> Vec<u8> {
        let mut enc = compressor(Vec::new(), level);
        enc.write_all(data).await.unwrap();
        enc.shutdown().await.unwrap();
        enc.into_inner()
    }

    async fn decompress(data: &[u8]) -> Vec<u8> {
        let mut dec = decompressor(data);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn round_trip_with_ordinary_data() {
        let data = b"repeated test content ".repeat(500);
        let compressed = compress(&data, CompressionLevel::default()).await;
        assert_eq!(decompress(&compressed).await, data);
    }

    #[tokio::test]
    async fn round_trip_with_zero_bytes() {
        // This is the case that blows up if shutdown() is forgotten: with no
        // final frame, the decompressor finds nothing to read.
        let compressed = compress(b"", CompressionLevel::default()).await;
        assert!(
            !compressed.is_empty(),
            "zstd must emit a frame even when there is no data"
        );
        assert_eq!(decompress(&compressed).await, b"");
    }

    #[tokio::test]
    async fn repetitive_data_really_gets_compressed() {
        let data = vec![0_u8; 1_000_000];
        let compressed = compress(&data, CompressionLevel::default()).await;
        assert!(
            compressed.len() < data.len() / 100,
            "1 MB of zeros must shrink to almost nothing"
        );
    }

    #[tokio::test]
    async fn a_high_level_compresses_at_least_as_well_as_a_low_one() {
        let data = b"text with some structure and repetition ".repeat(2000);
        let low = compress(&data, CompressionLevel::new(1).unwrap()).await;
        let high = compress(&data, CompressionLevel::new(19).unwrap()).await;
        assert!(
            high.len() <= low.len(),
            "level 19 should not compress worse than level 1"
        );
        // And both must decompress back to the same original.
        assert_eq!(decompress(&low).await, data);
        assert_eq!(decompress(&high).await, data);
    }

    #[test]
    fn the_level_is_validated_on_construction() {
        assert!(CompressionLevel::new(3).is_ok());
        assert!(CompressionLevel::new(1).is_ok());
        assert!(CompressionLevel::new(22).is_ok());
        assert!(CompressionLevel::new(0).is_err());
        assert!(CompressionLevel::new(23).is_err());
        assert!(CompressionLevel::new(-5).is_err());
    }

    #[test]
    fn the_default_level_is_valid_and_moderate() {
        let d = CompressionLevel::default();
        assert!(CompressionLevel::new(d.get()).is_ok());
        assert!(
            (1..=9).contains(&d.get()),
            "the default must be fast, not maximal"
        );
    }
}
