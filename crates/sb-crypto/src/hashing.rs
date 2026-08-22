use std::fmt::Write as _;
use std::pin::Pin;
use std::task::{Context, Poll};

use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A 32-byte SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Digest([u8; 32]);

#[derive(Debug, thiserror::Error)]
#[error("invalid hexadecimal digest: 64 hex characters were expected")]
pub struct DigestParseError;

impl Digest {
    /// Lowercase hexadecimal representation, 64 characters long.
    #[must_use]
    pub fn to_hex(&self) -> String {
        // `fold` + `write!` instead of `map(format!).collect()`: it avoids one
        // `String` per byte (clippy::format_collect).
        self.0.iter().fold(String::with_capacity(64), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }

    /// Parses a digest from its hexadecimal representation.
    ///
    /// It works on the **bytes** of `s`, not on its characters. The difference
    /// matters: the length is measured in bytes, so a string of 21 euro signs
    /// plus one letter occupies exactly 64 bytes without being hex, and slicing
    /// it into byte pairs with `&s[i*2..i*2+2]` would land in the middle of a
    /// multibyte character and panic. This parser reads strings that come from
    /// a manifest downloaded from the target, so that input is perfectly
    /// reachable.
    ///
    /// # Errors
    ///
    /// Returns [`DigestParseError`] if `s` does not occupy exactly 64 bytes, or
    /// if any of them is not an ASCII hexadecimal digit.
    pub fn from_hex(s: &str) -> Result<Self, DigestParseError> {
        let bytes = s.as_bytes();
        if bytes.len() != 64 {
            return Err(DigestParseError);
        }
        let mut out = [0_u8; 32];
        for (byte, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
            let high = hex_value(pair[0])?;
            let low = hex_value(pair[1])?;
            *byte = high * 16 + low;
        }
        Ok(Self(out))
    }
}

/// Numeric value of an ASCII hexadecimal digit.
///
/// Deliberately over `u8` and not over `char`: that is what lets us walk the
/// string byte by byte without risking cutting a multibyte character in half.
/// Any byte that is not `0-9`, `a-f` or `A-F` — including the leading byte of a
/// longer UTF-8 sequence — is an error, not a panic.
fn hex_value(b: u8) -> Result<u8, DigestParseError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(DigestParseError),
    }
}

/// Adapter that forwards bytes to the sink and hashes them on the way through.
pub struct Sha256Writer<W> {
    inner: W,
    hasher: Sha256,
    bytes: u64,
}

impl<W> Sha256Writer<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes: 0,
        }
    }

    /// Consumes the adapter and returns the sink, the digest and the number of
    /// bytes written. The manifest needs that counter to record the size of the
    /// artifact without having to read it back.
    #[must_use]
    pub fn into_parts(self) -> (W, Digest, u64) {
        let mut out = [0_u8; 32];
        out.copy_from_slice(&self.hasher.finalize());
        (self.inner, Digest(out), self.bytes)
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Sha256Writer<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            // Only what the sink actually accepted gets hashed: hashing the
            // whole `buf` when only n bytes were written would corrupt the
            // digest.
            Poll::Ready(Ok(n)) => {
                this.hasher.update(&buf[..n]);
                this.bytes += u64::try_from(n).unwrap_or(u64::MAX);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Adapter that hashes bytes as they are read from the source.
pub struct Sha256Reader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R> Sha256Reader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    /// Digest of everything read so far. It is only the digest of the whole
    /// stream once the end has been reached.
    #[must_use]
    pub fn digest(&self) -> Digest {
        // The hasher is cloned rather than consumed so the digest can be
        // queried in the middle of a read.
        let mut out = [0_u8; 32];
        out.copy_from_slice(&self.hasher.clone().finalize());
        Digest(out)
    }

    #[must_use]
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Sha256Reader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                // Only what was just filled in on this call, not the whole
                // buffer: the `ReadBuf` may arrive carrying content from
                // another layer of the pipeline, and hashing all of it would
                // corrupt the digest.
                this.hasher.update(&buf.filled()[before..]);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Known SHA-256 of the empty string.
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// Known SHA-256 of "abc".
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[tokio::test]
    async fn hashes_the_empty_string() {
        let mut w = Sha256Writer::new(Vec::new());
        w.shutdown().await.unwrap();
        let (sink, digest, bytes) = w.into_parts();
        assert!(sink.is_empty());
        assert_eq!(digest.to_hex(), SHA256_EMPTY);
        assert_eq!(bytes, 0);
    }

    #[tokio::test]
    async fn hashes_and_forwards_the_bytes() {
        let mut w = Sha256Writer::new(Vec::new());
        w.write_all(b"abc").await.unwrap();
        w.shutdown().await.unwrap();
        let (sink, digest, bytes) = w.into_parts();
        assert_eq!(sink, b"abc");
        assert_eq!(digest.to_hex(), SHA256_ABC);
        assert_eq!(bytes, 3, "the pipeline needs this counter for the manifest");
    }

    #[tokio::test]
    async fn the_hash_does_not_depend_on_how_the_writes_are_chunked() {
        let mut a = Sha256Writer::new(Vec::new());
        a.write_all(b"abc").await.unwrap();
        a.shutdown().await.unwrap();

        let mut b = Sha256Writer::new(Vec::new());
        b.write_all(b"a").await.unwrap();
        b.write_all(b"b").await.unwrap();
        b.write_all(b"c").await.unwrap();
        b.shutdown().await.unwrap();

        assert_eq!(a.into_parts().1, b.into_parts().1);
    }

    #[tokio::test]
    async fn counts_the_bytes_that_actually_went_through() {
        let mut w = Sha256Writer::new(Vec::new());
        w.write_all(&vec![0_u8; 100_000]).await.unwrap();
        w.shutdown().await.unwrap();
        assert_eq!(w.into_parts().2, 100_000);
    }

    #[test]
    fn the_digest_parses_from_hex() {
        let d = Digest::from_hex(SHA256_ABC).unwrap();
        assert_eq!(d.to_hex(), SHA256_ABC);
    }

    #[test]
    fn invalid_hex_is_rejected() {
        assert!(Digest::from_hex("not-hex").is_err());
        assert!(Digest::from_hex("ab").is_err()); // wrong length
    }

    #[test]
    fn a_64_byte_string_with_multibyte_characters_is_rejected() {
        // Regression: the length is measured in bytes, so 21 euro signs (3
        // bytes each) plus one letter occupy exactly 64 bytes and used to pass
        // the length check. Slicing that into byte pairs with
        // `&s[i*2..i*2+2]` cut a character in half and panicked. This string
        // arrives inside the manifest downloaded from the target: it is
        // external input, not a theoretical case.
        let s = format!("{}a", "\u{20ac}".repeat(21));
        assert_eq!(s.len(), 64, "the trap is that it measures 64 bytes");
        assert!(Digest::from_hex(&s).is_err());
    }

    #[test]
    fn uppercase_hex_is_accepted_too() {
        let d = Digest::from_hex(&SHA256_ABC.to_uppercase()).unwrap();
        assert_eq!(d.to_hex(), SHA256_ABC);
    }

    #[tokio::test]
    async fn the_reader_hashes_what_it_reads() {
        use tokio::io::AsyncReadExt;
        let mut r = Sha256Reader::new(&b"abc"[..]);
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"abc");
        assert_eq!(r.digest().to_hex(), SHA256_ABC);
    }

    #[tokio::test]
    async fn reader_and_writer_produce_the_same_digest() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let data = vec![7_u8; 100_000];

        let mut w = Sha256Writer::new(Vec::new());
        w.write_all(&data).await.unwrap();
        w.shutdown().await.unwrap();
        let (_, d_write, _) = w.into_parts();

        let mut r = Sha256Reader::new(&data[..]);
        let mut sink = Vec::new();
        r.read_to_end(&mut sink).await.unwrap();

        assert_eq!(d_write, r.digest());
    }
}
