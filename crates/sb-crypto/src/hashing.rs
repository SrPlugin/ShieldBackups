use std::fmt::Write as _;
use std::pin::Pin;
use std::task::{Context, Poll};

use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWrite;

/// Digest SHA-256 de 32 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Digest([u8; 32]);

#[derive(Debug, thiserror::Error)]
#[error("digest hexadecimal inválido: se esperaban 64 caracteres hex")]
pub struct DigestParseError;

impl Digest {
    /// Representación hexadecimal en minúsculas, 64 caracteres.
    #[must_use]
    pub fn to_hex(&self) -> String {
        // `fold` + `write!` en vez de `map(format!).collect()`: evita una
        // `String` por byte (clippy::format_collect).
        self.0.iter().fold(String::with_capacity(64), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }

    /// Parsea un digest desde su representación hexadecimal.
    ///
    /// # Errors
    ///
    /// Devuelve [`DigestParseError`] si `s` no tiene exactamente 64
    /// caracteres o si alguno de ellos no es hexadecimal.
    pub fn from_hex(s: &str) -> Result<Self, DigestParseError> {
        if s.len() != 64 {
            return Err(DigestParseError);
        }
        let mut out = [0_u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| DigestParseError)?;
        }
        Ok(Self(out))
    }
}

/// Adaptador que reenvía los bytes al sumidero y los hashea de paso.
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

    /// Consume el adaptador y devuelve el sumidero, el digest y los bytes
    /// escritos. El contador lo necesita el manifiesto para registrar el
    /// tamaño del artefacto sin tener que releerlo.
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
            // Solo se hashea lo que el sumidero aceptó de verdad: hashear `buf`
            // entero cuando solo se escribieron n bytes corrompería el digest.
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// SHA-256 conocido de la cadena vacía.
    const SHA256_VACIO: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// SHA-256 conocido de "abc".
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[tokio::test]
    async fn hashea_la_cadena_vacia() {
        let mut w = Sha256Writer::new(Vec::new());
        w.shutdown().await.unwrap();
        let (sink, digest, bytes) = w.into_parts();
        assert!(sink.is_empty());
        assert_eq!(digest.to_hex(), SHA256_VACIO);
        assert_eq!(bytes, 0);
    }

    #[tokio::test]
    async fn hashea_y_reenvia_los_bytes() {
        let mut w = Sha256Writer::new(Vec::new());
        w.write_all(b"abc").await.unwrap();
        w.shutdown().await.unwrap();
        let (sink, digest, bytes) = w.into_parts();
        assert_eq!(sink, b"abc");
        assert_eq!(digest.to_hex(), SHA256_ABC);
        assert_eq!(
            bytes, 3,
            "el pipeline necesita este contador para el manifiesto"
        );
    }

    #[tokio::test]
    async fn el_hash_no_depende_de_como_se_trocean_las_escrituras() {
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
    async fn cuenta_los_bytes_que_de_verdad_pasaron() {
        let mut w = Sha256Writer::new(Vec::new());
        w.write_all(&vec![0_u8; 100_000]).await.unwrap();
        w.shutdown().await.unwrap();
        assert_eq!(w.into_parts().2, 100_000);
    }

    #[test]
    fn el_digest_se_parsea_desde_hex() {
        let d = Digest::from_hex(SHA256_ABC).unwrap();
        assert_eq!(d.to_hex(), SHA256_ABC);
    }

    #[test]
    fn un_hex_invalido_se_rechaza() {
        assert!(Digest::from_hex("no-es-hex").is_err());
        assert!(Digest::from_hex("ab").is_err()); // longitud incorrecta
    }
}
