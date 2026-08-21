use std::fmt::Write as _;
use std::pin::Pin;
use std::task::{Context, Poll};

use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
    /// Trabaja sobre los **bytes** de `s` y no sobre sus caracteres. La
    /// diferencia importa: la longitud se mide en bytes, así que una cadena de
    /// 21 signos de euro y una letra ocupa exactamente 64 bytes sin ser hex, y
    /// trocearla en pares de bytes con `&s[i*2..i*2+2]` caería en mitad de un
    /// carácter multibyte y entraría en pánico. Este parser lee cadenas que
    /// vienen de un manifiesto descargado del destino, así que esa entrada es
    /// perfectamente alcanzable.
    ///
    /// # Errors
    ///
    /// Devuelve [`DigestParseError`] si `s` no ocupa exactamente 64 bytes o si
    /// alguno de ellos no es un dígito hexadecimal ASCII.
    pub fn from_hex(s: &str) -> Result<Self, DigestParseError> {
        let bytes = s.as_bytes();
        if bytes.len() != 64 {
            return Err(DigestParseError);
        }
        let mut out = [0_u8; 32];
        for (byte, par) in out.iter_mut().zip(bytes.chunks_exact(2)) {
            let alto = valor_hex(par[0])?;
            let bajo = valor_hex(par[1])?;
            *byte = alto * 16 + bajo;
        }
        Ok(Self(out))
    }
}

/// Valor numérico de un dígito hexadecimal ASCII.
///
/// Deliberadamente sobre `u8` y no sobre `char`: es lo que permite recorrer la
/// cadena por bytes sin arriesgarse a cortar un carácter multibyte por la
/// mitad. Cualquier byte que no sea `0-9`, `a-f` o `A-F` —incluido el primer
/// byte de una secuencia UTF-8 más larga— es un error, no un pánico.
fn valor_hex(b: u8) -> Result<u8, DigestParseError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(DigestParseError),
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

/// Adaptador que hashea los bytes según se leen de la fuente.
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

    /// Digest de todo lo leído hasta ahora. Solo es el digest completo del
    /// flujo si ya se llegó al final.
    #[must_use]
    pub fn digest(&self) -> Digest {
        // Se clona el hasher en vez de consumirlo para poder consultar el
        // digest a mitad de la lectura.
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
        let antes = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                // Solo lo recién llenado en esta llamada, no el buffer entero:
                // el `ReadBuf` puede llegar con contenido de otra capa del
                // pipeline y hashearlo entero corrompería el digest.
                this.hasher.update(&buf.filled()[antes..]);
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

    #[test]
    fn una_cadena_de_64_bytes_con_caracteres_multibyte_se_rechaza() {
        // Regresión: la longitud se mide en bytes, así que 21 signos de euro
        // (3 bytes cada uno) más una letra ocupan exactamente 64 bytes y
        // pasaban la comprobación de longitud. Trocear eso en pares de bytes
        // con `&s[i*2..i*2+2]` cortaba un carácter por la mitad y entraba en
        // pánico. Esta cadena llega dentro del manifiesto que se descarga del
        // destino: es entrada externa, no un caso teórico.
        let s = format!("{}a", "\u{20ac}".repeat(21));
        assert_eq!(s.len(), 64, "la trampa es que mide 64 bytes");
        assert!(Digest::from_hex(&s).is_err());
    }

    #[test]
    fn el_hex_en_mayusculas_tambien_se_acepta() {
        let d = Digest::from_hex(&SHA256_ABC.to_uppercase()).unwrap();
        assert_eq!(d.to_hex(), SHA256_ABC);
    }

    #[tokio::test]
    async fn el_reader_hashea_lo_que_lee() {
        use tokio::io::AsyncReadExt;
        let mut r = Sha256Reader::new(&b"abc"[..]);
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"abc");
        assert_eq!(r.digest().to_hex(), SHA256_ABC);
    }

    #[tokio::test]
    async fn reader_y_writer_producen_el_mismo_digest() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let datos = vec![7_u8; 100_000];

        let mut w = Sha256Writer::new(Vec::new());
        w.write_all(&datos).await.unwrap();
        w.shutdown().await.unwrap();
        let (_, d_write, _) = w.into_parts();

        let mut r = Sha256Reader::new(&datos[..]);
        let mut sink = Vec::new();
        r.read_to_end(&mut sink).await.unwrap();

        assert_eq!(d_write, r.digest());
    }
}
