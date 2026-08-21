//! Cifrado age en streaming, encapsulado tras una API estable.
//!
//! El resto del proyecto solo ve [`encrypt_to`], [`decrypt_from`], [`Recipient`]
//! e [`Identity`]: la API de `age` cambia entre versiones menores y este módulo
//! es el único punto que hay que tocar cuando eso ocurra.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{
    FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt, TokioAsyncReadCompatExt,
    TokioAsyncWriteCompatExt,
};

/// Errores del flujo cifrado.
#[derive(Debug, thiserror::Error)]
pub enum AgeError {
    /// La cadena no es una clave pública age válida.
    #[error("clave pública age inválida")]
    RecipientInvalido,
    /// El artefacto no está dirigido a la identidad proporcionada.
    #[error("no se pudo descifrar: el artefacto no está dirigido a esta identidad")]
    IdentidadIncorrecta,
    /// El texto no contiene una clave privada age.
    ///
    /// El mensaje no repite nada de lo que se le pasó **a propósito**: lo que
    /// se estaba leyendo era una clave privada, y un error que la citara la
    /// dejaría escrita en el log de quien se equivocó de fichero.
    #[error(
        "no se encontró ninguna clave privada age: se espera una línea `AGE-SECRET-KEY-1…`, \
         como la que escribe `age-keygen`"
    )]
    IdentidadInvalida,
    /// Fallo de E/S sobre el flujo subyacente.
    #[error("error de E/S en el flujo cifrado: {0}")]
    Io(#[from] std::io::Error),
}

/// Clave pública age (`age1...`) a la que se cifra un artefacto.
#[derive(Clone)]
pub struct Recipient(age::x25519::Recipient);

impl Recipient {
    /// Parsea una clave pública age desde su forma textual `age1...`.
    ///
    /// # Errors
    /// Devuelve `RecipientInvalido` si la cadena no es una clave pública age.
    pub fn parse(s: &str) -> Result<Self, AgeError> {
        s.parse::<age::x25519::Recipient>()
            .map(Self)
            .map_err(|_| AgeError::RecipientInvalido)
    }
}

impl std::fmt::Display for Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Clave privada age.
///
/// No implementa `Debug` ni `Display` a propósito, igual que `Secret<T>`: una
/// clave privada no puede acabar en un log por accidente.
pub struct Identity(age::x25519::Identity);

impl Identity {
    /// Genera una identidad nueva a partir del RNG del sistema.
    #[must_use]
    pub fn generate() -> Self {
        Self(age::x25519::Identity::generate())
    }

    /// Deriva la clave pública correspondiente a esta identidad.
    #[must_use]
    pub fn to_recipient(&self) -> Recipient {
        Recipient(self.0.to_public())
    }

    /// Lee una identidad del contenido de un fichero de clave age.
    ///
    /// Acepta el fichero entero tal y como lo escribe `age-keygen` —dos líneas
    /// de comentario y la clave— y no solo la clave suelta: obligar a quien
    /// restaura a recortar el fichero a mano, con la base de datos caída,
    /// sería pedirle justo lo que no puede hacer bien en ese momento. Se queda
    /// con la **primera** clave que encuentre, que es la única que hay en un
    /// fichero generado así.
    ///
    /// # Errors
    /// Devuelve [`AgeError::IdentidadInvalida`] si no hay ninguna línea que sea
    /// una clave privada age. El error no cita nada del texto recibido.
    pub fn parse(texto: &str) -> Result<Self, AgeError> {
        texto
            .lines()
            .map(str::trim)
            .filter(|linea| !linea.is_empty() && !linea.starts_with('#'))
            .find_map(|linea| linea.parse::<age::x25519::Identity>().ok())
            .map(Self)
            .ok_or(AgeError::IdentidadInvalida)
    }

    /// La forma textual de la clave privada, envuelta para que no se pueda
    /// imprimir por accidente.
    ///
    /// El envoltorio [`Secret`](crate::Secret) no es decorativo: es lo único
    /// que separa «escribir un fichero de clave» de «dejar la clave en un log».
    /// Quien la necesite de verdad tiene que pedir `expose()` explícitamente.
    #[must_use]
    pub fn to_secret_string(&self) -> crate::Secret<String> {
        crate::Secret::new(
            age::secrecy::ExposeSecret::expose_secret(&self.0.to_string()).to_owned(),
        )
    }
}

/// Envuelve un sumidero para que lo escrito en él salga cifrado a `rec`.
///
/// **Hay que llamar a `shutdown()`** sobre el valor devuelto: age solo cierra
/// el último bloque AEAD al finalizar, y sin eso el artefacto no se puede leer.
///
/// # Errors
/// Devuelve error si el recipient es inválido o si falla la escritura de la cabecera.
pub async fn encrypt_to<W: AsyncWrite + Unpin>(
    sink: W,
    rec: &Recipient,
) -> Result<impl AsyncWrite + Unpin, AgeError> {
    let encryptor = age::Encryptor::with_recipients(std::iter::once(&rec.0 as &dyn age::Recipient))
        .map_err(|_| AgeError::RecipientInvalido)?;
    let writer = encryptor.wrap_async_output(sink.compat_write()).await?;
    Ok(writer.compat_write())
}

/// Envuelve una fuente cifrada para leerla en claro con `id`.
///
/// La integridad se comprueba bloque a bloque durante la lectura: un ciphertext
/// manipulado falla al leer, no al abrir.
///
/// # Errors
/// Devuelve `IdentidadIncorrecta` si el artefacto no está dirigido a `id` o si
/// la cabecera no es un artefacto age legible.
pub async fn decrypt_from<R: AsyncRead + Unpin>(
    source: R,
    id: &Identity,
) -> Result<impl AsyncRead + Unpin, AgeError> {
    let decryptor = age::Decryptor::new_async(source.compat())
        .await
        .map_err(|_| AgeError::IdentidadIncorrecta)?;
    let reader = decryptor
        .decrypt_async(std::iter::once(&id.0 as &dyn age::Identity))
        .map_err(|_| AgeError::IdentidadIncorrecta)?;
    Ok(reader.compat())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn par_de_claves() -> (Recipient, Identity) {
        let id = Identity::generate();
        let rec = id.to_recipient();
        (rec, id)
    }

    async fn cifrar(datos: &[u8], rec: &Recipient) -> Vec<u8> {
        let mut sink = Vec::new();
        {
            let mut w = encrypt_to(&mut sink, rec).await.unwrap();
            w.write_all(datos).await.unwrap();
            w.shutdown().await.unwrap();
        }
        sink
    }

    async fn descifrar(datos: &[u8], id: &Identity) -> Vec<u8> {
        let mut r = decrypt_from(datos, id).await.unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn ida_y_vuelta() {
        let (rec, id) = par_de_claves();
        let datos = b"datos sensibles";
        let cifrado = cifrar(datos, &rec).await;
        assert_ne!(
            &cifrado[..],
            &datos[..],
            "el ciphertext no puede ser el plaintext"
        );
        assert_eq!(descifrar(&cifrado, &id).await, datos);
    }

    #[tokio::test]
    async fn ida_y_vuelta_con_cero_bytes() {
        // Mismo peligro que en zstd: sin shutdown() no se cierra el último
        // bloque AEAD y el descifrado falla con un error confuso.
        let (rec, id) = par_de_claves();
        let cifrado = cifrar(b"", &rec).await;
        assert!(!cifrado.is_empty(), "age siempre emite cabecera");
        assert_eq!(descifrar(&cifrado, &id).await, b"");
    }

    #[tokio::test]
    async fn ida_y_vuelta_con_volumen() {
        // Fuerza que age emita varios bloques AEAD, no solo uno.
        let (rec, id) = par_de_claves();
        let datos: Vec<u8> = (0..300_000_u32).map(|i| (i % 251) as u8).collect();
        let cifrado = cifrar(&datos, &rec).await;
        assert_eq!(descifrar(&cifrado, &id).await, datos);
    }

    #[tokio::test]
    async fn una_identidad_ajena_no_puede_descifrar() {
        let (rec, _id) = par_de_claves();
        let (_, otra) = par_de_claves();
        let cifrado = cifrar(b"secreto", &rec).await;
        assert!(decrypt_from(&cifrado[..], &otra).await.is_err());
    }

    #[tokio::test]
    async fn un_ciphertext_manipulado_falla_al_leer() {
        let (rec, id) = par_de_claves();
        let mut cifrado = cifrar(&vec![9_u8; 100_000], &rec).await;
        let ultimo = cifrado.len() - 1;
        cifrado[ultimo] ^= 0xff;

        let mut r = decrypt_from(&cifrado[..], &id).await.unwrap();
        let mut out = Vec::new();
        // AEAD: la manipulación se detecta al leer, no al abrir.
        assert!(r.read_to_end(&mut out).await.is_err());
    }

    #[tokio::test]
    async fn un_ciphertext_truncado_falla() {
        let (rec, id) = par_de_claves();
        let mut cifrado = cifrar(&vec![4_u8; 200_000], &rec).await;
        cifrado.truncate(cifrado.len() / 2);

        let resultado = async {
            let mut r = decrypt_from(&cifrado[..], &id).await?;
            let mut out = Vec::new();
            r.read_to_end(&mut out).await?;
            Ok::<_, Box<dyn std::error::Error>>(out)
        }
        .await;
        assert!(
            resultado.is_err(),
            "un artefacto truncado nunca debe leerse como válido"
        );
    }

    #[test]
    fn un_recipient_se_parsea_desde_su_forma_textual() {
        let (rec, _) = par_de_claves();
        let texto = rec.to_string();
        assert!(texto.starts_with("age1"));
        assert_eq!(Recipient::parse(&texto).unwrap().to_string(), texto);
    }

    #[test]
    fn un_recipient_invalido_se_rechaza() {
        assert!(Recipient::parse("esto-no-es-un-recipient").is_err());
        assert!(Recipient::parse("").is_err());
    }

    #[test]
    fn una_identidad_da_la_vuelta_por_su_forma_textual() {
        let id = Identity::generate();
        let publica = id.to_recipient().to_string();
        let texto = id.to_secret_string();
        assert!(texto.expose().starts_with("AGE-SECRET-KEY-1"));

        let leida = Identity::parse(texto.expose()).unwrap();
        assert_eq!(
            leida.to_recipient().to_string(),
            publica,
            "la identidad leída debe ser la misma que se escribió"
        );
    }

    #[test]
    fn un_fichero_de_clave_con_comentarios_se_lee_igual() {
        // Es exactamente lo que escribe `age-keygen`: dos líneas de comentario
        // con la fecha y la clave pública, y luego la clave.
        let id = Identity::generate();
        let fichero = format!(
            "# created: 2026-08-21T10:00:00Z\n# public key: {}\n{}\n",
            id.to_recipient(),
            id.to_secret_string().expose()
        );
        assert_eq!(
            Identity::parse(&fichero)
                .unwrap()
                .to_recipient()
                .to_string(),
            id.to_recipient().to_string()
        );
    }

    #[test]
    fn una_identidad_invalida_se_rechaza_sin_delatar_su_contenido() {
        for malo in ["", "# solo comentarios\n", "AGE-SECRET-KEY-1NOESVALIDA"] {
            // `unwrap_err` exigiría `Debug` en `Identity`, que no lo tiene a
            // propósito. `err()` no exige nada del lado correcto.
            let error = Identity::parse(malo).err().unwrap();
            assert!(matches!(error, AgeError::IdentidadInvalida));
            assert!(
                !error.to_string().contains("AGE-SECRET-KEY-1NOESVALIDA"),
                "el error no puede repetir lo que se le dio: era una clave privada"
            );
        }
    }

    #[test]
    fn una_clave_publica_no_cuela_como_identidad() {
        // El error de teclado más probable: pasar el `.pub` en vez de la clave.
        let id = Identity::generate();
        assert!(Identity::parse(&id.to_recipient().to_string()).is_err());
    }
}
