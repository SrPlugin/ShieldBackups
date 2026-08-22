//! Streaming age encryption, wrapped behind a stable API.
//!
//! The rest of the project only ever sees [`encrypt_to`], [`decrypt_from`],
//! [`Recipient`] and [`Identity`]: the `age` API changes between minor
//! versions, and this module is the single place that has to be touched when
//! that happens.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{
    FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt, TokioAsyncReadCompatExt,
    TokioAsyncWriteCompatExt,
};

/// Errors of the encrypted stream.
#[derive(Debug, thiserror::Error)]
pub enum AgeError {
    /// The string is not a valid age public key.
    #[error("invalid age public key")]
    InvalidRecipient,
    /// The artifact is not addressed to the identity that was supplied.
    #[error("could not decrypt: the artifact is not addressed to this identity")]
    WrongIdentity,
    /// The text does not contain an age private key.
    ///
    /// The message repeats nothing of what it was given, **on purpose**: what
    /// was being read was a private key, and an error quoting it would leave it
    /// written in the log of whoever picked the wrong file.
    #[error(
        "no age private key was found: an `AGE-SECRET-KEY-1…` line is expected, \
         like the one `age-keygen` writes"
    )]
    InvalidIdentity,
    /// I/O failure on the underlying stream.
    #[error("I/O error on the encrypted stream: {0}")]
    Io(#[from] std::io::Error),
}

/// An age public key (`age1...`) an artifact is encrypted to.
#[derive(Clone)]
pub struct Recipient(age::x25519::Recipient);

impl Recipient {
    /// Parses an age public key from its `age1...` textual form.
    ///
    /// # Errors
    /// Returns `InvalidRecipient` if the string is not an age public key.
    pub fn parse(s: &str) -> Result<Self, AgeError> {
        s.parse::<age::x25519::Recipient>()
            .map(Self)
            .map_err(|_| AgeError::InvalidRecipient)
    }
}

impl std::fmt::Display for Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An age private key.
///
/// It deliberately implements neither `Debug` nor `Display`, just like
/// `Secret<T>`: a private key must not be able to end up in a log by accident.
pub struct Identity(age::x25519::Identity);

impl Identity {
    /// Generates a fresh identity from the system RNG.
    #[must_use]
    pub fn generate() -> Self {
        Self(age::x25519::Identity::generate())
    }

    /// Derives the public key that corresponds to this identity.
    #[must_use]
    pub fn to_recipient(&self) -> Recipient {
        Recipient(self.0.to_public())
    }

    /// Reads an identity from the contents of an age key file.
    ///
    /// It accepts the whole file exactly as `age-keygen` writes it — two
    /// comment lines and the key — and not just the bare key: forcing whoever
    /// is restoring to trim the file by hand, with the database down, would be
    /// asking them for precisely what they cannot do well at that moment. It
    /// keeps the **first** key it finds, which is the only one there is in a
    /// file generated that way.
    ///
    /// # Errors
    /// Returns [`AgeError::InvalidIdentity`] if there is no line that is an age
    /// private key. The error quotes nothing of the text it received.
    pub fn parse(text: &str) -> Result<Self, AgeError> {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .find_map(|line| line.parse::<age::x25519::Identity>().ok())
            .map(Self)
            .ok_or(AgeError::InvalidIdentity)
    }

    /// The textual form of the private key, wrapped so that it cannot be
    /// printed by accident.
    ///
    /// The [`Secret`](crate::Secret) wrapper is not decorative: it is the only
    /// thing separating "writing a key file" from "leaving the key in a log".
    /// Whoever genuinely needs it has to ask for `expose()` explicitly.
    #[must_use]
    pub fn to_secret_string(&self) -> crate::Secret<String> {
        crate::Secret::new(
            age::secrecy::ExposeSecret::expose_secret(&self.0.to_string()).to_owned(),
        )
    }
}

/// Wraps a sink so that whatever is written to it comes out encrypted to `rec`.
///
/// **You must call `shutdown()`** on the returned value: age only closes the
/// last AEAD block on finalization, and without that the artifact cannot be
/// read.
///
/// # Errors
/// Returns an error if the recipient is invalid or if writing the header fails.
pub async fn encrypt_to<W: AsyncWrite + Unpin>(
    sink: W,
    rec: &Recipient,
) -> Result<impl AsyncWrite + Unpin, AgeError> {
    let encryptor = age::Encryptor::with_recipients(std::iter::once(&rec.0 as &dyn age::Recipient))
        .map_err(|_| AgeError::InvalidRecipient)?;
    let writer = encryptor.wrap_async_output(sink.compat_write()).await?;
    Ok(writer.compat_write())
}

/// Wraps an encrypted source so it reads back in the clear using `id`.
///
/// Integrity is checked block by block as the stream is read: a tampered
/// ciphertext fails on read, not on open.
///
/// # Errors
/// Returns `WrongIdentity` if the artifact is not addressed to `id`, or if the
/// header is not a readable age artifact.
pub async fn decrypt_from<R: AsyncRead + Unpin>(
    source: R,
    id: &Identity,
) -> Result<impl AsyncRead + Unpin, AgeError> {
    let decryptor = age::Decryptor::new_async(source.compat())
        .await
        .map_err(|_| AgeError::WrongIdentity)?;
    let reader = decryptor
        .decrypt_async(std::iter::once(&id.0 as &dyn age::Identity))
        .map_err(|_| AgeError::WrongIdentity)?;
    Ok(reader.compat())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn key_pair() -> (Recipient, Identity) {
        let id = Identity::generate();
        let rec = id.to_recipient();
        (rec, id)
    }

    async fn encrypt(data: &[u8], rec: &Recipient) -> Vec<u8> {
        let mut sink = Vec::new();
        {
            let mut w = encrypt_to(&mut sink, rec).await.unwrap();
            w.write_all(data).await.unwrap();
            w.shutdown().await.unwrap();
        }
        sink
    }

    async fn decrypt(data: &[u8], id: &Identity) -> Vec<u8> {
        let mut r = decrypt_from(data, id).await.unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn round_trip() {
        let (rec, id) = key_pair();
        let data = b"sensitive data";
        let encrypted = encrypt(data, &rec).await;
        assert_ne!(
            &encrypted[..],
            &data[..],
            "the ciphertext must not be the plaintext"
        );
        assert_eq!(decrypt(&encrypted, &id).await, data);
    }

    #[tokio::test]
    async fn round_trip_with_zero_bytes() {
        // Same hazard as with zstd: without shutdown() the last AEAD block is
        // never closed and decryption fails with a confusing error.
        let (rec, id) = key_pair();
        let encrypted = encrypt(b"", &rec).await;
        assert!(!encrypted.is_empty(), "age always emits a header");
        assert_eq!(decrypt(&encrypted, &id).await, b"");
    }

    #[tokio::test]
    async fn round_trip_with_bulk_data() {
        // Forces age to emit several AEAD blocks, not just one.
        let (rec, id) = key_pair();
        let data: Vec<u8> = (0..300_000_u32).map(|i| (i % 251) as u8).collect();
        let encrypted = encrypt(&data, &rec).await;
        assert_eq!(decrypt(&encrypted, &id).await, data);
    }

    #[tokio::test]
    async fn a_foreign_identity_cannot_decrypt() {
        let (rec, _id) = key_pair();
        let (_, other) = key_pair();
        let encrypted = encrypt(b"secret", &rec).await;
        assert!(decrypt_from(&encrypted[..], &other).await.is_err());
    }

    #[tokio::test]
    async fn a_tampered_ciphertext_fails_on_read() {
        let (rec, id) = key_pair();
        let mut encrypted = encrypt(&vec![9_u8; 100_000], &rec).await;
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xff;

        let mut r = decrypt_from(&encrypted[..], &id).await.unwrap();
        let mut out = Vec::new();
        // AEAD: tampering is detected on read, not on open.
        assert!(r.read_to_end(&mut out).await.is_err());
    }

    #[tokio::test]
    async fn a_truncated_ciphertext_fails() {
        let (rec, id) = key_pair();
        let mut encrypted = encrypt(&vec![4_u8; 200_000], &rec).await;
        encrypted.truncate(encrypted.len() / 2);

        let result = async {
            let mut r = decrypt_from(&encrypted[..], &id).await?;
            let mut out = Vec::new();
            r.read_to_end(&mut out).await?;
            Ok::<_, Box<dyn std::error::Error>>(out)
        }
        .await;
        assert!(
            result.is_err(),
            "a truncated artifact must never read as valid"
        );
    }

    #[test]
    fn a_recipient_parses_from_its_textual_form() {
        let (rec, _) = key_pair();
        let text = rec.to_string();
        assert!(text.starts_with("age1"));
        assert_eq!(Recipient::parse(&text).unwrap().to_string(), text);
    }

    #[test]
    fn an_invalid_recipient_is_rejected() {
        assert!(Recipient::parse("this-is-not-a-recipient").is_err());
        assert!(Recipient::parse("").is_err());
    }

    #[test]
    fn an_identity_round_trips_through_its_textual_form() {
        let id = Identity::generate();
        let public = id.to_recipient().to_string();
        let text = id.to_secret_string();
        assert!(text.expose().starts_with("AGE-SECRET-KEY-1"));

        let read_back = Identity::parse(text.expose()).unwrap();
        assert_eq!(
            read_back.to_recipient().to_string(),
            public,
            "the identity read back must be the one that was written"
        );
    }

    #[test]
    fn a_key_file_with_comments_reads_the_same() {
        // This is exactly what `age-keygen` writes: two comment lines with the
        // date and the public key, and then the key itself.
        let id = Identity::generate();
        let file = format!(
            "# created: 2026-08-21T10:00:00Z\n# public key: {}\n{}\n",
            id.to_recipient(),
            id.to_secret_string().expose()
        );
        assert_eq!(
            Identity::parse(&file).unwrap().to_recipient().to_string(),
            id.to_recipient().to_string()
        );
    }

    #[test]
    fn an_invalid_identity_is_rejected_without_leaking_its_contents() {
        for bad in ["", "# only comments\n", "AGE-SECRET-KEY-1NOTVALID"] {
            // `unwrap_err` would require `Debug` on `Identity`, which it
            // deliberately does not have. `err()` requires nothing of the ok
            // side.
            let error = Identity::parse(bad).err().unwrap();
            assert!(matches!(error, AgeError::InvalidIdentity));
            assert!(
                !error.to_string().contains("AGE-SECRET-KEY-1NOTVALID"),
                "the error must not repeat what it was given: it was a private key"
            );
        }
    }

    #[test]
    fn a_public_key_does_not_pass_as_an_identity() {
        // The likeliest typo: passing the `.pub` instead of the key.
        let id = Identity::generate();
        assert!(Identity::parse(&id.to_recipient().to_string()).is_err());
    }
}
