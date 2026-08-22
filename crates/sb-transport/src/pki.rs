use std::sync::Arc;

// PEM parsing has lived in `rustls-pki-types` since its 1.9: `rustls-pemfile`
// was archived in August 2025 (RUSTSEC-2025-0134) and its last release was
// nothing more than a wrapper around this very code.
use rustls::pki_types::pem::{Error as PemError, PemObject as _};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};

/// Name the plugin presents in its server certificate.
pub const SERVER_NAME: &str = "shieldbk-plugin";
/// Name the core presents in its client certificate.
pub const CLIENT_NAME: &str = "shieldbk-core";

#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("could not generate the cryptographic material: {0}")]
    Generation(String),
    #[error("invalid cryptographic material: {0}")]
    Material(String),
    #[error("invalid TLS configuration: {0}")]
    Tls(#[from] rustls::Error),
}

/// Installs the rustls crypto provider if nobody has done so yet.
///
/// `rustls` 0.23 requires a process-wide `CryptoProvider` before any
/// configuration can be built. If we relied on it being inferred automatically
/// from *features*, the day another crate in the graph enables `aws-lc-rs` that
/// inference turns ambiguous and rustls panics. Installing it explicitly — and
/// from the library itself, not just from the tests — makes anyone using
/// `sb-transport` work without having to know any of this.
///
/// If the host process already installed its own provider, `install_default`
/// returns an error and we ignore it on purpose: we defer to theirs.
fn ensure_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// What the core hands the plugin over stdin: exactly enough to bring up a TLS
/// server that accepts nobody but the core.
///
/// **It does not include the client key.** If it did, the plugin could
/// impersonate the core to another plugin and ask it for credentials.
///
/// `Debug` is implemented by hand and redacted: this struct holds a private key
/// and must never end up whole in a log.
#[derive(Clone, Serialize, Deserialize)]
pub struct ServerBundle {
    pub ca_cert_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
}

impl std::fmt::Debug for ServerBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerBundle")
            .field("ca_cert_pem", &"<certificate>")
            .field("server_cert_pem", &"<certificate>")
            .field("server_key_pem", &"<redacted>")
            .finish()
    }
}

/// The complete PKI the core generates for a single session.
///
/// It lives in memory and dies with the process: it is never written to disk at
/// any point. That is deliberate — a certificate on disk is a certificate
/// somebody can steal.
///
/// It deliberately does not implement `Debug`: it holds two private keys.
#[allow(
    clippy::struct_field_names,
    reason = "the `_pem` suffix names the serialization format and is part of the public accessors"
)]
pub struct EphemeralPki {
    ca_cert_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
}

impl EphemeralPki {
    /// Generates a fresh certificate authority and, signed by it, a server leaf
    /// (for the plugin) and a client leaf (for the core).
    ///
    /// # Errors
    /// Returns an error if generating the cryptographic material fails.
    pub fn generate() -> Result<Self, PkiError> {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
            KeyUsagePurpose,
        };

        ensure_crypto_provider();

        let ca_key = KeyPair::generate().map_err(|e| gen_err(&e))?;
        let mut ca_params =
            CertificateParams::new(Vec::<String>::new()).map_err(|e| gen_err(&e))?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "shieldbk ephemeral CA");
        let ca_cert = ca_params.self_signed(&ca_key).map_err(|e| gen_err(&e))?;

        let leaf =
            |name: &str, usage: ExtendedKeyUsagePurpose| -> Result<(String, String), PkiError> {
                let key = KeyPair::generate().map_err(|e| gen_err(&e))?;
                let mut params =
                    CertificateParams::new(vec![name.to_string()]).map_err(|e| gen_err(&e))?;
                params.distinguished_name.push(DnType::CommonName, name);
                params.use_authority_key_identifier_extension = true;
                params.key_usages = vec![
                    KeyUsagePurpose::DigitalSignature,
                    KeyUsagePurpose::KeyEncipherment,
                ];
                params.extended_key_usages = vec![usage];
                let cert = params
                    .signed_by(&key, &ca_cert, &ca_key)
                    .map_err(|e| gen_err(&e))?;
                Ok((cert.pem(), key.serialize_pem()))
            };

        let (server_cert_pem, server_key_pem) =
            leaf(SERVER_NAME, ExtendedKeyUsagePurpose::ServerAuth)?;
        let (client_cert_pem, client_key_pem) =
            leaf(CLIENT_NAME, ExtendedKeyUsagePurpose::ClientAuth)?;

        Ok(Self {
            ca_cert_pem: ca_cert.pem(),
            server_cert_pem,
            server_key_pem,
            client_cert_pem,
            client_key_pem,
        })
    }

    /// Certificate of the ephemeral CA, in PEM. Both sides need it.
    #[must_use]
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Certificate the plugin will present, in PEM.
    #[must_use]
    pub fn server_cert_pem(&self) -> &str {
        &self.server_cert_pem
    }

    /// The plugin's private key, in PEM.
    #[must_use]
    pub fn server_key_pem(&self) -> &str {
        &self.server_key_pem
    }

    /// Certificate the core will present, in PEM.
    #[must_use]
    pub fn client_cert_pem(&self) -> &str {
        &self.client_cert_pem
    }

    /// The core's private key, in PEM. It never leaves this process.
    #[must_use]
    pub fn client_key_pem(&self) -> &str {
        &self.client_key_pem
    }

    /// What gets sent to the plugin.
    #[must_use]
    pub fn server_bundle(&self) -> ServerBundle {
        ServerBundle {
            ca_cert_pem: self.ca_cert_pem.clone(),
            server_cert_pem: self.server_cert_pem.clone(),
            server_key_pem: self.server_key_pem.clone(),
        }
    }

    /// # Errors
    /// Returns an error if the generated material is not acceptable to rustls.
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, PkiError> {
        server_config_from_bundle(&self.server_bundle())
    }

    /// Configuration for the core's side: it requires the server to be signed
    /// by our CA and presents the client certificate.
    ///
    /// # Errors
    /// Returns an error if the generated material is not acceptable to rustls.
    pub fn client_config(&self) -> Result<Arc<ClientConfig>, PkiError> {
        ensure_crypto_provider();
        let roots = root_store(&self.ca_cert_pem)?;
        let chain = parse_certs(&self.client_cert_pem)?;
        let key = parse_key(&self.client_key_pem)?;
        let cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, key)?;
        Ok(Arc::new(cfg))
    }
}

/// Rebuilds the server configuration from the bundle that was received.
///
/// The plugin SDK uses it; the SDK never generates material of its own, it only
/// loads the three PEMs the core gave it.
///
/// # Errors
/// Returns an error if the material is invalid or the CA cannot be loaded.
pub fn server_config_from_bundle(bundle: &ServerBundle) -> Result<Arc<ServerConfig>, PkiError> {
    ensure_crypto_provider();
    let roots = root_store(&bundle.ca_cert_pem)?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| PkiError::Material(e.to_string()))?;
    let chain = parse_certs(&bundle.server_cert_pem)?;
    let key = parse_key(&bundle.server_key_pem)?;
    let cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)?;
    Ok(Arc::new(cfg))
}

fn gen_err(e: &rcgen::Error) -> PkiError {
    PkiError::Generation(e.to_string())
}

fn root_store(ca_pem: &str) -> Result<RootCertStore, PkiError> {
    let certs = parse_certs(ca_pem)?;
    if certs.is_empty() {
        return Err(PkiError::Material("no CA certificate was found".into()));
    }
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| PkiError::Material(e.to_string()))?;
    }
    Ok(roots)
}

fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, PkiError> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| PkiError::Material(e.to_string()))
}

fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>, PkiError> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|e| match e {
        // The PEM carried no key at all. It deserves its own message: this is
        // the error seen by whoever picked the wrong file, and "no items found"
        // does not help.
        PemError::NoItemsFound => PkiError::Material("no private key was found in the PEM".into()),
        other => PkiError::Material(other.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_complete_pki() {
        let pki = EphemeralPki::generate().unwrap();
        assert!(pki.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(pki.server_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(pki.server_key_pem().contains("PRIVATE KEY"));
        assert!(pki.client_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(pki.client_key_pem().contains("PRIVATE KEY"));
    }

    #[test]
    fn every_generation_produces_different_material() {
        // Reusing material across runs would turn an ephemeral certificate into
        // a permanent one without anyone noticing.
        let a = EphemeralPki::generate().unwrap();
        let b = EphemeralPki::generate().unwrap();
        assert_ne!(a.ca_cert_pem(), b.ca_cert_pem());
        assert_ne!(a.server_key_pem(), b.server_key_pem());
        assert_ne!(a.client_key_pem(), b.client_key_pem());
    }

    #[test]
    fn the_server_and_client_certificates_are_different() {
        let pki = EphemeralPki::generate().unwrap();
        assert_ne!(pki.server_cert_pem(), pki.client_cert_pem());
        assert_ne!(pki.server_key_pem(), pki.client_key_pem());
    }

    #[test]
    fn builds_a_valid_server_configuration() {
        let pki = EphemeralPki::generate().unwrap();
        assert!(pki.server_config().is_ok());
    }

    #[test]
    fn builds_a_valid_client_configuration() {
        let pki = EphemeralPki::generate().unwrap();
        assert!(pki.client_config().is_ok());
    }

    #[test]
    fn the_server_bundle_does_not_include_the_client_key() {
        // If the plugin received the client key, it could pass itself off as
        // the core to another plugin and ask it for credentials.
        let pki = EphemeralPki::generate().unwrap();
        let bundle = pki.server_bundle();
        let json = serde_json::to_string(&bundle).unwrap();
        assert!(!json.contains(pki.client_key_pem()));
        assert!(!json.contains(pki.client_cert_pem()));
    }

    #[test]
    fn the_bundle_carries_exactly_what_the_plugin_needs() {
        let pki = EphemeralPki::generate().unwrap();
        let bundle = pki.server_bundle();
        assert_eq!(bundle.ca_cert_pem, pki.ca_cert_pem());
        assert_eq!(bundle.server_cert_pem, pki.server_cert_pem());
        assert_eq!(bundle.server_key_pem, pki.server_key_pem());
    }

    #[test]
    fn a_server_config_rebuilt_from_the_bundle_works() {
        // This is what the plugin SDK will do: load three PEMs and nothing else.
        let pki = EphemeralPki::generate().unwrap();
        let bundle = pki.server_bundle();
        assert!(server_config_from_bundle(&bundle).is_ok());
    }

    #[test]
    fn the_bundle_travels_through_json_without_losing_anything() {
        let pki = EphemeralPki::generate().unwrap();
        let json = serde_json::to_string(&pki.server_bundle()).unwrap();
        let round_tripped: ServerBundle = serde_json::from_str(&json).unwrap();
        assert!(server_config_from_bundle(&round_tripped).is_ok());
    }

    #[test]
    fn a_bundle_with_corrupt_material_is_rejected() {
        let pki = EphemeralPki::generate().unwrap();
        let mut bundle = pki.server_bundle();
        bundle.server_key_pem = "this is not a key".into();
        assert!(server_config_from_bundle(&bundle).is_err());
    }

    #[test]
    fn a_bundle_without_a_ca_is_rejected() {
        let pki = EphemeralPki::generate().unwrap();
        let mut bundle = pki.server_bundle();
        bundle.ca_cert_pem = String::new();
        assert!(server_config_from_bundle(&bundle).is_err());
    }

    #[test]
    fn the_cryptographic_material_does_not_show_up_when_printing_the_bundle() {
        // The bundle ends up in a log if somebody prints it carelessly.
        let pki = EphemeralPki::generate().unwrap();
        let text = format!("{:?}", pki.server_bundle());
        assert!(
            !text.contains("PRIVATE KEY"),
            "the private key must not appear in Debug"
        );
    }
}
