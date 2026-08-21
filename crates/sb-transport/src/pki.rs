use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};

/// Nombre que presenta el plugin en su certificado de servidor.
pub const SERVER_NAME: &str = "shieldbk-plugin";
/// Nombre que presenta el núcleo en su certificado de cliente.
pub const CLIENT_NAME: &str = "shieldbk-core";

#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("no se pudo generar el material criptográfico: {0}")]
    Generacion(String),
    #[error("material criptográfico inválido: {0}")]
    Material(String),
    #[error("configuración TLS inválida: {0}")]
    Tls(#[from] rustls::Error),
}

/// Instala el proveedor criptográfico de rustls si nadie lo ha hecho todavía.
///
/// `rustls` 0.23 exige un `CryptoProvider` a nivel de proceso antes de poder
/// construir cualquier configuración. Si dependemos de la deducción automática
/// por *features*, el día que otra caja del grafo active `aws-lc-rs` la
/// deducción se vuelve ambigua y rustls entra en pánico. Instalarlo de forma
/// explícita —y desde la propia biblioteca, no solo desde los tests— hace que
/// cualquiera que use `sb-transport` funcione sin tener que saber esto.
///
/// Si el proceso anfitrión ya instaló su propio proveedor, `install_default`
/// devuelve error y lo ignoramos a propósito: respetamos el suyo.
fn ensure_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Lo que el núcleo entrega al plugin por stdin: lo justo para levantar un
/// servidor TLS que solo acepte al núcleo.
///
/// **No incluye la clave del cliente.** Si la incluyera, el plugin podría
/// suplantar al núcleo ante otro plugin y pedirle credenciales.
///
/// `Debug` está implementado a mano y redactado: este struct contiene una clave
/// privada y no puede acabar íntegro en un log.
#[derive(Clone, Serialize, Deserialize)]
pub struct ServerBundle {
    pub ca_cert_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
}

impl std::fmt::Debug for ServerBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerBundle")
            .field("ca_cert_pem", &"<certificado>")
            .field("server_cert_pem", &"<certificado>")
            .field("server_key_pem", &"<redactado>")
            .finish()
    }
}

/// PKI completa generada por el núcleo para una única sesión.
///
/// Vive en memoria y muere con el proceso: no se escribe a disco en ningún
/// momento. Es deliberado — un certificado en disco es un certificado que
/// alguien puede robar.
///
/// No implementa `Debug` a propósito: contiene dos claves privadas.
#[allow(
    clippy::struct_field_names,
    reason = "el sufijo `_pem` indica el formato de serialización y forma parte de los accesores públicos"
)]
pub struct EphemeralPki {
    ca_cert_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
}

impl EphemeralPki {
    /// Genera una autoridad certificadora nueva y, firmadas por ella, una hoja
    /// de servidor (para el plugin) y una hoja de cliente (para el núcleo).
    ///
    /// # Errors
    /// Devuelve error si falla la generación del material criptográfico.
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

        let hoja =
            |nombre: &str, uso: ExtendedKeyUsagePurpose| -> Result<(String, String), PkiError> {
                let key = KeyPair::generate().map_err(|e| gen_err(&e))?;
                let mut params =
                    CertificateParams::new(vec![nombre.to_string()]).map_err(|e| gen_err(&e))?;
                params.distinguished_name.push(DnType::CommonName, nombre);
                params.use_authority_key_identifier_extension = true;
                params.key_usages = vec![
                    KeyUsagePurpose::DigitalSignature,
                    KeyUsagePurpose::KeyEncipherment,
                ];
                params.extended_key_usages = vec![uso];
                let cert = params
                    .signed_by(&key, &ca_cert, &ca_key)
                    .map_err(|e| gen_err(&e))?;
                Ok((cert.pem(), key.serialize_pem()))
            };

        let (server_cert_pem, server_key_pem) =
            hoja(SERVER_NAME, ExtendedKeyUsagePurpose::ServerAuth)?;
        let (client_cert_pem, client_key_pem) =
            hoja(CLIENT_NAME, ExtendedKeyUsagePurpose::ClientAuth)?;

        Ok(Self {
            ca_cert_pem: ca_cert.pem(),
            server_cert_pem,
            server_key_pem,
            client_cert_pem,
            client_key_pem,
        })
    }

    /// Certificado de la CA efímera, en PEM. Lo necesitan ambos lados.
    #[must_use]
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Certificado que presentará el plugin, en PEM.
    #[must_use]
    pub fn server_cert_pem(&self) -> &str {
        &self.server_cert_pem
    }

    /// Clave privada del plugin, en PEM.
    #[must_use]
    pub fn server_key_pem(&self) -> &str {
        &self.server_key_pem
    }

    /// Certificado que presentará el núcleo, en PEM.
    #[must_use]
    pub fn client_cert_pem(&self) -> &str {
        &self.client_cert_pem
    }

    /// Clave privada del núcleo, en PEM. Nunca sale de este proceso.
    #[must_use]
    pub fn client_key_pem(&self) -> &str {
        &self.client_key_pem
    }

    /// Lo que se le manda al plugin.
    #[must_use]
    pub fn server_bundle(&self) -> ServerBundle {
        ServerBundle {
            ca_cert_pem: self.ca_cert_pem.clone(),
            server_cert_pem: self.server_cert_pem.clone(),
            server_key_pem: self.server_key_pem.clone(),
        }
    }

    /// # Errors
    /// Devuelve error si el material generado no es aceptable para rustls.
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, PkiError> {
        server_config_from_bundle(&self.server_bundle())
    }

    /// Configuración del lado del núcleo: exige que el servidor esté firmado
    /// por nuestra CA y presenta el certificado de cliente.
    ///
    /// # Errors
    /// Devuelve error si el material generado no es aceptable para rustls.
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

/// Reconstruye la configuración del servidor a partir del bundle recibido.
///
/// La usa el SDK del plugin, que nunca genera material propio: solo carga los
/// tres PEM que le dio el núcleo.
///
/// # Errors
/// Devuelve error si el material es inválido o la CA no se puede cargar.
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
    PkiError::Generacion(e.to_string())
}

fn root_store(ca_pem: &str) -> Result<RootCertStore, PkiError> {
    let certs = parse_certs(ca_pem)?;
    if certs.is_empty() {
        return Err(PkiError::Material(
            "no se encontró ningún certificado de CA".into(),
        ));
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
    rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| PkiError::Material(e.to_string()))
}

fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>, PkiError> {
    rustls_pemfile::private_key(&mut pem.as_bytes())
        .map_err(|e| PkiError::Material(e.to_string()))?
        .ok_or_else(|| PkiError::Material("no se encontró clave privada en el PEM".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genera_una_pki_completa() {
        let pki = EphemeralPki::generate().unwrap();
        assert!(pki.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(pki.server_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(pki.server_key_pem().contains("PRIVATE KEY"));
        assert!(pki.client_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(pki.client_key_pem().contains("PRIVATE KEY"));
    }

    #[test]
    fn cada_generacion_produce_material_distinto() {
        // Reutilizar material entre ejecuciones convertiría un certificado
        // efímero en uno permanente sin que nadie se diera cuenta.
        let a = EphemeralPki::generate().unwrap();
        let b = EphemeralPki::generate().unwrap();
        assert_ne!(a.ca_cert_pem(), b.ca_cert_pem());
        assert_ne!(a.server_key_pem(), b.server_key_pem());
        assert_ne!(a.client_key_pem(), b.client_key_pem());
    }

    #[test]
    fn el_certificado_de_servidor_y_el_de_cliente_son_distintos() {
        let pki = EphemeralPki::generate().unwrap();
        assert_ne!(pki.server_cert_pem(), pki.client_cert_pem());
        assert_ne!(pki.server_key_pem(), pki.client_key_pem());
    }

    #[test]
    fn construye_una_configuracion_de_servidor_valida() {
        let pki = EphemeralPki::generate().unwrap();
        assert!(pki.server_config().is_ok());
    }

    #[test]
    fn construye_una_configuracion_de_cliente_valida() {
        let pki = EphemeralPki::generate().unwrap();
        assert!(pki.client_config().is_ok());
    }

    #[test]
    fn el_bundle_del_servidor_no_incluye_la_clave_del_cliente() {
        // Si el plugin recibiera la clave del cliente, podría hacerse pasar por
        // el núcleo ante otro plugin y pedirle credenciales.
        let pki = EphemeralPki::generate().unwrap();
        let bundle = pki.server_bundle();
        let json = serde_json::to_string(&bundle).unwrap();
        assert!(!json.contains(pki.client_key_pem()));
        assert!(!json.contains(pki.client_cert_pem()));
    }

    #[test]
    fn el_bundle_lleva_exactamente_lo_que_el_plugin_necesita() {
        let pki = EphemeralPki::generate().unwrap();
        let bundle = pki.server_bundle();
        assert_eq!(bundle.ca_cert_pem, pki.ca_cert_pem());
        assert_eq!(bundle.server_cert_pem, pki.server_cert_pem());
        assert_eq!(bundle.server_key_pem, pki.server_key_pem());
    }

    #[test]
    fn una_config_de_servidor_reconstruida_desde_el_bundle_funciona() {
        // Es lo que hará el SDK del plugin: cargar tres PEM y nada más.
        let pki = EphemeralPki::generate().unwrap();
        let bundle = pki.server_bundle();
        assert!(server_config_from_bundle(&bundle).is_ok());
    }

    #[test]
    fn el_bundle_viaja_por_json_sin_perder_nada() {
        let pki = EphemeralPki::generate().unwrap();
        let json = serde_json::to_string(&pki.server_bundle()).unwrap();
        let vuelta: ServerBundle = serde_json::from_str(&json).unwrap();
        assert!(server_config_from_bundle(&vuelta).is_ok());
    }

    #[test]
    fn un_bundle_con_material_corrupto_se_rechaza() {
        let pki = EphemeralPki::generate().unwrap();
        let mut bundle = pki.server_bundle();
        bundle.server_key_pem = "esto no es una clave".into();
        assert!(server_config_from_bundle(&bundle).is_err());
    }

    #[test]
    fn un_bundle_sin_ca_se_rechaza() {
        let pki = EphemeralPki::generate().unwrap();
        let mut bundle = pki.server_bundle();
        bundle.ca_cert_pem = String::new();
        assert!(server_config_from_bundle(&bundle).is_err());
    }

    #[test]
    fn el_material_criptografico_no_aparece_al_imprimir_el_bundle() {
        // El bundle acaba en un log si alguien lo imprime por descuido.
        let pki = EphemeralPki::generate().unwrap();
        let texto = format!("{:?}", pki.server_bundle());
        assert!(
            !texto.contains("PRIVATE KEY"),
            "la clave privada no puede aparecer en Debug"
        );
    }
}
