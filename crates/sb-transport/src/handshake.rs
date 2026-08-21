use serde::{Deserialize, Serialize};

use crate::pki::ServerBundle;

/// Marcador que abre ambos mensajes del handshake.
///
/// Sirve para que un binario que no es un plugin de shieldbk falle de inmediato
/// y con un mensaje claro, en vez de colgarse esperando algo que nunca llega.
pub const MAGIC: &str = "SHIELDBK_PLUGIN";

/// Versión del sobre del handshake.
///
/// Distinta de `core_protocol_versions`, que negocia el protocolo gRPC
/// posterior. Esta versiona el propio JSON de arranque, para que añadir un
/// campo obligatorio en el futuro haga fallar al plugin viejo **al arrancar**,
/// con un mensaje claro, en vez de más tarde y peor.
pub const HANDSHAKE_VERSION: u32 = 1;

/// Cuánto espera el núcleo a que el plugin se anuncie, por defecto.
/// Generoso para arranques lentos, acotado para que nada se cuelgue de noche.
pub const READY_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("la respuesta no es JSON válido: {0}")]
    JsonInvalido(#[from] serde_json::Error),
    #[error("el binario no se identificó como un plugin de shieldbk")]
    MagicIncorrecto,
    #[error("sin versión de protocolo en común: el núcleo soporta {core:?}, el plugin {plugin:?}")]
    SinVersionComun { core: Vec<u32>, plugin: Vec<u32> },
    #[error(
        "sobre de handshake versión {encontrada}; esta versión de shieldbk entiende hasta la {soportada}"
    )]
    SobreNoSoportado { encontrada: u32, soportada: u32 },
}

/// Lo que el núcleo escribe en el stdin del plugin.
///
/// Deliberadamente JSON de una línea: un plugin en cualquier lenguaje lo lee
/// con un `read_line` y lo parsea con la librería estándar. No hace falta
/// hablar protobuf para arrancar.
#[derive(Clone, Serialize, Deserialize)]
pub struct Bootstrap {
    pub magic: String,
    /// Versión de este sobre. `default` = 0 para sobres anteriores al campo.
    #[serde(default)]
    pub handshake_version: u32,
    pub core_protocol_versions: Vec<u32>,
    pub control_socket: String,
    /// Nombre que el plugin debe presentar en su certificado de servidor.
    /// Va explícito para que un plugin escrito en otro lenguaje no tenga que
    /// parsear el certificado ni conocer una constante de Rust.
    #[serde(default)]
    pub server_name: String,
    /// Nombre que el plugin debe exigir al cliente. Hace que la política de
    /// mTLS sean datos y no conocimiento tribal.
    #[serde(default)]
    pub client_name: String,
    /// Margen que tiene el plugin para anunciarse antes de que el núcleo lo
    /// dé por perdido. El contrato temporal es bidireccional.
    #[serde(default)]
    pub ready_timeout_ms: u64,
    pub tls: ServerBundle,
}

/// `Debug` redactado a mano: este struct contiene la clave privada del
/// servidor y jamás debe poder acabar íntegro en un log.
impl std::fmt::Debug for Bootstrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bootstrap")
            .field("magic", &self.magic)
            .field("handshake_version", &self.handshake_version)
            .field("core_protocol_versions", &self.core_protocol_versions)
            .field("control_socket", &self.control_socket)
            .field("server_name", &self.server_name)
            .field("client_name", &self.client_name)
            .field("ready_timeout_ms", &self.ready_timeout_ms)
            .field("tls", &"<redactado>")
            .finish()
    }
}

impl Bootstrap {
    /// Construye el sobre que el núcleo envía al plugin.
    ///
    /// Es la vía recomendada: rellena el marcador, la versión del sobre, los
    /// nombres TLS y el timeout con los valores correctos, de modo que añadir
    /// un campo en el futuro no obligue a revisar cada sitio que lo construye.
    #[must_use]
    pub fn nuevo(
        core_protocol_versions: Vec<u32>,
        control_socket: String,
        tls: ServerBundle,
    ) -> Self {
        Self {
            magic: MAGIC.into(),
            handshake_version: HANDSHAKE_VERSION,
            core_protocol_versions,
            control_socket,
            server_name: crate::pki::SERVER_NAME.into(),
            client_name: crate::pki::CLIENT_NAME.into(),
            ready_timeout_ms: READY_TIMEOUT_MS,
            tls,
        }
    }

    /// # Errors
    /// Devuelve error si la serialización falla.
    pub fn to_line(&self) -> Result<String, HandshakeError> {
        Ok(serde_json::to_string(self)?)
    }

    /// # Errors
    /// Devuelve error si la línea no es JSON válido, no lleva el marcador o
    /// declara una versión de sobre que esta versión no sabe leer.
    pub fn from_line(linea: &str) -> Result<Self, HandshakeError> {
        let b: Self = serde_json::from_str(linea.trim())?;
        if b.magic != MAGIC {
            return Err(HandshakeError::MagicIncorrecto);
        }
        if b.handshake_version > HANDSHAKE_VERSION {
            return Err(HandshakeError::SobreNoSoportado {
                encontrada: b.handshake_version,
                soportada: HANDSHAKE_VERSION,
            });
        }
        Ok(b)
    }

    /// Elige la versión más alta soportada por ambos lados.
    ///
    /// # Errors
    /// Devuelve `SinVersionComun` si no hay ninguna en común, con las dos
    /// listas en el mensaje para que quien lo lea sepa qué actualizar.
    pub fn negotiate(&self, del_plugin: &[u32]) -> Result<u32, HandshakeError> {
        self.core_protocol_versions
            .iter()
            .filter(|v| del_plugin.contains(v))
            .max()
            .copied()
            .ok_or_else(|| HandshakeError::SinVersionComun {
                core: self.core_protocol_versions.clone(),
                plugin: del_plugin.to_vec(),
            })
    }
}

/// Lo que el plugin escribe en su stdout cuando ya está escuchando.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ready {
    pub magic: String,
    pub protocol_version: u32,
    pub capabilities: Vec<String>,
    pub pid: u32,
}

impl Ready {
    /// # Errors
    /// Devuelve error si la serialización falla.
    pub fn to_line(&self) -> Result<String, HandshakeError> {
        Ok(serde_json::to_string(self)?)
    }

    /// # Errors
    /// Devuelve error si la línea no es JSON válido o no lleva el marcador.
    pub fn from_line(linea: &str) -> Result<Self, HandshakeError> {
        let r: Self = serde_json::from_str(linea.trim())?;
        if r.magic != MAGIC {
            return Err(HandshakeError::MagicIncorrecto);
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bootstrap_de_ejemplo() -> Bootstrap {
        Bootstrap::nuevo(
            vec![1],
            "/run/user/1000/shieldbk-abc/control.sock".into(),
            crate::pki::ServerBundle {
                ca_cert_pem: "CA".into(),
                server_cert_pem: "CERT".into(),
                server_key_pem: "KEY".into(),
            },
        )
    }

    fn ready_de_ejemplo() -> Ready {
        Ready {
            magic: MAGIC.into(),
            protocol_version: 1,
            capabilities: vec!["engine".into()],
            pid: 4242,
        }
    }

    #[test]
    fn el_bootstrap_viaja_como_una_sola_linea_json() {
        // Una línea: el plugin lo lee con un read_line normal, sin necesitar
        // un parser de streaming ni saber cuántos bytes esperar.
        let linea = bootstrap_de_ejemplo().to_line().unwrap();
        assert!(!linea.contains('\n'), "debe ser exactamente una línea");
        let vuelta = Bootstrap::from_line(&linea).unwrap();
        assert_eq!(
            vuelta.control_socket,
            "/run/user/1000/shieldbk-abc/control.sock"
        );
        assert_eq!(vuelta.tls.server_key_pem, "KEY");
    }

    #[test]
    fn se_rechaza_un_bootstrap_con_magic_incorrecto() {
        let mut b = bootstrap_de_ejemplo();
        b.magic = "OTRA-COSA".into();
        let linea = serde_json::to_string(&b).unwrap();
        assert!(matches!(
            Bootstrap::from_line(&linea).unwrap_err(),
            HandshakeError::MagicIncorrecto
        ));
    }

    #[test]
    fn se_rechaza_un_bootstrap_que_no_es_json() {
        assert!(matches!(
            Bootstrap::from_line("esto no es json").unwrap_err(),
            HandshakeError::JsonInvalido(_)
        ));
    }

    #[test]
    fn se_rechaza_una_linea_vacia() {
        // Es lo que se lee de un binario que murió sin escribir nada.
        assert!(Bootstrap::from_line("").is_err());
        assert!(Ready::from_line("").is_err());
    }

    #[test]
    fn el_ready_viaja_como_una_sola_linea_json() {
        let linea = ready_de_ejemplo().to_line().unwrap();
        assert!(!linea.contains('\n'));
        let vuelta = Ready::from_line(&linea).unwrap();
        assert_eq!(vuelta.pid, 4242);
        assert_eq!(vuelta.capabilities, vec!["engine".to_string()]);
    }

    #[test]
    fn se_rechaza_un_ready_con_magic_incorrecto() {
        let mut r = ready_de_ejemplo();
        r.magic = "NO-SOY-UN-PLUGIN".into();
        let linea = serde_json::to_string(&r).unwrap();
        assert!(matches!(
            Ready::from_line(&linea).unwrap_err(),
            HandshakeError::MagicIncorrecto
        ));
    }

    #[test]
    fn los_espacios_y_saltos_alrededor_no_estorban() {
        // Un plugin en otro lenguaje puede escribir con println y dejar \r\n.
        let linea = ready_de_ejemplo().to_line().unwrap();
        let sucia = format!("  {linea}\r\n");
        assert_eq!(Ready::from_line(&sucia).unwrap().pid, 4242);
    }

    #[test]
    fn el_plugin_elige_una_version_que_el_nucleo_soporta() {
        let b = bootstrap_de_ejemplo();
        assert_eq!(b.negotiate(&[1, 2]).unwrap(), 1);
    }

    #[test]
    fn se_elige_la_version_mas_alta_en_comun() {
        let mut b = bootstrap_de_ejemplo();
        b.core_protocol_versions = vec![1, 2, 3];
        assert_eq!(b.negotiate(&[1, 2]).unwrap(), 2);
    }

    #[test]
    fn sin_version_en_comun_se_falla_con_un_mensaje_util() {
        let mut b = bootstrap_de_ejemplo();
        b.core_protocol_versions = vec![3, 4];
        let err = b.negotiate(&[1, 2]).unwrap_err();
        let texto = err.to_string();
        assert!(
            texto.contains('3'),
            "el mensaje debe decir qué pide el núcleo"
        );
        assert!(texto.contains('1'), "y qué ofrece el plugin");
    }

    #[test]
    fn un_plugin_sin_versiones_no_negocia_nada() {
        let b = bootstrap_de_ejemplo();
        assert!(b.negotiate(&[]).is_err());
    }

    #[test]
    fn un_nucleo_sin_versiones_no_negocia_nada() {
        let mut b = bootstrap_de_ejemplo();
        b.core_protocol_versions = vec![];
        assert!(b.negotiate(&[1]).is_err());
    }

    #[test]
    fn el_bootstrap_no_revela_la_clave_privada_al_imprimirse() {
        // Este struct contiene la clave del servidor. Si alguien lo loguea para
        // depurar el arranque de un plugin, no puede filtrarla.
        let texto = format!("{:?}", bootstrap_de_ejemplo());
        assert!(
            !texto.contains("KEY"),
            "la clave privada no puede aparecer en Debug"
        );
    }

    #[test]
    fn el_json_del_bootstrap_si_lleva_la_clave() {
        // Lo contrario del test anterior: redactar el Debug no debe haber
        // roto la serialización, o el plugin no recibiría su clave.
        let linea = bootstrap_de_ejemplo().to_line().unwrap();
        assert!(linea.contains("KEY"));
    }

    #[test]
    fn el_bootstrap_lleva_los_nombres_tls_para_plugins_de_otros_lenguajes() {
        // Un plugin en Go o Python no puede importar SERVER_NAME/CLIENT_NAME
        // del crate de Rust. Sin estos campos tendría que parsear el DER del
        // certificado solo para saber a quién autorizar.
        let b = Bootstrap::nuevo(
            vec![1],
            "/tmp/x.sock".into(),
            crate::pki::ServerBundle {
                ca_cert_pem: "CA".into(),
                server_cert_pem: "CERT".into(),
                server_key_pem: "KEY".into(),
            },
        );
        assert_eq!(b.server_name, crate::pki::SERVER_NAME);
        assert_eq!(b.client_name, crate::pki::CLIENT_NAME);
    }

    #[test]
    fn el_bootstrap_declara_su_propia_version_de_sobre() {
        let b = bootstrap_de_ejemplo();
        assert_eq!(b.handshake_version, HANDSHAKE_VERSION);
    }

    #[test]
    fn el_bootstrap_anuncia_cuanto_tiempo_tiene_el_plugin_para_arrancar() {
        // Sin esto el contrato temporal es unilateral: el plugin no sabe si lo
        // van a matar antes de terminar de abrir su socket.
        let b = bootstrap_de_ejemplo();
        assert!(b.ready_timeout_ms > 0);
    }

    #[test]
    fn se_rechaza_un_sobre_de_version_futura() {
        // Un núcleo nuevo podría añadir campos obligatorios. Mejor que el
        // plugin viejo lo diga al arrancar que fallar más tarde y peor.
        let mut b = bootstrap_de_ejemplo();
        b.handshake_version = HANDSHAKE_VERSION + 1;
        let linea = serde_json::to_string(&b).unwrap();
        assert!(matches!(
            Bootstrap::from_line(&linea).unwrap_err(),
            HandshakeError::SobreNoSoportado { .. }
        ));
    }

    #[test]
    fn el_error_de_sobre_dice_ambas_versiones() {
        let mut b = bootstrap_de_ejemplo();
        b.handshake_version = 77;
        let texto = Bootstrap::from_line(&serde_json::to_string(&b).unwrap())
            .unwrap_err()
            .to_string();
        assert!(texto.contains("77"), "debe decir qué versión llegó");
        assert!(
            texto.contains(&HANDSHAKE_VERSION.to_string()),
            "y cuál se entiende"
        );
    }

    #[test]
    fn un_bootstrap_sin_los_campos_nuevos_sigue_deserializando() {
        // Compatibilidad hacia atrás: los campos nuevos son #[serde(default)],
        // así que un sobre antiguo no rompe. Es la propiedad que permite
        // evolucionar el protocolo sin romper plugins publicados.
        let json = r#"{
            "magic": "SHIELDBK_PLUGIN",
            "core_protocol_versions": [1],
            "control_socket": "/tmp/x.sock",
            "tls": {"ca_cert_pem":"CA","server_cert_pem":"CERT","server_key_pem":"KEY"}
        }"#;
        let b = Bootstrap::from_line(json).unwrap();
        assert_eq!(b.control_socket, "/tmp/x.sock");
        assert_eq!(b.handshake_version, 0, "un sobre sin versión declara la 0");
    }

    #[test]
    fn los_campos_nuevos_viajan_por_json() {
        let linea = bootstrap_de_ejemplo().to_line().unwrap();
        assert!(linea.contains("server_name"));
        assert!(linea.contains("client_name"));
        assert!(linea.contains("handshake_version"));
        assert!(linea.contains("ready_timeout_ms"));
    }

    #[test]
    fn el_constructor_rellena_los_valores_correctos_por_defecto() {
        let b = Bootstrap::nuevo(
            vec![1, 2],
            "/tmp/y.sock".into(),
            crate::pki::ServerBundle {
                ca_cert_pem: "CA".into(),
                server_cert_pem: "CERT".into(),
                server_key_pem: "KEY".into(),
            },
        );
        assert_eq!(b.magic, MAGIC);
        assert_eq!(b.handshake_version, HANDSHAKE_VERSION);
        assert_eq!(b.core_protocol_versions, vec![1, 2]);
        assert_eq!(b.control_socket, "/tmp/y.sock");
        assert!(Bootstrap::from_line(&b.to_line().unwrap()).is_ok());
    }
}
