use serde::{Deserialize, Serialize};

use crate::pki::ServerBundle;

/// Marcador que abre ambos mensajes del handshake.
///
/// Sirve para que un binario que no es un plugin de shieldbk falle de inmediato
/// y con un mensaje claro, en vez de colgarse esperando algo que nunca llega.
pub const MAGIC: &str = "SHIELDBK_PLUGIN";

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("la respuesta no es JSON válido: {0}")]
    JsonInvalido(#[from] serde_json::Error),
    #[error("el binario no se identificó como un plugin de shieldbk")]
    MagicIncorrecto,
    #[error("sin versión de protocolo en común: el núcleo soporta {core:?}, el plugin {plugin:?}")]
    SinVersionComun { core: Vec<u32>, plugin: Vec<u32> },
}

/// Lo que el núcleo escribe en el stdin del plugin.
///
/// Deliberadamente JSON de una línea: un plugin en cualquier lenguaje lo lee
/// con un `read_line` y lo parsea con la librería estándar. No hace falta
/// hablar protobuf para arrancar.
#[derive(Clone, Serialize, Deserialize)]
pub struct Bootstrap {
    pub magic: String,
    pub core_protocol_versions: Vec<u32>,
    pub control_socket: String,
    pub tls: ServerBundle,
}

/// `Debug` redactado a mano: este struct contiene la clave privada del
/// servidor y jamás debe poder acabar íntegro en un log.
impl std::fmt::Debug for Bootstrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bootstrap")
            .field("magic", &self.magic)
            .field("core_protocol_versions", &self.core_protocol_versions)
            .field("control_socket", &self.control_socket)
            .field("tls", &"<redactado>")
            .finish()
    }
}

impl Bootstrap {
    /// # Errors
    /// Devuelve error si la serialización falla.
    pub fn to_line(&self) -> Result<String, HandshakeError> {
        Ok(serde_json::to_string(self)?)
    }

    /// # Errors
    /// Devuelve error si la línea no es JSON válido o no lleva el marcador.
    pub fn from_line(linea: &str) -> Result<Self, HandshakeError> {
        let b: Self = serde_json::from_str(linea.trim())?;
        if b.magic != MAGIC {
            return Err(HandshakeError::MagicIncorrecto);
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
        Bootstrap {
            magic: MAGIC.into(),
            core_protocol_versions: vec![1],
            control_socket: "/run/user/1000/shieldbk-abc/control.sock".into(),
            tls: crate::pki::ServerBundle {
                ca_cert_pem: "CA".into(),
                server_cert_pem: "CERT".into(),
                server_key_pem: "KEY".into(),
            },
        }
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
}
