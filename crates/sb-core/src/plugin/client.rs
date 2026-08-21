//! El plugin como interlocutor: proceso vivo + canal gRPC.
//!
//! [`PluginProcess`] arranca el binario y garantiza su limpieza;
//! [`sb_transport::connect_control`] abre el canal cifrado. Ninguno de los dos
//! sabe hablar el servicio `Plugin`. Este módulo los junta y expone los cinco
//! RPC de control con tres cosas que las operaciones de backup necesitan y que
//! `tonic::Status` no da:
//!
//! * **Plazo en cada llamada.** Un plugin que se queda colgado —esperando a un
//!   servidor de base de datos que no contesta— dejaría el backup esperando
//!   para siempre. Los RPC de control son todos rápidos, así que cualquier
//!   espera larga es un fallo disfrazado de lentitud.
//! * **Errores que dicen quién y en qué.** Un backup tiene dos plugins vivos a
//!   la vez, el motor y el destino; «falló configure» obliga a adivinar cuál
//!   de los dos fue.
//! * **Versión y capacidades comprobadas antes de usarlas.** Pedirle un dump a
//!   un plugin que solo sabe almacenar debe fallar al elegirlo, no a mitad del
//!   backup.

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::time::Duration;

use sb_proto::plugin_client::PluginClient as PluginGrpc;
use sb_proto::{
    ConfigureRequest, Field, InfoRequest, InfoResponse, PreflightRequest, PreflightResponse,
    SchemaRequest, ShutdownRequest, Value,
};
use sb_transport::{ControlError, connect_control};
use tonic::transport::Channel;

use super::process::{PluginProcess, PluginProcessError};

/// Plazo máximo de cualquier RPC de control.
///
/// Los cinco son rápidos por definición —informan, describen, guardan
/// configuración o comprueban— así que un minuto no es un plazo ajustado sino
/// el punto a partir del cual está claro que el plugin no va a contestar. Vale
/// solo para el canal de control: un `Dump` puede tardar horas y no pasa por
/// aquí.
const PLAZO_RPC: Duration = Duration::from_secs(60);

/// Lo que un plugin sabe hacer, tal y como lo declara al arrancar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capacidad {
    /// Sabe producir y restaurar un volcado: es un motor.
    Engine,
    /// Sabe guardar y recuperar artefactos: es un destino.
    Storage,
}

impl Capacidad {
    /// El nombre con el que viaja por el cable, que es el mismo que el plugin
    /// declara en su anuncio de arranque.
    #[must_use]
    pub fn como_cadena(self) -> &'static str {
        match self {
            Self::Engine => "engine",
            Self::Storage => "storage",
        }
    }
}

impl std::fmt::Display for Capacidad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.como_cadena())
    }
}

/// Todo lo que puede salir mal al hablar con un plugin.
///
/// Cada variante nombra al plugin porque el usuario tiene varios y el mensaje
/// es lo único que le dice cuál de ellos le está dando problemas.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("{0}")]
    Proceso(#[from] PluginProcessError),
    #[error("{0}")]
    Transporte(#[from] ControlError),
    /// El plugin contestó, pero con un error.
    #[error("el plugin «{plugin}» falló en {operacion}: {mensaje}")]
    Rpc {
        plugin: String,
        operacion: String,
        mensaje: String,
    },
    /// El plugin no contestó dentro del plazo. Se distingue de `Rpc` porque el
    /// remedio es otro: aquí no hay mensaje del plugin que leer, hay un
    /// proceso al que mirar.
    #[error("el plugin «{plugin}» no respondió a {operacion} en {} s", PLAZO_RPC.as_secs())]
    Timeout { plugin: String, operacion: String },
    #[error("el plugin «{plugin}» no sabe hacer de «{capacidad}»")]
    SinCapacidad { plugin: String, capacidad: String },
    #[error(
        "el plugin «{plugin}» habla la versión {del_plugin} del protocolo y este núcleo la {del_nucleo}"
    )]
    VersionIncompatible {
        plugin: String,
        del_plugin: u32,
        del_nucleo: u32,
    },
}

/// Un plugin arrancado, conectado y listo para recibir órdenes.
///
/// Mientras este handle exista, el proceso existe y el canal está abierto.
/// `shutdown` lo cierra ordenadamente; si nadie lo llama, el `Drop` del proceso
/// se encarga igualmente.
#[derive(Debug)]
pub struct PluginClient {
    proceso: PluginProcess,
    canal: Channel,
}

impl PluginClient {
    /// Arranca el plugin, comprueba que hablan el mismo protocolo y abre el
    /// canal de control.
    ///
    /// La versión se comprueba **antes** de conectar: si el plugin habla otro
    /// protocolo, el canal no serviría de nada y lo único que se lograría
    /// abriéndolo es que el fallo aparezca más tarde y peor explicado.
    ///
    /// # Errors
    /// Devuelve [`PluginError::Proceso`] si el binario no arranca o no se
    /// anuncia, [`PluginError::VersionIncompatible`] si las versiones no
    /// coinciden y [`PluginError::Transporte`] si el canal no se puede abrir.
    pub async fn start(nombre: &str, binario: &Path) -> Result<Self, PluginError> {
        let proceso = PluginProcess::spawn(nombre, binario).await?;

        if proceso.protocol_version() != sb_proto::PROTOCOL_VERSION {
            let error = PluginError::VersionIncompatible {
                plugin: nombre.to_string(),
                del_plugin: proceso.protocol_version(),
                del_nucleo: sb_proto::PROTOCOL_VERSION,
            };
            cerrar_tras_un_fallo(proceso, &error).await;
            return Err(error);
        }

        let tls = match proceso.pki().client_config() {
            Ok(tls) => tls,
            Err(fuente) => {
                let error = PluginError::Transporte(ControlError::from_pki(fuente));
                cerrar_tras_un_fallo(proceso, &error).await;
                return Err(error);
            }
        };

        let canal = match connect_control(proceso.control_socket(), tls).await {
            Ok(canal) => canal,
            Err(fuente) => {
                let error = PluginError::Transporte(fuente);
                cerrar_tras_un_fallo(proceso, &error).await;
                return Err(error);
            }
        };

        Ok(Self { proceso, canal })
    }

    #[must_use]
    pub fn nombre(&self) -> &str {
        self.proceso.nombre()
    }

    /// El proceso que hay debajo: pid, directorio de ejecución y capacidades
    /// declaradas.
    #[must_use]
    pub fn proceso(&self) -> &PluginProcess {
        &self.proceso
    }

    /// El canal de control, listo para construir un `EngineClient` o un
    /// `StorageClient` encima.
    ///
    /// Clonarlo no abre otra conexión: un `Channel` de tonic es un handle a la
    /// conexión ya establecida, y todas las llamadas se multiplexan sobre ella.
    #[must_use]
    pub fn canal(&self) -> Channel {
        self.canal.clone()
    }

    /// Si el plugin declaró saber hacer eso al arrancar.
    #[must_use]
    pub fn tiene_capacidad(&self, capacidad: Capacidad) -> bool {
        self.proceso
            .capabilities()
            .iter()
            .any(|c| c == capacidad.como_cadena())
    }

    /// Como [`Self::tiene_capacidad`], pero convierte el «no» en un error que
    /// se puede propagar.
    ///
    /// Existe para que elegir un plugin para un papel que no sabe desempeñar
    /// falle al elegirlo y no a mitad del backup.
    ///
    /// # Errors
    /// Devuelve [`PluginError::SinCapacidad`], que nombra al plugin y a la
    /// capacidad que le falta.
    pub fn exigir_capacidad(&self, capacidad: Capacidad) -> Result<(), PluginError> {
        if self.tiene_capacidad(capacidad) {
            return Ok(());
        }
        Err(PluginError::SinCapacidad {
            plugin: self.nombre().to_string(),
            capacidad: capacidad.como_cadena().to_string(),
        })
    }

    /// Identidad, versión y capacidades, ya sobre el canal autenticado.
    ///
    /// # Errors
    /// Devuelve [`PluginError::Rpc`] o [`PluginError::Timeout`].
    pub async fn info(&self) -> Result<InfoResponse, PluginError> {
        let mut grpc = self.grpc();
        self.con_plazo("info", grpc.info(InfoRequest {})).await
    }

    /// Los campos de configuración que el plugin acepta.
    ///
    /// # Errors
    /// Devuelve [`PluginError::Rpc`] o [`PluginError::Timeout`].
    pub async fn schema(&self) -> Result<Vec<Field>, PluginError> {
        let mut grpc = self.grpc();
        let respuesta = self
            .con_plazo("schema", grpc.schema(SchemaRequest {}))
            .await?;
        Ok(respuesta.fields)
    }

    /// Entrega la configuración ya validada y con los secretos resueltos.
    ///
    /// # Errors
    /// Devuelve [`PluginError::Rpc`] si el plugin rechaza la configuración
    /// —ahí va el motivo— o [`PluginError::Timeout`].
    pub async fn configure(&self, config: HashMap<String, Value>) -> Result<(), PluginError> {
        let mut grpc = self.grpc();
        self.con_plazo("configure", grpc.configure(ConfigureRequest { config }))
            .await?;
        Ok(())
    }

    /// Comprobación de conectividad, permisos y dependencias.
    ///
    /// Que el informe venga con `ok: false` **no** es un error de esta función:
    /// es su respuesta, y es justo lo que `doctor` tiene que enseñarle al
    /// usuario. Solo falla si el plugin no llega a contestar.
    ///
    /// # Errors
    /// Devuelve [`PluginError::Rpc`] o [`PluginError::Timeout`].
    pub async fn preflight(&self) -> Result<PreflightResponse, PluginError> {
        let mut grpc = self.grpc();
        self.con_plazo("preflight", grpc.preflight(PreflightRequest {}))
            .await
    }

    /// Cierra el plugin: primero se lo pide, luego se asegura.
    ///
    /// Que el RPC de cierre falle no es motivo de error —el plugin puede haber
    /// muerto ya, que es exactamente lo que se buscaba—, pero el proceso tiene
    /// que terminar sí o sí: se registra el fallo y se pasa al cierre del
    /// proceso, que mata al grupo entero y recoge al hijo.
    ///
    /// # Errors
    /// Devuelve [`PluginError::Proceso`] si la limpieza del proceso falla.
    pub async fn shutdown(self) -> Result<(), PluginError> {
        let mut grpc = self.grpc();
        if let Err(error) = self
            .con_plazo("shutdown", grpc.shutdown(ShutdownRequest {}))
            .await
        {
            tracing::debug!(
                plugin = %self.nombre(),
                %error,
                "el plugin no confirmó el cierre; se cierra por las bravas"
            );
        }
        // El canal se suelta antes de matar al proceso: si no, la conexión
        // abierta sobrevive al socket que ya no existe.
        drop(self.canal);
        self.proceso.shutdown().await?;
        Ok(())
    }

    /// Mata al plugin de golpe, como si se hubiera caído solo.
    ///
    /// Existe para poder comprobar que hablar con un plugin muerto da un error
    /// y no un bloqueo. Manda `SIGKILL` al grupo entero: sin despedida, sin
    /// oportunidad de limpiar. No es una forma legítima de cerrar un plugin.
    #[doc(hidden)]
    pub fn matar_para_test(&self) {
        super::process::matar_al_grupo(self.proceso.pid());
    }

    /// Un cliente gRPC nuevo sobre el canal ya abierto.
    ///
    /// Se construye uno por llamada a propósito: el cliente generado necesita
    /// `&mut self` y el canal es barato de clonar, así que esto sale más
    /// barato que guardar un cliente tras un mutex y serializar las llamadas.
    fn grpc(&self) -> PluginGrpc<Channel> {
        PluginGrpc::new(self.canal())
    }

    /// El plazo y la traducción de errores, en un solo sitio.
    ///
    /// Repetir `tokio::time::timeout` en cada RPC es exactamente la clase de
    /// repetición que acaba con un método sin plazo: basta con olvidarlo una
    /// vez para que un plugin colgado deje el backup esperando para siempre.
    async fn con_plazo<T, F>(&self, operacion: &str, llamada: F) -> Result<T, PluginError>
    where
        F: Future<Output = Result<tonic::Response<T>, tonic::Status>>,
    {
        match tokio::time::timeout(PLAZO_RPC, llamada).await {
            Ok(Ok(respuesta)) => Ok(respuesta.into_inner()),
            Ok(Err(status)) => Err(PluginError::Rpc {
                plugin: self.nombre().to_string(),
                operacion: operacion.to_string(),
                mensaje: mensaje_de(&status),
            }),
            Err(_) => Err(PluginError::Timeout {
                plugin: self.nombre().to_string(),
                operacion: operacion.to_string(),
            }),
        }
    }
}

/// Lo que le queda al usuario de un `Status`.
///
/// El mensaje a secas es lo que el plugin quiso decir y es lo que hay que
/// enseñar; cuando viene vacío —le pasa a los errores de transporte, donde no
/// hay nadie al otro lado que redacte nada— el código es lo único que informa.
pub(crate) fn mensaje_de(status: &tonic::Status) -> String {
    if status.message().is_empty() {
        format!("{:?}", status.code())
    } else {
        format!("{:?}: {}", status.code(), status.message())
    }
}

/// Cierra un proceso cuyo arranque no llegó a buen puerto.
///
/// Un plugin al que no se le puede hablar no puede quedarse vivo: conserva en
/// memoria el material criptográfico de la sesión y no hay nadie que le vaya a
/// pedir nada nunca.
async fn cerrar_tras_un_fallo(proceso: PluginProcess, error: &PluginError) {
    tracing::warn!(plugin = %proceso.nombre(), %error, "no se pudo abrir el canal con el plugin");
    if let Err(fuente) = proceso.shutdown().await {
        tracing::warn!(%fuente, "y tampoco se pudo cerrar limpiamente");
    }
}

#[cfg(test)]
use crate::plugin::test_support::ruta_mock;

#[cfg(test)]
mod tests {
    use super::*;

    fn v_str(s: &str) -> sb_proto::Value {
        sb_proto::Value {
            kind: Some(sb_proto::value::Kind::StringValue(s.into())),
        }
    }
    #[expect(dead_code, reason = "los campos enteros del mock son opcionales")]
    fn v_int(i: i64) -> sb_proto::Value {
        sb_proto::Value {
            kind: Some(sb_proto::value::Kind::IntValue(i)),
        }
    }

    #[tokio::test]
    async fn conecta_y_pide_info() {
        let c = PluginClient::start("mock", &ruta_mock()).await.unwrap();
        let info = c.info().await.unwrap();
        assert_eq!(info.name, "mock");
        assert_eq!(info.protocol_version, sb_proto::PROTOCOL_VERSION);
        c.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn pide_el_esquema_y_trae_campos() {
        let c = PluginClient::start("mock", &ruta_mock()).await.unwrap();
        let campos = c.schema().await.unwrap();
        assert!(campos.iter().any(|f| f.name == "dir"));
        c.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn configura_y_hace_preflight() {
        let dir = tempfile::tempdir().unwrap();
        let c = PluginClient::start("mock", &ruta_mock()).await.unwrap();

        let mut cfg = std::collections::HashMap::new();
        cfg.insert("dir".to_string(), v_str(&dir.path().to_string_lossy()));
        c.configure(cfg).await.unwrap();

        let pre = c.preflight().await.unwrap();
        assert!(pre.ok, "el mock configurado debe pasar el preflight");
        c.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn el_preflight_sin_configurar_informa_en_vez_de_reventar() {
        // doctor necesita un informe, no una excepción: si el plugin no está
        // configurado, eso es justo lo que doctor debe contarle al usuario.
        let c = PluginClient::start("mock", &ruta_mock()).await.unwrap();
        let pre = c.preflight().await.unwrap();
        assert!(!pre.ok);
        assert!(!pre.checks.is_empty(), "debe explicar qué falta");
        c.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn declara_correctamente_sus_capacidades() {
        let c = PluginClient::start("mock", &ruta_mock()).await.unwrap();
        assert!(c.tiene_capacidad(Capacidad::Engine));
        assert!(c.tiene_capacidad(Capacidad::Storage));
        assert!(c.exigir_capacidad(Capacidad::Engine).is_ok());
        c.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn exigir_una_capacidad_ausente_da_un_error_que_la_nombra() {
        let c = PluginClient::start("mock", &ruta_mock()).await.unwrap();
        // El mock tiene ambas, así que se comprueba el mensaje con el tipo de error directamente.
        let err = PluginError::SinCapacidad {
            plugin: "postgres".into(),
            capacidad: "storage".into(),
        };
        let texto = err.to_string();
        assert!(texto.contains("postgres"));
        assert!(texto.contains("storage"));
        c.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn hablar_con_un_plugin_muerto_da_error_no_cuelgue() {
        let c = PluginClient::start("mock", &ruta_mock()).await.unwrap();
        c.matar_para_test();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let r = tokio::time::timeout(std::time::Duration::from_secs(5), c.info()).await;
        assert!(r.expect("no debe colgarse").is_err());
    }

    #[tokio::test]
    async fn un_error_del_plugin_nombra_el_plugin_y_la_operacion() {
        // Un error que solo dice "falló" obliga a adivinar cuál de los dos
        // plugins de un backup fue el que falló y en qué llamada.
        let err = PluginError::Rpc {
            plugin: "r2".into(),
            operacion: "configure".into(),
            mensaje: "bucket inexistente".into(),
        };
        let texto = err.to_string();
        assert!(texto.contains("r2"));
        assert!(texto.contains("configure"));
        assert!(texto.contains("bucket inexistente"));
    }

    #[tokio::test]
    async fn el_error_de_version_dice_ambas_versiones() {
        let err = PluginError::VersionIncompatible {
            plugin: "viejo".into(),
            del_plugin: 7,
            del_nucleo: 1,
        };
        let texto = err.to_string();
        assert!(texto.contains('7'), "la del plugin");
        assert!(texto.contains("viejo"));
    }

    #[tokio::test]
    async fn dos_clientes_simultaneos_funcionan() {
        // Un backup arranca motor y destino a la vez.
        let a = PluginClient::start("mock", &ruta_mock()).await.unwrap();
        let b = PluginClient::start("mock", &ruta_mock()).await.unwrap();
        assert_eq!(a.info().await.unwrap().name, "mock");
        assert_eq!(b.info().await.unwrap().name, "mock");
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn el_shutdown_ordenado_termina_el_proceso() {
        let c = PluginClient::start("mock", &ruta_mock()).await.unwrap();
        let pid = c.proceso().pid();
        c.shutdown().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "shutdown debe terminar el proceso"
        );
    }
}
