//! La configuración que `Configure` deja y los servicios de datos leen.
//!
//! Un plugin no es un solo objeto: `Plugin`, `Engine` y `Storage` se registran
//! por separado, pero `Configure` solo llega al primero. Sin algo compartido,
//! cada plugin acaba escribiendo el mismo `Arc<Mutex<Option<Config>>>` y la
//! misma regla de «si aún no hay configuración, `failed_precondition`». Eso es
//! lo que vive aquí, una vez.

use std::sync::{Arc, Mutex, PoisonError};

use tonic::Status;

/// La configuración del plugin, compartida entre sus servicios.
///
/// `T` es la configuración **ya parseada y validada** por el plugin: el SDK no
/// puede parsearla, porque el esquema lo define cada plugin en su `Schema`. La
/// alternativa —guardar aquí el `HashMap<String, Value>` crudo— se descartó
/// porque obligaría a re-parsear en cada RPC de datos y haría que un campo mal
/// puesto se descubriera en mitad de un volcado en vez de en `Configure`, que
/// es el RPC que el núcleo llama precisamente para validar.
///
/// Se crea una vez y se clona en cada servicio; todos los clones ven el mismo
/// valor.
///
/// ```ignore
/// let config = Configurado::<MiConfig>::nuevo("postgres");
/// PluginRuntime::new(MiPlugin::new(config.clone()))
///     .con_motor(MiMotor::new(config))
///     .serve()
///     .await?;
/// ```
///
/// Antes de que `Configure` la escriba **no hay valores por defecto
/// silenciosos**: [`Configurado::resuelta`] falla. Un volcado que se escribiera
/// en un destino que nadie pidió es peor que un error claro.
pub struct Configurado<T> {
    /// Nombre del plugin, solo para que el error diga de quién habla.
    plugin: Option<&'static str>,
    valor: Arc<Mutex<Option<T>>>,
}

impl<T> Configurado<T> {
    /// Un hueco de configuración que se identifica con el nombre del plugin.
    ///
    /// El nombre solo sirve para el mensaje de error; darlo hace que el núcleo
    /// sepa **cuál** de los plugins que arrancó se quedó sin configurar.
    #[must_use]
    pub fn nuevo(plugin: &'static str) -> Self {
        Self {
            plugin: Some(plugin),
            valor: Arc::new(Mutex::new(None)),
        }
    }

    /// Guarda la configuración validada. La escribe `Configure`.
    ///
    /// Reconfigurar sustituye lo anterior: el núcleo puede llamar a `Configure`
    /// más de una vez y lo último que dijo es lo que vale.
    pub fn guardar(&self, valor: T) {
        // Un mutex envenenado significa que otro hilo panicó teniéndolo; el
        // dato de dentro sigue siendo un `Option<T>` válido, así que se recupera
        // en vez de propagar el pánico a todo el plugin.
        *self.valor.lock().unwrap_or_else(PoisonError::into_inner) = Some(valor);
    }

    /// Si ya se llamó a `Configure`.
    ///
    /// Para `Preflight`, que es el RPC de diagnóstico y debe **informar** de que
    /// falta configuración en vez de fallar por ello.
    #[must_use]
    pub fn esta_configurado(&self) -> bool {
        self.valor
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }
}

impl<T: Clone> Configurado<T> {
    /// La configuración actual.
    ///
    /// Es lo primero que hace cada RPC de datos: pedirla y propagar el error
    /// con `?` antes de tocar el canal.
    ///
    /// # Errors
    ///
    /// [`Status::failed_precondition`] si todavía no llegó `Configure`. El
    /// mensaje es **accionable a propósito**: dice quién no está configurado y
    /// qué llamada falta, porque quien lo va a leer es un operador mirando el
    /// log del núcleo, no el autor del plugin. Un plugin que sustituya este
    /// error por otro debe mantener esa propiedad.
    pub fn resuelta(&self) -> Result<T, Status> {
        self.valor
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| Status::failed_precondition(self.mensaje()))
    }

    fn mensaje(&self) -> String {
        match self.plugin {
            Some(p) => format!(
                "el plugin `{p}` aún no está configurado: llama a Configure con los campos que publica Schema antes de cualquier RPC de datos"
            ),
            None => "el plugin aún no está configurado: llama a Configure con los campos que publica Schema antes de cualquier RPC de datos".to_string(),
        }
    }
}

/// Clonar comparte el mismo valor: es lo que permite repartirlo entre los
/// servicios. Se implementa a mano porque derivarlo exigiría `T: Clone`, y
/// clonar el handle no clona la configuración.
impl<T> Clone for Configurado<T> {
    fn clone(&self) -> Self {
        Self {
            plugin: self.plugin,
            valor: Arc::clone(&self.valor),
        }
    }
}

/// Un plugin sin nombre declarado: el mensaje de error sale genérico pero sigue
/// diciendo qué llamada falta.
impl<T> Default for Configurado<T> {
    fn default() -> Self {
        Self {
            plugin: None,
            valor: Arc::new(Mutex::new(None)),
        }
    }
}

impl<T> std::fmt::Debug for Configurado<T> {
    /// No imprime el valor: la configuración de un plugin real lleva
    /// credenciales, y un `Debug` que las volcara al log sería una fuga.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Configurado")
            .field("plugin", &self.plugin.unwrap_or("<sin nombre>"))
            .field("configurado", &self.esta_configurado())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Config {
        dir: String,
    }

    #[test]
    fn sin_configure_falla_con_failed_precondition() {
        let e = Configurado::<Config>::nuevo("mock").resuelta().unwrap_err();
        assert_eq!(e.code(), Code::FailedPrecondition);
    }

    #[test]
    fn el_mensaje_dice_quien_falta_y_que_llamada_lo_arregla() {
        // Un código seco no le sirve al operador que lee el log del núcleo.
        let e = Configurado::<Config>::nuevo("postgres")
            .resuelta()
            .unwrap_err();
        assert!(e.message().contains("postgres"), "{}", e.message());
        assert!(e.message().contains("Configure"), "{}", e.message());
    }

    #[test]
    fn sin_nombre_el_mensaje_sigue_diciendo_que_falta_configure() {
        let e = Configurado::<Config>::default().resuelta().unwrap_err();
        assert!(e.message().contains("Configure"), "{}", e.message());
    }

    #[test]
    fn tras_guardar_devuelve_lo_guardado() {
        let c = Configurado::nuevo("mock");
        c.guardar(Config {
            dir: "/tmp/x".into(),
        });
        assert_eq!(c.resuelta().unwrap().dir, "/tmp/x");
    }

    #[test]
    fn los_clones_ven_la_configuracion_que_escribio_otro() {
        // La razón de existir del tipo: `Configure` llega al servicio Plugin y
        // la leen Engine y Storage, que son valores distintos.
        let plugin = Configurado::nuevo("mock");
        let motor = plugin.clone();
        let destino = plugin.clone();

        assert!(motor.resuelta().is_err());
        plugin.guardar(Config {
            dir: "/datos".into(),
        });

        assert_eq!(motor.resuelta().unwrap().dir, "/datos");
        assert_eq!(destino.resuelta().unwrap().dir, "/datos");
    }

    #[test]
    fn reconfigurar_sustituye_lo_anterior() {
        let c = Configurado::nuevo("mock");
        c.guardar(Config { dir: "/uno".into() });
        c.guardar(Config { dir: "/dos".into() });
        assert_eq!(c.resuelta().unwrap().dir, "/dos");
    }

    #[test]
    fn esta_configurado_distingue_el_antes_del_despues() {
        // Preflight lo necesita: debe informar de que falta configuración, no
        // fallar por ello.
        let c = Configurado::nuevo("mock");
        assert!(!c.esta_configurado());
        c.guardar(Config { dir: "/x".into() });
        assert!(c.esta_configurado());
    }

    #[test]
    fn el_debug_no_filtra_la_configuracion() {
        // La configuración de un plugin real lleva credenciales.
        let c = Configurado::nuevo("mock");
        c.guardar(Config {
            dir: "contrasena-secreta".into(),
        });
        assert!(!format!("{c:?}").contains("contrasena-secreta"));
    }
}
