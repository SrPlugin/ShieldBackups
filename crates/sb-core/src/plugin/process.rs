//! Arranque y ciclo de vida de un plugin como proceso hijo.
//!
//! El núcleo lanza cada plugin como un proceso aparte, le entrega por stdin el
//! sobre con el material TLS de la sesión y espera su anuncio por stdout. A
//! partir de ahí el plugin escucha en un socket Unix con mTLS y el núcleo le
//! habla por gRPC.
//!
//! Este módulo es el lado del núcleo de ese arranque, y es donde se
//! materializan tres garantías que no son higiene sino seguridad:
//!
//! * **El hijo no hereda el entorno del núcleo.** Si el núcleo tiene
//!   `PGPASSWORD` o `AWS_SECRET_ACCESS_KEY` en su entorno, un plugin que las
//!   heredara tendría credenciales que nadie le dio —y el entorno de un
//!   proceso es legible en `/proc/<pid>/environ` por cualquiera que pueda
//!   leerlo—.
//! * **El plugin vive en su propio grupo de procesos.** El plugin de
//!   `PostgreSQL` lanzará `pg_dump` como nieto del núcleo; matar solo al plugin
//!   dejaría a `pg_dump` huérfano, consumiendo recursos del servidor de base
//!   de datos y con una transacción abierta.
//! * **La limpieza está garantizada.** Un proceso huérfano conserva en memoria
//!   el material criptográfico de la sesión.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{DirBuilder, Permissions};
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sb_transport::{Bootstrap, EphemeralPki, HandshakeError, PkiError, READY_TIMEOUT_MS, Ready};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

/// Las únicas variables de entorno que un plugin recibe del núcleo.
///
/// La lista es corta a propósito: es más fácil razonar sobre lo que se deja
/// pasar que sobre lo que se filtra. `PATH` porque un plugin necesita
/// encontrar las herramientas que envuelve (`pg_dump`, `mysqldump`), `HOME` y
/// `TMPDIR` porque muchas bibliotecas las dan por hechas, y `LANG`/`TZ` porque
/// sin ellas las fechas y los mensajes salen en otro idioma que el operador no
/// espera.
const VARIABLES_HEREDADAS: [&str; 5] = ["PATH", "HOME", "TMPDIR", "LANG", "TZ"];

/// `PATH` que se usa si el núcleo no tenía ninguno.
///
/// Sin `PATH` un plugin no puede ni ejecutar `pg_dump`. Se prefiere un valor
/// mínimo y explícito a heredar la ausencia.
const PATH_POR_DEFECTO: &str = "/usr/local/bin:/usr/bin:/bin";

/// Permisos del directorio donde vive el socket de control.
///
/// `0700`: el socket es la puerta de entrada al plugin y quien pueda abrirlo
/// habla con él. El mTLS lo protege de todas formas, pero dos cerraduras son
/// mejor que una.
const MODO_PRIVADO: u32 = 0o700;

/// Distingue directorios de plugins arrancados por el mismo núcleo.
///
/// Un backup usa motor y destino a la vez: dos plugins vivos que no pueden
/// compartir socket. El pid del núcleo separa ejecuciones distintas y este
/// contador separa los plugins de una misma ejecución.
static SIGUIENTE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
pub enum PluginProcessError {
    #[error("no se pudo arrancar el plugin «{nombre}» desde {binario}: {fuente}")]
    NoSePudoArrancar {
        nombre: String,
        binario: String,
        #[source]
        fuente: std::io::Error,
    },
    #[error("no se pudo preparar el directorio de ejecución {dir}: {fuente}")]
    DirectorioDeEjecucion {
        dir: String,
        #[source]
        fuente: std::io::Error,
    },
    #[error("no se pudo generar el material criptográfico de la sesión: {0}")]
    Pki(#[from] PkiError),
    /// El plugin no llegó a anunciarse: o se quedó callado hasta agotar el
    /// plazo, o murió sin escribir nada. Se tratan igual a propósito —desde el
    /// núcleo son el mismo suceso, «este binario no es un plugin que funcione»—
    /// y la diferencia queda registrada en el log junto al stderr del proceso,
    /// que es donde sirve para depurar.
    #[error("el plugin no se anunció dentro del plazo de arranque")]
    TimeoutHandshake,
    #[error("el anuncio del plugin no es válido: {0}")]
    Anuncio(#[from] HandshakeError),
    #[error("fallo de entrada/salida hablando con el plugin: {0}")]
    Io(#[from] std::io::Error),
}

/// Un plugin arrancado y anunciado, con su proceso bajo control.
///
/// Mientras este handle exista, el proceso existe. Cuando se destruye —por
/// `shutdown` o por `Drop`—, el plugin y todos sus descendientes mueren y su
/// directorio de ejecución desaparece.
pub struct PluginProcess {
    nombre: String,
    pid: u32,
    protocol_version: u32,
    capabilities: Vec<String>,
    runtime_dir: PathBuf,
    control_socket: PathBuf,
    pki: EphemeralPki,
    entorno: BTreeMap<String, String>,
    /// `None` solo después de `shutdown`, que se lleva el hijo para recogerlo.
    hijo: Option<Child>,
}

/// `Debug` escrito a mano y redactado: este struct guarda la PKI de la sesión,
/// que incluye dos claves privadas. `EphemeralPki` no implementa `Debug` a
/// propósito, así que aquí se imprime como `<redactado>`: el handle se puede
/// volcar a un log de depuración del arranque sin que salga nada privado.
impl fmt::Debug for PluginProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginProcess")
            .field("nombre", &self.nombre)
            .field("pid", &self.pid)
            .field("protocol_version", &self.protocol_version)
            .field("capabilities", &self.capabilities)
            .field("runtime_dir", &self.runtime_dir)
            .field("control_socket", &self.control_socket)
            .field("pki", &"<redactado>")
            .field("entorno", &self.entorno)
            .field("hijo", &self.hijo)
            .finish()
    }
}

impl PluginProcess {
    /// Arranca el binario de un plugin y espera a que se anuncie.
    ///
    /// Genera una PKI efímera para esta sesión, crea un directorio privado
    /// para el socket de control, lanza el proceso con un entorno mínimo y en
    /// su propio grupo, le entrega el sobre por stdin y espera su `Ready`.
    ///
    /// Si algo falla en cualquier punto —incluido el plazo de arranque— el
    /// proceso se mata **y se recoge**, y el directorio se borra, antes de
    /// devolver el error: un arranque fallido no puede dejar residuos.
    ///
    /// # Errors
    /// Devuelve [`PluginProcessError::NoSePudoArrancar`] si el binario no se
    /// puede ejecutar, [`PluginProcessError::TimeoutHandshake`] si no se
    /// anuncia a tiempo, y los errores de PKI, entrada/salida o anuncio
    /// inválido correspondientes.
    pub async fn spawn(nombre: &str, binario: &Path) -> Result<Self, PluginProcessError> {
        let pki = EphemeralPki::generate()?;
        let runtime_dir = crear_directorio_privado()?;
        let control_socket = runtime_dir.join("control.sock");
        let entorno = entorno_minimo();

        let mut hijo = match lanzar(binario, &entorno) {
            Ok(hijo) => hijo,
            Err(fuente) => {
                // El directorio se creó antes de saber que el binario no
                // existe: no puede quedarse ahí.
                borrar_directorio(&runtime_dir);
                return Err(PluginProcessError::NoSePudoArrancar {
                    nombre: nombre.to_string(),
                    binario: binario.display().to_string(),
                    fuente,
                });
            }
        };

        // El pid solo está disponible mientras no se haya recogido al hijo, y
        // se necesita después para matar al grupo entero. Recién lanzado
        // siempre lo hay; el 0 del caso imposible es inofensivo porque
        // `matar_al_grupo` lo descarta antes de señalar nada.
        let pid = hijo.id().unwrap_or_default();
        let entrada = hijo.stdin.take();
        let salida = hijo.stdout.take();
        reemitir_stderr(nombre, hijo.stderr.take());

        let sobre = Bootstrap::nuevo(
            vec![sb_proto::PROTOCOL_VERSION],
            control_socket.display().to_string(),
            pki.server_bundle(),
        );

        let mut proceso = Self {
            nombre: nombre.to_string(),
            pid,
            protocol_version: 0,
            capabilities: Vec::new(),
            runtime_dir,
            control_socket,
            pki,
            entorno,
            hijo: Some(hijo),
        };

        match esperar_anuncio(&sobre, entrada, salida).await {
            Ok(ready) => {
                tracing::info!(
                    plugin = %proceso.nombre,
                    pid,
                    protocol_version = ready.protocol_version,
                    "plugin arrancado"
                );
                proceso.protocol_version = ready.protocol_version;
                proceso.capabilities = ready.capabilities;
                Ok(proceso)
            }
            Err(error) => {
                tracing::warn!(plugin = %proceso.nombre, pid, %error, "el plugin no arrancó");
                proceso.matar_y_recoger().await;
                Err(error)
            }
        }
    }

    #[must_use]
    pub fn nombre(&self) -> &str {
        &self.nombre
    }

    /// Pid del proceso del plugin, que es también el de su grupo.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Versión del protocolo que el plugin declaró hablar.
    #[must_use]
    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// Lo que el plugin dice saber hacer: `engine`, `storage` o ambas.
    #[must_use]
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Directorio privado donde vive el socket de control.
    #[must_use]
    pub fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    /// Socket por el que se habla gRPC con el plugin.
    #[must_use]
    pub fn control_socket(&self) -> &Path {
        &self.control_socket
    }

    /// PKI de esta sesión: de aquí sale la configuración de cliente con la que
    /// el núcleo se conecta al canal de control.
    #[must_use]
    pub fn pki(&self) -> &EphemeralPki {
        &self.pki
    }

    /// El entorno exacto con el que se lanzó el hijo.
    ///
    /// Se guarda —en vez de deducirlo— para que sea comprobable: lo que este
    /// mapa no contenga, el plugin no lo tiene.
    #[must_use]
    pub fn entorno_del_hijo(&self) -> &BTreeMap<String, String> {
        &self.entorno
    }

    /// Cierra el plugin: mata al grupo entero, **recoge** al hijo y borra el
    /// directorio de ejecución.
    ///
    /// Recoger al hijo no es opcional: un proceso al que nadie hace `wait`
    /// queda zombie en la tabla de procesos, y con un backup por hora se
    /// acumulan.
    ///
    /// # Errors
    /// Hoy no falla —los fallos de la limpieza se registran y se ignoran,
    /// porque no hay nada mejor que hacer con ellos—, pero devuelve `Result`
    /// para que un cierre ordenado por gRPC pueda informar de su fallo sin
    /// cambiar a todos los que llaman.
    pub async fn shutdown(mut self) -> Result<(), PluginProcessError> {
        self.matar_y_recoger().await;
        Ok(())
    }

    /// Mata al grupo, recoge al hijo y borra el directorio. Idempotente.
    async fn matar_y_recoger(&mut self) {
        matar_al_grupo(self.pid);
        if let Some(mut hijo) = self.hijo.take() {
            // Que `start_kill` falle porque ya había muerto no importa: lo que
            // cuenta es el `wait`.
            let _ = hijo.start_kill();
            if let Err(fuente) = hijo.wait().await {
                tracing::warn!(plugin = %self.nombre, pid = self.pid, %fuente, "no se pudo recoger al plugin");
            }
        }
        borrar_directorio(&self.runtime_dir);
    }
}

/// Red de seguridad ante pánicos y salidas por atajo.
///
/// En `Drop` no se puede esperar a nada, así que esto es lo mejor que se puede
/// hacer sin bloquear: la señal al grupo se manda igual —es una llamada al
/// sistema, no una espera— y la recogida del hijo queda en manos de
/// `kill_on_drop`, que tokio resuelve en su cola de huérfanos.
impl Drop for PluginProcess {
    fn drop(&mut self) {
        if let Some(mut hijo) = self.hijo.take() {
            matar_al_grupo(self.pid);
            let _ = hijo.start_kill();
        }
        borrar_directorio(&self.runtime_dir);
    }
}

/// Lanza el proceso del plugin con las tres tuberías bajo control.
fn lanzar(binario: &Path, entorno: &BTreeMap<String, String>) -> std::io::Result<Child> {
    let mut orden = Command::new(binario);
    // El entorno del núcleo no viaja: se parte de cero y se añade lo mínimo.
    orden.env_clear();
    orden.envs(entorno);
    orden
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Si el núcleo entra en pánico entre el spawn y el shutdown, el plugin no
    // le sobrevive.
    orden.kill_on_drop(true);
    // Grupo de procesos propio (`setpgid(0, 0)`): el plugin de
    // `PostgreSQL`
    // lanzará `pg_dump` como nieto del núcleo, y al abortar hay que poder
    // matarlos juntos. Matar solo al plugin dejaría un `pg_dump` huérfano con
    // una transacción abierta contra la base de datos de producción.
    //
    // `process_group` es seguro; `pre_exec`, que sería la otra forma de hacer
    // esto, no lo es —y el workspace prohíbe `unsafe`—.
    orden.process_group(0);
    orden.spawn()
}

/// Entrega el sobre, cierra el stdin y espera el anuncio con plazo.
async fn esperar_anuncio(
    sobre: &Bootstrap,
    entrada: Option<ChildStdin>,
    salida: Option<ChildStdout>,
) -> Result<Ready, PluginProcessError> {
    let entrada =
        entrada.ok_or_else(|| std::io::Error::other("el plugin se lanzó sin stdin propio"))?;
    enviar_sobre(sobre, entrada).await?;

    let salida =
        salida.ok_or_else(|| std::io::Error::other("el plugin se lanzó sin stdout propio"))?;
    let mut lector = BufReader::new(salida);
    let mut linea = String::new();
    let leidos = tokio::time::timeout(
        Duration::from_millis(READY_TIMEOUT_MS),
        lector.read_line(&mut linea),
    )
    .await
    .map_err(|_| PluginProcessError::TimeoutHandshake)??;

    if leidos == 0 {
        // Fin de fichero: el proceso murió sin anunciarse. Para el núcleo es
        // el mismo suceso que el silencio, y llega antes.
        return Err(PluginProcessError::TimeoutHandshake);
    }
    Ok(Ready::from_line(&linea)?)
}

/// Escribe el sobre de arranque y **cierra** el stdin del hijo.
///
/// Cerrarlo es parte del contrato: el plugin ya tiene todo lo que necesita, y
/// un stdin abierto es un canal por el que nadie va a hablar.
///
/// Un fallo al escribir no se propaga tal cual porque casi siempre significa
/// que el proceso ya había muerto —una tubería rota—; el diagnóstico bueno lo
/// da la espera del anuncio, que verá el fin de fichero, junto al stderr que
/// se está reemitiendo.
async fn enviar_sobre(
    sobre: &Bootstrap,
    mut entrada: ChildStdin,
) -> Result<(), PluginProcessError> {
    let linea = sobre.to_line()?;
    let escritura = async {
        entrada.write_all(linea.as_bytes()).await?;
        entrada.write_all(b"\n").await?;
        entrada.flush().await
    }
    .await;
    if let Err(fuente) = escritura {
        tracing::debug!(%fuente, "no se pudo entregar el sobre de arranque");
    }
    drop(entrada);
    Ok(())
}

/// Lee el stderr del plugin y lo reemite al log del núcleo.
///
/// Sin esto, un plugin que falla lo hace en silencio: su stderr es una tubería
/// que nadie lee y el operador solo ve «el plugin no arrancó».
fn reemitir_stderr(nombre: &str, stderr: Option<ChildStderr>) {
    let Some(stderr) = stderr else { return };
    let nombre = nombre.to_string();
    tokio::spawn(async move {
        let mut lineas = BufReader::new(stderr).lines();
        while let Ok(Some(linea)) = lineas.next_line().await {
            tracing::info!(plugin = %nombre, "{linea}");
        }
    });
}

/// El entorno con el que se lanza un plugin: lo mínimo, y nada más.
fn entorno_minimo() -> BTreeMap<String, String> {
    let mut entorno = BTreeMap::new();
    for clave in VARIABLES_HEREDADAS {
        if let Ok(valor) = std::env::var(clave) {
            entorno.insert(clave.to_string(), valor);
        }
    }
    entorno
        .entry("PATH".to_string())
        .or_insert_with(|| PATH_POR_DEFECTO.to_string());
    entorno
}

/// Crea el directorio privado donde vivirá el socket de control.
///
/// Bajo `XDG_RUNTIME_DIR` si existe —está en un tmpfs propio del usuario y las
/// rutas son cortas, que importa porque un socket Unix no admite más de 108
/// bytes de ruta—, y si no bajo el temporal del sistema. El modo se pide al
/// crear, no después: entre crear y corregir hay una ventana en la que el
/// directorio sería legible por otros.
fn crear_directorio_privado() -> Result<PathBuf, PluginProcessError> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|d| d.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let n = SIGUIENTE.fetch_add(1, Ordering::Relaxed);
    let dir = base.join(format!("shieldbk-{}-{n}", std::process::id()));

    DirBuilder::new()
        .mode(MODO_PRIVADO)
        .create(&dir)
        .map_err(|fuente| PluginProcessError::DirectorioDeEjecucion {
            dir: dir.display().to_string(),
            fuente,
        })?;
    // El `umask` del proceso solo puede quitar permisos, nunca añadirlos, así
    // que esto no relaja nada; está para que el modo sea exactamente 0700
    // aunque alguien haya heredado un umask raro.
    std::fs::set_permissions(&dir, Permissions::from_mode(MODO_PRIVADO)).map_err(|fuente| {
        PluginProcessError::DirectorioDeEjecucion {
            dir: dir.display().to_string(),
            fuente,
        }
    })?;
    Ok(dir)
}

/// Borra el directorio de ejecución. Best-effort: si no se puede, se registra.
fn borrar_directorio(dir: &Path) {
    if let Err(fuente) = std::fs::remove_dir_all(dir)
        && fuente.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(dir = %dir.display(), %fuente, "no se pudo borrar el directorio del plugin");
    }
}

/// Manda `SIGKILL` al grupo de procesos del plugin.
///
/// Al grupo, no al proceso: es lo que se lleva por delante a los nietos. Como
/// el plugin se lanzó con `process_group(0)`, el identificador del grupo es su
/// propio pid, y el núcleo —que está en otro grupo— no se mata a sí mismo.
pub(crate) fn matar_al_grupo(pid: u32) {
    let Ok(crudo) = i32::try_from(pid) else {
        return;
    };
    let Some(objetivo) = rustix::process::Pid::from_raw(crudo) else {
        return;
    };
    if let Err(fuente) =
        rustix::process::kill_process_group(objetivo, rustix::process::Signal::KILL)
    {
        // `ESRCH` es lo normal cuando el plugin ya había terminado solo.
        tracing::debug!(pid, %fuente, "no se pudo señalar al grupo del plugin");
    }
}

#[cfg(test)]
#[allow(
    clippy::for_kv_map,
    clippy::items_after_statements,
    reason = "estos tests describen el contrato tal y como se leería en una revisión; recorrer el mapa por pares deja a la vista que se inspeccionan las claves de un entorno, y el `use` junto a la comprobación de permisos mantiene el motivo al lado del assert"
)]
mod tests {
    use super::*;
    use crate::plugin::test_support::ruta_mock;

    #[tokio::test]
    async fn arranca_un_plugin_y_completa_el_handshake() {
        let p = PluginProcess::spawn("mock", &ruta_mock()).await.unwrap();
        assert_eq!(p.protocol_version(), sb_proto::PROTOCOL_VERSION);
        assert!(p.capabilities().contains(&"engine".to_string()));
        assert!(p.capabilities().contains(&"storage".to_string()));
        p.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn el_hijo_no_hereda_el_entorno_del_nucleo() {
        // Si el núcleo tiene PGPASSWORD en su entorno, un plugin que lo
        // heredara tendría credenciales que nadie le dio. Y el entorno de un
        // proceso es legible en /proc/<pid>/environ.
        let p = PluginProcess::spawn("mock", &ruta_mock()).await.unwrap();
        let entorno = p.entorno_del_hijo();
        assert!(!entorno.contains_key("SHIELDBK_VARIABLE_QUE_NO_DEBE_HEREDARSE"));
        assert!(
            entorno.contains_key("PATH"),
            "pero sí lo mínimo para funcionar"
        );
        assert!(
            entorno.len() <= 6,
            "el entorno debe ser mínimo, tiene {}",
            entorno.len()
        );
        p.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn el_entorno_del_hijo_no_contiene_nada_que_parezca_un_secreto() {
        let p = PluginProcess::spawn("mock", &ruta_mock()).await.unwrap();
        for (clave, _) in p.entorno_del_hijo() {
            let c = clave.to_uppercase();
            assert!(
                !c.contains("PASSWORD")
                    && !c.contains("SECRET")
                    && !c.contains("TOKEN")
                    && !c.contains("KEY")
                    && !c.contains("CREDENTIAL"),
                "variable sospechosa en el entorno del plugin: {clave}"
            );
        }
        p.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn un_binario_inexistente_da_un_error_claro() {
        let err = PluginProcess::spawn("fantasma", std::path::Path::new("/no/existe/plugin"))
            .await
            .unwrap_err();
        assert!(matches!(err, PluginProcessError::NoSePudoArrancar { .. }));
        let texto = err.to_string();
        assert!(texto.contains("fantasma"), "debe nombrar el plugin");
        assert!(
            texto.contains("/no/existe/plugin"),
            "y decir dónde lo buscó"
        );
    }

    #[tokio::test]
    async fn un_binario_que_no_habla_el_protocolo_vence_por_tiempo() {
        let inicio = std::time::Instant::now();
        let err = PluginProcess::spawn("dormilon", std::path::Path::new("/bin/sleep"))
            .await
            .unwrap_err();
        assert!(matches!(err, PluginProcessError::TimeoutHandshake));
        assert!(
            inicio.elapsed() < std::time::Duration::from_secs(60),
            "el timeout debe ser acotado"
        );
    }

    #[tokio::test]
    async fn al_destruir_el_proceso_el_hijo_muere() {
        let pid = {
            let p = PluginProcess::spawn("mock", &ruta_mock()).await.unwrap();
            p.pid()
        };
        for _ in 0..100 {
            if !proceso_vivo(pid) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            !proceso_vivo(pid),
            "el plugin no debe sobrevivir a su handle"
        );
    }

    #[tokio::test]
    async fn el_directorio_de_sockets_es_privado_y_se_borra() {
        let dir = {
            let p = PluginProcess::spawn("mock", &ruta_mock()).await.unwrap();
            let d = p.runtime_dir().to_path_buf();

            use std::os::unix::fs::PermissionsExt;
            let modo = std::fs::metadata(&d).unwrap().permissions().mode();
            assert_eq!(modo & 0o777, 0o700);

            p.shutdown().await.unwrap();
            d
        };
        assert!(!dir.exists(), "el directorio de sockets no debe sobrevivir");
    }

    #[tokio::test]
    async fn dos_plugins_simultaneos_no_comparten_directorio() {
        // Un backup usa motor y destino a la vez.
        let a = PluginProcess::spawn("mock", &ruta_mock()).await.unwrap();
        let b = PluginProcess::spawn("mock", &ruta_mock()).await.unwrap();
        assert_ne!(a.runtime_dir(), b.runtime_dir());
        assert_ne!(a.pid(), b.pid());
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn el_plugin_no_queda_zombie_tras_el_cierre() {
        // Un proceso al que no se le hace wait queda como zombie en la tabla
        // de procesos. Con un backup por hora, se acumulan.
        let p = PluginProcess::spawn("mock", &ruta_mock()).await.unwrap();
        let pid = p.pid();
        p.shutdown().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!es_zombie(pid), "el proceso quedó zombie");
    }

    /// Comprueba si un pid sigue vivo sin enviarle señal.
    fn proceso_vivo(pid: u32) -> bool {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }

    /// Comprueba si un pid está en estado zombie leyendo /proc.
    fn es_zombie(pid: u32) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| {
                s.rsplit(right_paren())
                    .next()
                    .map(|resto| resto.trim_start().starts_with('Z'))
            })
            .unwrap_or(false)
    }

    fn right_paren() -> char {
        ')'
    }
}
