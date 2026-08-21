//! Lo que necesita un plugin de `ShieldBackups` escrito en Rust.
//!
//! Un plugin completo son unas cien líneas: implementar los traits generados y
//! llamar a [`PluginRuntime::serve`]. Lo que todos los plugins comparten está
//! aquí para que ninguno lo reescriba:
//!
//! - [`PluginRuntime`] arranca el proceso y lo termina cuando el núcleo llama a
//!   `Shutdown`, que el SDK intercepta.
//! - [`Configurado`] guarda la configuración que `Configure` deja y que los
//!   servicios de datos leen, con el `failed_precondition` ya escrito.
//! - [`stream_de_progreso`] pone el armazón de los RPC que mueven bytes.

mod cierre;
pub mod configurado;
pub mod progreso;
pub mod runtime;

pub use configurado::Configurado;
pub use progreso::{EmisorProgreso, ProgresoStream, stream_de_progreso};
pub use runtime::{PluginRuntime, SdkError};

// Reexportados para que un plugin no tenga que declarar sb-proto ni tonic.
pub use sb_proto;
pub use tonic;

/// Abre el canal de datos que el núcleo creó para una transferencia.
///
/// Se reexporta desde `sb-transport` porque la necesitan todos los plugins que
/// mueven bytes, y hacerles declarar el crate del transporte por una sola
/// función iría en contra de que el SDK sea lo único que un plugin depende.
pub use sb_transport::connect_data;
