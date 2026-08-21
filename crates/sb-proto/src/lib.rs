//! Contrato entre el núcleo y los plugins.
//!
//! Este crate no contiene lógica: solo el código generado desde
//! `proto/shieldbk/v1/plugin.proto`, que es la fuente de verdad del protocolo.

/// Versión del protocolo que implementa esta compilación.
///
/// Se incrementa solo ante cambios que un plugin antiguo no pueda manejar.
/// Añadir campos a un mensaje **no** requiere subirla: protobuf lo tolera por
/// diseño, y ese es el motivo de haber elegido protobuf.
pub const PROTOCOL_VERSION: u32 = 1;

pub mod v1 {
    // El código generado no sigue nuestras convenciones de estilo.
    #![allow(clippy::pedantic, clippy::all)]

    tonic::include_proto!("shieldbk.v1");
}

pub use v1::*;
