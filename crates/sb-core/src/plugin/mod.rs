//! Los plugins vistos desde el núcleo.
//!
//! Un plugin de shieldbk no es una biblioteca enlazada: es un **proceso
//! aparte** con el que se habla por gRPC sobre un socket Unix con mTLS. Este
//! módulo es el lado del núcleo de esa relación.

pub mod client;
pub mod process;

#[cfg(test)]
mod test_support;

pub use client::{Capacidad, PluginClient, PluginError};
pub use process::{PluginProcess, PluginProcessError};
