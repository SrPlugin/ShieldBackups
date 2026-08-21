//! `sb-plugin-r2`: el destino de backups sobre Cloudflare R2.
//!
//! R2 habla el protocolo de S3, y de ahí que el plugin use el SDK de AWS. Lo
//! que no es de S3 —la región `auto`, el endpoint de cuenta, los checksums y
//! el tamaño uniforme de las partes— está aislado en `cliente` y `config`, con
//! el motivo escrito al lado.

mod cliente;
mod config;
mod plugin;
mod put;
mod storage;
mod trozos;

use sb_plugin_sdk::PluginRuntime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Un único estado compartido: `Configure` llega por el servicio Plugin y lo
    // lee el destino. Guarda la configuración y el cliente ya construido.
    let estado = cliente::Estado::nuevo(plugin::NOMBRE);
    PluginRuntime::new(plugin::PluginR2::new(estado.clone()))
        .con_destino(storage::DestinoR2::new(estado))
        .serve()
        .await?;
    Ok(())
}
