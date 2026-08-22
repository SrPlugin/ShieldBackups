//! El proceso del plugin de R2. Todo lo que hace vive en la librería
//! [`sb_plugin_r2`]; aquí solo se monta el runtime del SDK.

use sb_plugin_r2::{cliente, plugin, storage};
use sb_plugin_sdk::PluginRuntime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Un único estado compartido: `Configure` llega por el servicio Plugin y lo
    // lee el destino. Guarda la configuración y el cliente ya construido.
    let estado = cliente::Estado::new(plugin::NOMBRE);
    PluginRuntime::new(plugin::PluginR2::new(estado.clone()))
        .with_storage(storage::DestinoR2::new(estado))
        .serve()
        .await?;
    Ok(())
}
