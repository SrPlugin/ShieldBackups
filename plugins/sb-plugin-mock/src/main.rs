//! `sb-plugin-mock`: un plugin que es motor y destino a la vez.
//!
//! Existe para que el núcleo —pipeline, orquestación y CLI— se pueda probar
//! entero sin base de datos, sin red y sin credenciales. El motor genera bytes
//! deterministas desde una semilla y el destino los guarda en un directorio,
//! así que un test puede regenerar exactamente lo que el motor produjo
//! —`sb_plugin_mock::datos_deterministas`— y compararlo byte a byte.

mod claves;
mod config;
mod engine;
mod flujo;
mod plugin;
mod storage;

use sb_plugin_sdk::PluginRuntime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Un único estado compartido: `Configure` llega por el servicio Plugin y
    // lo leen el motor y el destino. Sin él, cada servicio tendría su propia
    // idea de dónde está `dir`.
    let estado = config::Estado::nuevo(plugin::NOMBRE);
    PluginRuntime::new(plugin::PluginMock::new(estado.clone()))
        .con_motor(engine::MotorMock::new(estado.clone()))
        .con_destino(storage::DestinoMock::new(estado))
        .serve()
        .await?;
    Ok(())
}
