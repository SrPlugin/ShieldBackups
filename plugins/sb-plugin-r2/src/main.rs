//! The R2 plugin's process. Everything it does lives in the [`sb_plugin_r2`]
//! library; here only the SDK runtime is wired up.

use sb_plugin_r2::{client, plugin, storage};
use sb_plugin_sdk::PluginRuntime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A single shared state: `Configure` arrives through the Plugin service and
    // the storage target reads it. It holds the configuration and the already
    // built client.
    let state = client::State::new(plugin::NAME);
    PluginRuntime::new(plugin::R2Plugin::new(state.clone()))
        .with_storage(storage::R2Storage::new(state))
        .serve()
        .await?;
    Ok(())
}
