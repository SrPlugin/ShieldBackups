//! `sb-plugin-webhook`: a notifier that POSTs the outcome of a command to a URL.
//!
//! It exists so that `shieldbk` can tell Slack, Discord or a healthchecks.io
//! check that a backup ran (or did not) without the core knowing anything
//! about any of them.

mod config;
mod plugin;
mod send;

use sb_plugin_sdk::PluginRuntime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // One shared slot: `Configure` reaches the Plugin service and `Notify` reads
    // what it left behind.
    let state = config::State::new(plugin::NAME);
    PluginRuntime::new(plugin::WebhookPlugin::new(state.clone()))
        .with_notifier(plugin::WebhookNotifier::new(state))
        .serve()
        .await?;
    Ok(())
}
