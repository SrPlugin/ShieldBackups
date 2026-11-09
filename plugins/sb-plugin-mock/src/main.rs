//! `sb-plugin-mock`: a plugin that is a source, a storage target, a notifier and a
//! drill.
//!
//! It exists so that the core -- pipeline, orchestration and CLI -- can be
//! tested end to end without a database, without the network and without
//! credentials. The source generates deterministic bytes from a seed and the
//! storage target saves them in a directory, so a test can regenerate exactly
//! what the source produced -- `sb_plugin_mock::deterministic_data` -- and
//! compare it byte for byte.

mod config;
mod drill;
mod keys;
mod notifier;
mod plugin;
mod source;
mod storage;
mod stream;

use sb_plugin_sdk::PluginRuntime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A single shared state: `Configure` arrives through the Plugin service and
    // the source, the storage target, the notifier and the drill read it. Without
    // it, each service would have its own idea of where `dir` is.
    let state = config::State::new(plugin::NAME);
    // The source and the drill also share where a restore lands: the drill moves
    // it to a scratch directory between `Provision` and `Teardown`.
    let scratch = drill::Scratch::default();
    PluginRuntime::new(plugin::MockPlugin::new(state.clone()))
        .with_source(source::MockSource::new(state.clone(), scratch.clone()))
        .with_storage(storage::MockStorage::new(state.clone()))
        .with_notifier(notifier::MockNotifier::new(state.clone()))
        .with_drill(drill::MockDrill::new(state, scratch))
        .serve()
        .await?;
    Ok(())
}
