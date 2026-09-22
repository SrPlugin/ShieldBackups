//! `sb-plugin-postgres`: a source that wraps `pg_dump`/`pg_restore`.

use sb_plugin_postgres::config;
use sb_plugin_postgres::plugin::{self, PostgresPlugin};
use sb_plugin_postgres::source::PostgresSource;
use sb_plugin_sdk::PluginRuntime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A single shared state: `Configure` arrives through the Plugin service
    // and the source reads it. Without it, the source would have no way to
    // learn what `Configure` said.
    let state = config::State::new(plugin::NAME);
    PluginRuntime::new(PostgresPlugin::new(state.clone()))
        .with_source(PostgresSource::new(state))
        .serve()
        .await?;
    Ok(())
}
