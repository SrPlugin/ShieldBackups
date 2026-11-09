//! `sb-plugin-postgres`: a source that wraps `pg_dump`/`pg_restore`, and a drill that
//! wraps `psql`.

use sb_plugin_postgres::config;
use sb_plugin_postgres::drill::{PostgresDrill, Scratch};
use sb_plugin_postgres::plugin::{self, PostgresPlugin};
use sb_plugin_postgres::source::PostgresSource;
use sb_plugin_sdk::PluginRuntime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A single shared state: `Configure` arrives through the Plugin service
    // and the source reads it. Without it, the source would have no way to
    // learn what `Configure` said.
    let state = config::State::new(plugin::NAME);
    // The source and the drill also share which database a restore lands in: the
    // drill moves it to a scratch database between `Provision` and `Teardown`.
    let scratch = Scratch::default();
    PluginRuntime::new(PostgresPlugin::new(state.clone()))
        .with_source(PostgresSource::new(state.clone(), scratch.clone()))
        .with_drill(PostgresDrill::new(state, scratch))
        .serve()
        .await?;
    Ok(())
}
