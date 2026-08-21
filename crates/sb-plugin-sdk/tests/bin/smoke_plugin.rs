use sb_plugin_sdk::PluginRuntime;
use sb_plugin_sdk::sb_proto::plugin_server::Plugin;
use sb_plugin_sdk::sb_proto::{
    Capability, ConfigureRequest, ConfigureResponse, InfoRequest, InfoResponse, PreflightRequest,
    PreflightResponse, SchemaRequest, SchemaResponse, ShutdownRequest, ShutdownResponse,
};
use sb_plugin_sdk::tonic::{Request, Response, Status};

#[derive(Default)]
struct Minimo;

#[sb_plugin_sdk::tonic::async_trait]
impl Plugin for Minimo {
    async fn info(&self, _: Request<InfoRequest>) -> Result<Response<InfoResponse>, Status> {
        Ok(Response::new(InfoResponse {
            name: "minimo".into(),
            version: "0.1.0".into(),
            protocol_version: sb_plugin_sdk::sb_proto::PROTOCOL_VERSION,
            capabilities: vec![Capability::Engine as i32],
        }))
    }
    async fn schema(&self, _: Request<SchemaRequest>) -> Result<Response<SchemaResponse>, Status> {
        Ok(Response::new(SchemaResponse::default()))
    }
    async fn configure(
        &self,
        _: Request<ConfigureRequest>,
    ) -> Result<Response<ConfigureResponse>, Status> {
        Ok(Response::new(ConfigureResponse::default()))
    }
    async fn preflight(
        &self,
        _: Request<PreflightRequest>,
    ) -> Result<Response<PreflightResponse>, Status> {
        Ok(Response::new(PreflightResponse::default()))
    }
    async fn shutdown(
        &self,
        _: Request<ShutdownRequest>,
    ) -> Result<Response<ShutdownResponse>, Status> {
        Ok(Response::new(ShutdownResponse::default()))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    PluginRuntime::new(Minimo).serve().await?;
    Ok(())
}
