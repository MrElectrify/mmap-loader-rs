pub mod offset_server {
    tonic::include_proto!("mmap");
}

use tonic::{transport::Server, Request, Response, Status};
use offset_server::offset_server::{Offset, OffsetServer};
use offset_server::{OffsetsRequest, OffsetsResponse};

#[derive(Debug, Default)]
struct OffsetHandler {}

#[tonic::async_trait]
impl Offset for OffsetHandler {
    async fn get_offsets(&self, request: Request<OffsetsRequest>) -> Result<Response<OffsetsResponse>, Status> {
        println!("Request: {:?}", request);
        Err(Status::not_found("The hash was not found"))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "0.0.0.0:37756".parse()?;
    let offset_handler = OffsetHandler::default();
    Server::builder()
        .add_service(OffsetServer::new(offset_handler))
        .serve(addr)
        .await?;
    Ok(())
}