use std::{env, net::SocketAddr};

use mmap_loader::server::Server;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() > 4 {
        eprintln!(
            "Usage: {} <address:ipv4:0.0.0.0> <port:u16:42220> <cache_path:path:cache.json>",
            args[0]
        );
        return Ok(());
    }
    let addr = args
        .get(1)
        .map(|str| str.as_str())
        .unwrap_or("0.0.0.0")
        .parse()?;
    let port = args
        .get(2)
        .map(|str| str.as_str())
        .unwrap_or("42220")
        .parse()?;
    let cache_path = args.get(3).map(|str| str.as_str()).unwrap_or("cache.json");
    let server = Server::new(SocketAddr::new(addr, port), cache_path)?;
    server.run().await
}
