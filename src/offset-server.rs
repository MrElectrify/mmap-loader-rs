#![feature(option_result_contains)]

use std::{env, net::SocketAddr};

use mmap_loader::server::Server;
use tonic::transport::Identity;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    // they must specify both cert and key if they want TLS
    if args.len() > 6 || args.len() == 5 || args.get(1).contains(&"-help") {
        eprintln!(
            "Usage: {} <address:ip:0.0.0.0> <port:u16:42220> <cache_path:path:cache.json> <cert_path:opt<path>> <key_path:opt<path>>",
            args[0]
        );
        return;
    }
    let addr = args
        .get(1)
        .map(|str| str.as_str())
        .unwrap_or("0.0.0.0")
        .parse()
        .expect("Failed to parse IP");
    let port = args
        .get(2)
        .map(|str| str.as_str())
        .unwrap_or("443")
        .parse()
        .expect("Failed to parse port");
    let cache_path = args.get(3).map(|str| str.as_str()).unwrap_or("cache.json");
    let tls_identity = match args.len() {
        6 => {
            let cert = tokio::fs::read(&args[4])
                .await
                .expect("Failed to read cert");
            let key = tokio::fs::read(&args[5])
                .await
                .expect("Failed to read cert");
            Some(Identity::from_pem(cert, key))
        }
        _ => None,
    };
    let server = Server::new(
        SocketAddr::new(addr, port),
        cache_path,
        tls_identity,
    )
    .expect("Failed to start server");
    server.run().await.expect("Failed to run server");
}
