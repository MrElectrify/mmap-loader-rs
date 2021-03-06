#![feature(option_result_contains)]

/// A little help for the offset server: generating a proper certificate can be annoying.
/// Rustls (at the time of writing) only likes v3 certificates. Follow this post on SF:
/// https://serverfault.com/a/979151. Essentially, create a CA request with a config,
/// self-sign it, maintain a CA database, and sign certificates through `openssl ca`.
/// Of course TLS is not really necessary at all here, because nothing particularly
/// private is sent over gRPC. I added it for cloudflare gRPC support, which pretty much
/// wants you to use TLS.
use std::{env, net::SocketAddr};

use mmap_loader::server::Server;
#[cfg(feature = "tls")]
use tonic::transport::Identity;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    // they must specify both cert and key if they want TLS
    #[cfg(feature = "tls")]
    if args.len() > 6 || args.len() == 5 || args.get(1).contains(&"-help") {
        eprintln!(
            "Usage: {} <address:ip:0.0.0.0> <port:u16:42220> <cache_path:path:cache.json> <cert_path:opt<path>> <key_path:opt<path>>",
            args[0]
        );
        return Ok(());
    }
    #[cfg(not(feature = "tls"))]
    if args.len() > 4 || args.get(1).contains(&"-help") {
        eprintln!(
            "Usage: {} <address:ip:0.0.0.0> <port:u16:42220> <cache_path:path:cache.json>",
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
        .unwrap_or("443")
        .parse()?;
    let cache_path = args.get(3).map(|str| str.as_str()).unwrap_or("cache.json");
    let tls_identity = match args.len() {
        #[cfg(feature = "tls")]
        6 => {
            let cert = tokio::fs::read(&args[4]).await?;
            let key = tokio::fs::read(&args[5]).await?;
            Some(Identity::from_pem(cert, key))
        }
        _ => None,
    };
    let server = Server::new(SocketAddr::new(addr, port), cache_path, tls_identity)?;
    server.run().await?;
    Ok(())
}
