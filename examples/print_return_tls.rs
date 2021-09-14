/// Usage: print_return <executable:path>
/// <host:hostname:localhost> <port:u16:42220>
/// Description: Prints the executable return value.
/// Requires a separate remote PDB server
use mmap_loader::pe::{NtContext, PortableExecutable};
use std::env;
use tonic::transport::Certificate;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // parse arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 5 || args[1] == "-help" {
        eprintln!(
            "Usage: {} <executable:path> <host:hostname:localhost> <port:u16:443> <ca_cert:opt<path>>",
            args[0]
        );
        return Ok(());
    }
    let host = args.get(2).map(String::as_str).unwrap_or("localhost");
    let port = args.get(3).map(String::as_str).unwrap_or("443").parse()?;
    // load the cert file
    let ca_cert = match args.len() {
        5 => Some(Certificate::from_pem(tokio::fs::read(&args[4]).await?)),
        _ => None,
    };
    // fetch nt functions and constants
    let nt_ctx = NtContext::resolve_tls(host, port, ca_cert, None).await?;
    // map the executable
    let executable = PortableExecutable::load(&args[1], &nt_ctx)?;
    println!("Result: {}", unsafe { executable.run() });
    Ok(())
}
