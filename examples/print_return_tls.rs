/// Usage: print_return <executable:path>
/// <host:hostname:localhost> <port:u16:42220>
/// Description: Prints the executable return value.
/// Requires a separate remote PDB server
use mmap_loader::pe::{NtContext, PortableExecutable};
use std::env;

#[tokio::main]
async fn main() {
    // parse arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 6 || args[1] == "-help" {
        eprintln!(
            "Usage: {} <executable:path> <host:hostname:localhost> <port:u16:443>",
            args[0]
        );
        return;
    }
    let host = args.get(2).map(String::as_str).unwrap_or("localhost");
    let port = args
        .get(3)
        .map(String::as_str)
        .unwrap_or("443")
        .parse()
        .expect("Failed to parse port");
    // fetch nt functions and constants
    let nt_ctx = NtContext::resolve_tls(host, port, None, None)
        .await
        .expect("Failed to resolve context");
    // map the executable
    let executable = PortableExecutable::load(&args[1], &nt_ctx).expect("Failed to map executable");
    println!("Result: {}", unsafe { executable.run() });
}
