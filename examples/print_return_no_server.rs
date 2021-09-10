/// Usage: print_return_no_server <executable:path>
/// Description: Prints the executable return value.
/// Bundles the server with the client and does not
/// require a separate server

use mmap_loader::{
    pe::{NtContext, PortableExecutable},
    server::Server,
};
use std::{
    env,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    thread,
};
use tokio::runtime::Runtime;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // parse arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <executable:path>", args[0]);
        return Ok(());
    }
    // create the local server and start it
    let server = Server::new(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 42220)),
        "test/cache.json".into(),
    )?;
    let runtime = Runtime::new()?;
    thread::spawn(move || runtime.block_on(server.run()).unwrap());
    // fetch nt functions and constants
    let nt_ctx = NtContext::resolve("localhost", 42220).await?;
    // map the executable
    let executable = PortableExecutable::load(&args[1], &nt_ctx)?;
    println!("Result: {}", unsafe { executable.run() });
    Ok(())
}
