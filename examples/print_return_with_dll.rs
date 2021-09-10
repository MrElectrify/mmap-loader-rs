/// Usage: print_return_with_dll <executable:path> <dll:path>
/// <host:hostname:localhost> <port:u16:42220>
/// Description: Prints the executable return value, after
/// loading a DLL before the executable begins executing.
/// Requires a separate remote PDB server

use mmap_loader::pe::{NtContext, PortableExecutable};
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // parse arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 4 {
        eprintln!(
            "Usage: {} <executable:path> <dll:path> <host:hostname> <port:u16>",
            args[0]
        );
        return Ok(());
    }
    let host = args.get(3).map(String::as_str).unwrap_or("localhost");
    let port = args.get(4).map(String::as_str).unwrap_or("42220").parse()?;
    // fetch nt functions and constants
    let nt_ctx = NtContext::resolve(host, port).await?;
    // map the executable
    let executable = PortableExecutable::load(&args[1], &nt_ctx)?;
    // map the dll
    let dll = PortableExecutable::load(&args[2], &nt_ctx)?;
    // run DllMain first
    if unsafe { dll.run() } == false as u8 {
        eprintln!("DllMain returned false!");
        return Ok(());
    }
    // now run the executable
    println!("Result: {}", unsafe { executable.run() });
    Ok(())
}
