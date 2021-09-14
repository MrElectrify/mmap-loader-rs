/// Usage: print_return_no_server <executable:path>
/// Description: Prints the executable return value.
/// Includes the handler
use mmap_loader::{
    pe::{NtContext, PortableExecutable},
    server::OffsetHandler,
};
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // parse arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <executable:path>", args[0]);
        return Ok(());
    }
    // create the local handler
    let handler = OffsetHandler::new("test/cache.json".into())?;
    // fetch nt functions and constants
    let nt_ctx = NtContext::resolve_local(&handler).await?;
    // map the executable
    let executable = PortableExecutable::load(&args[1], &nt_ctx)?;
    println!("Result: {}", unsafe { executable.run() });
    Ok(())
}
