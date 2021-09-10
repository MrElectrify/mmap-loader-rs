use mmap_loader::pe::{NtContext, PortableExecutable};
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // parse arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 4 {
        eprintln!(
            "Usage: {} <executable:path> <host:hostname> <port:u16>",
            args[0]
        );
        return Ok(());
    }
    let host = args.get(2).map(String::as_str).unwrap_or("localhost");
    let port = args.get(3).map(String::as_str).unwrap_or("42220").parse()?;
    // fetch nt functions and constants
    let nt_ctx = NtContext::resolve(host, port).await?;
    // map the executable
    let executable = PortableExecutable::load(&args[1], &nt_ctx)?;
    println!("Result: {}", unsafe { executable.run() });
    Ok(())
}
