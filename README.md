# mmap-loader-rs
A Windows Portable Executable Manual Map Loader that supports both executable and DLL types. Written in Rust

## Features
- Supports both DLL and EXE types
- Supports C++ exceptions, vectored exception handling, and structured exception handling
- Adds the entry to the loader structures, allowing support for functions such as `GetModuleHandle`
- MSVC recognizes mapped executables and debugging of children is fully supported with symbols
- Supports lazy execution, where multiple PE files can be loaded before any are executed
- Returns control flow to the calling function after execution is complete

## Known Limitations
- 32-bit is not fully supported (but is an easy fix)
- `GetModuleInformation` and related functions will not find the loaded module. This is because the linked lists that are used to find the module for these functions are sanity checked and protected by the kernel, and the first access after modifying these structures would result in a fatal OS exception. A suggested alternative is to use `VirtualQuery` to get the size of allocation
- Uses a remove server
- PEs are not un-loaded from OS structures to reduce the number of required signatures to upkeep. If necessary, functions exist to reverse all OS calls.

## Usage
```rs
use mmap_loader::pe::{NtContext, PortableExecutable};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // load NT functions and constants. this fetches offsets from a PDB parser server, included in `mmap_loader::server::Server`
  let nt_context = NtContext::resolve("localhost", 42221).await?;
  // load the PE file. this can be a DLL or EXE file
  let pe = PortableExecutable::load("foo.exe", &nt_context)?;
  // any other code. load DLLs, whatever
  // call the entry point when we are ready. this returns whatever the entry point returns
  pe.run();
}
```
