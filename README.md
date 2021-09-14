# mmap-loader-rs
A Windows Portable Executable Manual Map Loader that supports both executable and DLL types. Written in Rust

## Features
- Supports both DLL and EXE types
- Remote or local PDB server for parsing out internal Windows functions
- Supports C++ exceptions, vectored exception handling, and structured exception handling
- Adds the entry to the loader structures, allowing support for functions such as `GetModuleHandle`, `GetModuleFileName`, and more
- Allows for a module to be treated as a primary, resulting in calls to `GetModuleHandle(null)` to resolve to the mapped module
- Unmaps the file and cleans up OS structures upon destruction for ephemeral executables
- MSVC recognizes mapped executables and debugging of children is fully supported with symbols
- Supports lazy execution, where multiple PE files can be loaded before any are executed
- Returns control flow to the calling function after execution is complete

## Feature Flags
- server
    - enables a separate server component
- tls
    - enables tls support for the client and server

## Support
Let me know if something doesn't work by opening an issue. It has only been tested on Windows 10 20H2, and likely won't work on Windows 7 and prior. To see if it works on your system, run `cargo test`

## Known Limitations
- 32-bit is not supported
- `GetModuleInformation` and related functions will not find the loaded module. This is because the linked lists that are used to find the module for these functions are sanity checked and protected by the kernel, and the first access after modifying these structures would result in a fatal OS exception. A suggested alternative is to use `VirtualQuery` to get the size of allocation

## Usage
Check out the [examples](examples/)