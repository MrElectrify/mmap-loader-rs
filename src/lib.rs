mod db;
/// All non-OS error codes that can be emitted upon loading a module
pub mod error;
#[cfg(target_os = "windows")]
mod map;
mod offsets;
#[cfg(target_os = "windows")]
/// The portable executable mapper
pub mod pe;
#[cfg(target_os = "windows")]
mod primitives;
/// The necessary parts to run a PDB offset server
pub mod server;
#[cfg(target_os = "windows")]
mod util;

/// Exported for simple uses
pub use pe::{ NtContext, PortableExecutable };