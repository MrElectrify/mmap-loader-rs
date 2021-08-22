# mmap-loader-rs
A Windows Portable Executable Manual Map Loader that supports both executable and DLL types. Written in Rust

## Features
Features are generally equivalent to the C++ MMap-Loader here: https://github.com/MrElectrify/MMap-Loader, except OS structures are not yet updated

## Usage
```rs
use mmap_loader::pe::PortableExecutable;

fn main() {
  // load the PE file. this can be a DLL or EXE file
  let pe = PortableExecutable::load("foo.exe").unwrap();
  // call the entry point. this returns BOOL, whatever the entry point returns.
  // in the event of a DLL, this is whatever `DllMain` returns.
  pe.run();
}
```
