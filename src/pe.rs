use anyhow::Result;

use crate::{
    error::{Err, Error},
    map::MappedFile,
};

use log::debug;

use std::{ffi::c_void, ptr::null};

use winapi::{shared::winerror::ERROR_MOD_NOT_FOUND, um::{libloaderapi::LoadLibraryA, winnt::*}};

pub struct PortableExecutable<'a> {
    file: MappedFile,
    nt_headers: &'a IMAGE_NT_HEADERS64,
    _section_headers: &'a [IMAGE_SECTION_HEADER],
    entry_point: unsafe extern "C" fn(*const c_void, u32, *const c_void) -> isize,
}

impl<'a> PortableExecutable<'a> {
    /// Loads the portable executable, processing any options
    ///
    /// # Arguments
    ///
    /// `path`: The path to the executable file
    pub fn load(path: &str) -> Result<PortableExecutable> {
        // first map the file
        let mut file = MappedFile::load(path)?;
        // load the headers
        let (nt_headers, section_headers) = PortableExecutable::load_headers(&mut file)?;
        // load the entry point
        let entry_point = PortableExecutable::load_entry_point(&mut file, nt_headers)?;
        let pe = PortableExecutable {
            file,
            nt_headers,
            _section_headers: section_headers,
            entry_point,
        };
        pe.resolve_imports()?;
        // process relocations
        Ok(pe)
    }

    /// Loads the headers from a mapped file
    ///
    /// # Arguments
    ///
    /// `file`: The mapped executable file
    fn load_headers(
        file: &mut MappedFile,
    ) -> Result<(&'a IMAGE_NT_HEADERS64, &'a [IMAGE_SECTION_HEADER])> {
        unsafe {
            let dos_header = &*file
                .get_rva::<IMAGE_DOS_HEADER>(0)
                .ok_or(Error(Err::DOSOutOfBounds))?;
            let nt_headers = &*file
                .get_rva::<IMAGE_NT_HEADERS64>(dos_header.e_lfanew as isize)
                .ok_or(Error(Err::NTOutOfBounds))?;
            // ensure supported architecture
            if nt_headers.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
                || nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
            {
                return Err(Error(Err::DOSOutOfBounds).into());
            }
            // load section headers
            let section_headers = std::slice::from_raw_parts(
                file.get_rva_size_chk::<IMAGE_SECTION_HEADER>(
                    dos_header.e_lfanew as isize
                        + std::mem::size_of::<IMAGE_NT_HEADERS64>() as isize,
                    nt_headers.FileHeader.NumberOfSections as usize
                        * std::mem::size_of::<IMAGE_SECTION_HEADER>(),
                )
                .ok_or(Error(Err::SectOutOfBounds))?,
                nt_headers.FileHeader.NumberOfSections as usize,
            );
            Ok((nt_headers, section_headers))
        }
    }

    /// Loads the entry point from a mapped file
    ///
    /// # Arguments
    ///
    /// `file`: The mapped executable file
    fn load_entry_point(
        file: &mut MappedFile,
        nt_headers: &IMAGE_NT_HEADERS64,
    ) -> Result<unsafe extern "C" fn(*const c_void, u32, *const c_void) -> isize> {
        unsafe {
            // resolve the entry point
            // we transmute here because I have no earthly idea how to return a generic function
            let entry_point: unsafe extern "C" fn(*const c_void, u32, *const c_void) -> isize =
                std::mem::transmute(
                    file.get_rva::<u8>(nt_headers.OptionalHeader.AddressOfEntryPoint as isize)
                        .ok_or(Error(Err::EPOutOfBounds))?,
                );
            Ok(entry_point)
        }
    }

    /// Resolves imports from the NT headers
    fn resolve_imports(&self) -> Result<()> {
        unsafe {
            let iat_directory = &self.nt_headers.OptionalHeader.DataDirectory
                [IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
            // if there is not an IAT, just return
            if iat_directory.VirtualAddress == 0 {
                return Ok(());
            }
            // grab the IAT from the header. ensure there is space for the entire directory
            let iat_entry = self
                .file
                .get_rva_size_chk::<IMAGE_IMPORT_DESCRIPTOR>(
                    iat_directory.VirtualAddress as isize,
                    iat_directory.Size as usize,
                )
                .ok_or(Error(Err::IDOutOfBounds))?;
            self.resolve_import_descriptors(std::slice::from_raw_parts(
                iat_entry,
                (iat_directory.Size as usize) / std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>(),
            ))
        }
    }

    /// Resolves imports from the specified import descriptors
    ///
    /// # Arguments
    ///
    /// `table`: The import descriptors
    pub fn resolve_import_descriptors(&self, table: &[IMAGE_IMPORT_DESCRIPTOR]) -> Result<()> {
        // we know the table is not null
        for &entry in table {
            // ignore empty entries
            if entry.Name == 0 { continue }
            // load the name of the import. here we could crash if the string was on the edge
            // of the page. but that's a waste to check for every byte
            let name = self
                .file
                .get_rva::<i8>(entry.Name as isize)
                .ok_or(Error(Err::LibNameOutOfBounds))?;
            unsafe {
                debug!("Loading library {:?}", std::ffi::CStr::from_ptr(name));
            }
            unsafe {
                let library = LoadLibraryA(name);
                if library.is_null() {
                    return Err(std::io::Error::from_raw_os_error(ERROR_MOD_NOT_FOUND as i32).into())
                }
                // skip empty tables
                /*if entry.FirstThunk == 0 { continue }
                let mut thunk = &*self.file.get_rva::<IMAGE_THUNK_DATA>(entry.FirstThunk as isize).ok_or(Error(Err::IATOutOfBounds))?;
                while thunk.u1.AddressOfData() != &0 {
                    let proc_name = if (thunk.u1.Ordinal() & IMAGE_ORDINAL_FLAG) != 0 { thunk.u1.Ordinal() } else { self.file.get_rva::<i8>(thunk.u1.AddressOfData()).ok_or(Error(Err::ProcNameOutOfBounds))? };
                }*/
            }
        }
        Ok(())
    }

    /// Runs the executable's entry point with `DLL_PROCESS_ATTACH`
    ///
    /// # Safety
    ///
    /// The safety of this function is entirely dependent on whether or not
    /// the underlying executable is safe
    pub unsafe fn run(self) -> Result<isize> {
        Ok((self.entry_point)(
            self.file.contents(),
            DLL_PROCESS_ATTACH,
            null(),
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serial_test::serial;

    #[test]
    #[should_panic]
    fn bad_dos() {
        let _ = PortableExecutable::load("test/baddos.exe").unwrap();
    }

    #[test]
    #[should_panic]
    fn bad_section() {
        let _ = PortableExecutable::load("test/badsection.exe").unwrap();
    }

    #[test]
    #[should_panic]
    fn bad_entry() {
        let image = PortableExecutable::load("test/badentry.exe").unwrap();
        unsafe {
            image.run().unwrap();
        }
    }

    #[test]
    #[should_panic]
    fn bad_mod() {
        let _ = PortableExecutable::load("test/badmod.exe").unwrap();
    }

    #[test]
    #[serial]
    fn basic_image() {
        let image = PortableExecutable::load("test/basic.exe").unwrap();
        unsafe {
            assert_eq!(image.run().unwrap(), 23);
        }
    }

    // we only support x86-64/ARM64 for now
    #[test]
    #[should_panic]
    fn x86_image() {
        let _ = PortableExecutable::load("test/x86.exe").unwrap();
    }

    #[test]
    fn crt_image() {
        let image = PortableExecutable::load("test/crt.exe").unwrap();
        unsafe {
            assert_eq!(image.run().unwrap(), 55);
        }
    }

    #[test]
    fn stdout_image() {
        let image = PortableExecutable::load("test/stdout.exe").unwrap();
        unsafe {
            assert_eq!(image.run().unwrap(), 55);
        }
    }
}
