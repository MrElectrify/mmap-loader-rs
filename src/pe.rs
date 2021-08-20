use anyhow::Result;

use crate::{error::Error, map::MappedFile};

use std::{ffi::c_void, ptr::null};

use winapi::um::winnt::*;

pub struct PortableExecutable<'a> {
    file: MappedFile,
    dos_header: &'a IMAGE_DOS_HEADER,
    nt_headers: &'a IMAGE_NT_HEADERS64,
    section_headers: Vec<&'a IMAGE_SECTION_HEADER>,
    entry_point: unsafe extern "C" fn(*const c_void, u32, *const c_void) -> isize
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
        let (dos_header, nt_headers, section_headers) =
            PortableExecutable::load_headers(&mut file)?;
        // load the entry point
        let entry_point = PortableExecutable::load_entry_point(&mut file, nt_headers)?;
        Ok(PortableExecutable {
            file,
            dos_header,
            nt_headers,
            section_headers,
            entry_point
        })
    }

    /// Loads the headers from a mapped file
    ///
    /// # Arguments
    ///
    /// `file`: The mapped executable file
    fn load_headers(
        file: &mut MappedFile,
    ) -> Result<(
        &'a IMAGE_DOS_HEADER,
        &'a IMAGE_NT_HEADERS64,
        Vec<&'a IMAGE_SECTION_HEADER>,
    )> {
        unsafe {
            let dos_header = &*file
                .get_rva::<IMAGE_DOS_HEADER>(0)
                .ok_or(Error::from("DOS header was out of bounds"))?;
            let nt_headers = &*file
                .get_rva::<IMAGE_NT_HEADERS64>(dos_header.e_lfanew as isize)
                .ok_or(Error::from("NT headers were out of bounds"))?;
            // ensure supported architecture
            if nt_headers.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
                || nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
            {
                return Err(Error::from(
                    "Unsupported architecture. Only AMD64/x86-64 is supported.",
                )
                .into());
            }
            // load section headers. first, create a vector and reserve that space
            let mut section_headers =
                Vec::with_capacity(nt_headers.FileHeader.NumberOfSections as usize);
            // load each section
            for i in 0..nt_headers.FileHeader.NumberOfSections {
                section_headers.push(
                    &*file
                        .get_rva::<IMAGE_SECTION_HEADER>(
                            dos_header.e_lfanew as isize
                                + std::mem::size_of::<IMAGE_NT_HEADERS64>() as isize
                                + i as isize * std::mem::size_of::<IMAGE_SECTION_HEADER>() as isize,
                        )
                        .ok_or(Error::from("A section header was out of bounds"))?,
                );
            }
            Ok((dos_header, nt_headers, section_headers))
        }
    }

    /// Loads the entry point from a mapped file
    ///
    /// # Arguments
    ///
    /// `file`: The mapped executable file
    fn load_entry_point(
        file: &mut MappedFile,
        nt_headers: &IMAGE_NT_HEADERS64
    ) -> Result<unsafe extern "C" fn(*const c_void, u32, *const c_void) -> isize> {
        unsafe {
            // ensure the entry point is within the code
            if nt_headers.OptionalHeader.AddressOfEntryPoint < nt_headers.OptionalHeader.BaseOfCode ||
            nt_headers.OptionalHeader.AddressOfEntryPoint >= nt_headers.OptionalHeader.BaseOfCode + nt_headers.OptionalHeader.SizeOfCode {
                return Err(Error::from("Entry point was not within the code").into());
            }
            // resolve the entry point
            // we transmute here because I have no earthly idea how to return a generic function
            let entry_point: unsafe extern "C" fn(*const c_void, u32, *const c_void) -> isize =
                std::mem::transmute(
                    file
                        .get_rva::<*const u8>(
                            nt_headers.OptionalHeader.AddressOfEntryPoint as isize,
                        )
                        .ok_or(Error::from("Entry point was out of bounds"))?,
                );
            Ok(entry_point)
        }
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
