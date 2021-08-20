use anyhow::Result;

use crate::{error::Error, map::MappedFile};

use std::{ffi::c_void, ptr::null};

use winapi::um::winnt::*;

pub struct PortableExecutable {
    file: MappedFile,
    dos_header: IMAGE_DOS_HEADER,
    nt_headers: IMAGE_NT_HEADERS64,
    section_headers: Vec<IMAGE_SECTION_HEADER>,
}

impl PortableExecutable {
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
        Ok(PortableExecutable {
            file,
            dos_header,
            nt_headers,
            section_headers,
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
        IMAGE_DOS_HEADER,
        IMAGE_NT_HEADERS64,
        Vec<IMAGE_SECTION_HEADER>,
    )> {
        unsafe {
            let dos_header = *file
                .get_rva::<IMAGE_DOS_HEADER>(0)
                .ok_or(Error::from("DOS header was out of bounds"))?;
            let nt_headers = *file
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
            Ok((dos_header, nt_headers, vec![]))
        }
    }

    /// Runs the executable's entry point with `DLL_PROCESS_ATTACH`
    ///
    /// # Safety
    ///
    /// The safety of this function is entirely dependent on whether or not
    /// the underlying executable is safe
    pub unsafe fn run(self) -> Result<isize> {
        // resolve the entry point
        // we transmute here because I have no earthly idea how to return a generic function
        let entry_point: unsafe extern "C" fn(*const c_void, u32, *const c_void) -> isize =
            std::mem::transmute(
                self.file
                    .get_rva::<*const u8>(
                        self.nt_headers.OptionalHeader.AddressOfEntryPoint as isize,
                    )
                    .ok_or(Error::from("Entry point was out of bounds"))?,
            );
        Ok(entry_point(
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

    #[serial]
    #[test]
    fn good_image() {
        let image = PortableExecutable::load("basic.exe").unwrap();
        unsafe {
            assert_eq!(image.run().unwrap(), 23);
        }
    }

    // we only support x86-64/ARM64 for now
    #[test]
    #[should_panic]
    fn x86_image() {
        let _ = PortableExecutable::load("x86.exe").unwrap();
    }

    #[test]
    fn crt_image() {
        let image = PortableExecutable::load("crt.exe").unwrap();
        unsafe {
            assert_eq!(image.run().unwrap(), 23);
        }
    }
}
