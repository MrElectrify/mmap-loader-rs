use anyhow::Result;

use crate::{
    error::Error,
    map::MappedFile
};

use std::{ffi::c_void, ptr::null};

use winapi::um::{
    winnt::*
};

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
    pub fn load(path: &String) -> Result<PortableExecutable> {
        // first map the file
        let mut file = MappedFile::load(path)?;
        // load the headers
        let (dos_header, nt_headers, section_headers) = PortableExecutable::load_headers(&mut file)?;
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
            let dos_header = *file.get_rva::<IMAGE_DOS_HEADER>(0);
            let nt_offset = dos_header.e_lfanew;
            if nt_offset as usize > file.len()? {
                return Err(
                    Error::from("NT offset was bigger than the header's allocation").into(),
                );
            }
            let nt_headers = *file.get_rva::<IMAGE_NT_HEADERS64>(dos_header.e_lfanew as isize);
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
    pub unsafe fn run(self) -> Result<isize> {
        // resolve the entry point
        let entry_point_offset = self.nt_headers.OptionalHeader.AddressOfEntryPoint as usize;
        if entry_point_offset > self.file.len()? {
            return Err(
                Error::from("Entry point offset was bigger than the allocation").into(),
            );
        }
        let entry_point =
            self
                .file
                .get_rva_fn::<unsafe extern "C" fn(*const c_void, u32, *const c_void) -> isize>(
                    entry_point_offset as isize,
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

    #[test]
    fn good_image() {
        let image = PortableExecutable::load(&"test.exe".to_owned()).unwrap();
        unsafe {
            assert_eq!(image.run().unwrap(), 23);
        }
    }
}
