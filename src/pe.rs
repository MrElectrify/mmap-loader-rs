use anyhow::Result;

use crate::{
    bindings::Windows::Win32::System::{
        Diagnostics::Debug::{
            IMAGE_FILE_MACHINE_AMD64, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
            IMAGE_SECTION_HEADER,
        },
        SystemServices::IMAGE_DOS_HEADER,
    },
    error,
    map::MappedFile,
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
    pub fn load(path: &str) -> Result<PortableExecutable> {
        // first map the file
        let file = MappedFile::load(path)?;
        // load the headers
        let (dos_header, nt_headers, section_headers) = PortableExecutable::load_headers(&file)?;
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
        file: &MappedFile,
    ) -> Result<(
        IMAGE_DOS_HEADER,
        IMAGE_NT_HEADERS64,
        Vec<IMAGE_SECTION_HEADER>,
    )> {
        unsafe {
            let dos_header = *file.get_rva::<IMAGE_DOS_HEADER>(0);
            let nt_offset = dos_header.e_lfanew;
            if nt_offset as usize > file.len()? {
                return Err(error::Error::from("NT offset was bigger than the header's allocation").into())
            }
            let nt_headers = *file.get_rva::<IMAGE_NT_HEADERS64>(dos_header.e_lfanew as isize);
            Ok((dos_header, nt_headers, vec![]))
        }
    }

    /// Runs the executable's entry point with `DLL_PROCESS_ATTACH`
    pub unsafe fn run(self) -> isize {
        // resolve the entry point
        let entry_point = self.file.get_rva::<unsafe extern "stdcall" fn (i32) -> isize>(0);
        entry_point(5)
    }
}
