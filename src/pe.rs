use crate::{
    bindings::Windows::Win32::System::{
        Diagnostics::Debug::{
            IMAGE_NT_HEADERS64,
            IMAGE_SECTION_HEADER,
        },
        SystemServices::IMAGE_DOS_HEADER,
    },
    map::MappedFile,
    primitives::Error,
};

pub struct PortableExecutable {
    file: MappedFile,
    dos_header: IMAGE_DOS_HEADER,
    nt_headers: IMAGE_NT_HEADERS64,
    section_headers: Vec<IMAGE_SECTION_HEADER>
}

impl PortableExecutable {
    /// Loads the portable executable, processing any options
    ///
    /// # Arguments
    ///
    /// `path`: The path to the executable file
    pub fn load(path: &str) -> Result<PortableExecutable, Error> {
        // first map the file
        let file = MappedFile::load(path)?;
        // load the headers
        let (dos_header, nt_headers, section_headers) = PortableExecutable::load_headers(&file);
        Ok(PortableExecutable{ file, dos_header, nt_headers, section_headers })
    }

    /// Loads the headers from a mapped file
    ///
    /// # Arguments
    ///
    /// `file`: The mapped executable file
    fn load_headers(file: &MappedFile) -> (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, Vec<IMAGE_SECTION_HEADER>) {
        unsafe {
            let dos_header = *file.get_rva::<IMAGE_DOS_HEADER>(0);
            let nt_headers = *file.get_rva::<IMAGE_NT_HEADERS64>(dos_header.e_lfanew as isize);
            (dos_header, nt_headers, vec!())
        }
    }

    /// Runs the executable's entry point with `DLL_PROCESS_ATTACH`
    pub unsafe fn run(&mut self) -> isize {
        5
    }
}