use crate::{
    error::{Err, Error},
    map::MappedFile,
    primitives::{protected_write, ProtectionGuard},
};
use anyhow::Result;
use log::debug;
use ntapi::{ntldr::{LDRP_CSLIST, LDR_DATA_TABLE_ENTRY, LDR_DATA_TABLE_ENTRY_u1, LDR_DATA_TABLE_ENTRY_u2, LDR_DDAG_NODE, LDR_DDAG_NODE_u, LDR_DDAG_STATE, LdrModulesReadyToRun, PLDR_INIT_ROUTINE}, ntrtl::RtlInitUnicodeString};
use std::{
    ffi::{c_void, CStr},
    os::windows::prelude::OsStrExt,
    path::{Path, PathBuf},
    ptr::null_mut,
};
use winapi::{
    shared::ntdef::{
        BOOLEAN, LARGE_INTEGER, LIST_ENTRY, RTL_BALANCED_NODE, SINGLE_LIST_ENTRY, ULONGLONG,
        UNICODE_STRING,
    },
    um::{
        libloaderapi::{GetProcAddress, LoadLibraryA},
        winnt::{
            DLL_PROCESS_ATTACH, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DOS_HEADER,
            IMAGE_FILE_MACHINE_AMD64, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
            IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_ORDINAL_FLAG,
            IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER, IMAGE_THUNK_DATA,
            PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE,
        },
    },
};

pub struct PortableExecutable<'a> {
    file: MappedFile,
    file_name: PathBuf,
    file_path: PathBuf,
    nt_headers: &'a IMAGE_NT_HEADERS64,
    section_headers: &'a [IMAGE_SECTION_HEADER],
    entry_point: PLDR_INIT_ROUTINE,
    section_protections: Vec<ProtectionGuard>,
    loader_entry: LDR_DATA_TABLE_ENTRY,
    ddag_node: LDR_DDAG_NODE,
}

impl<'a> PortableExecutable<'a> {
    /// Initializes the loader entry
    fn init_ldr_entry(&mut self) -> Result<()> {
        self.loader_entry.DllBase = self.file.contents_mut();
        self.loader_entry.DdagNode = &mut self.ddag_node;
        unsafe {
            RtlInitUnicodeString(
                &mut self.loader_entry.BaseDllName,
                self.file_name
                    .as_os_str()
                    .encode_wide()
                    .collect::<Vec<u16>>()
                    .as_ptr(),
            );
            RtlInitUnicodeString(
                &mut self.loader_entry.FullDllName,
                self.file_path
                    .as_os_str()
                    .encode_wide()
                    .collect::<Vec<u16>>()
                    .as_ptr(),
            );
        }
        self.ddag_node.State = LdrModulesReadyToRun;
        self.ddag_node.LoadCount = u32::MAX;
        Ok(())
    }

    /// Loads the portable executable, processing any options
    ///
    /// # Arguments
    ///
    /// `path`: The path to the executable file
    pub fn load(path: &str) -> Result<PortableExecutable> {
        let mut file = MappedFile::load(path)?;
        let path = Path::new(path);
        let file_name = path.file_name().ok_or(Error(Err::FileNotFound))?;
        let file_path = path.canonicalize()?;
        debug!(
            "Loading {} at path {}",
            file_name.to_string_lossy(),
            file_path.to_string_lossy()
        );
        let (nt_headers, section_headers) = PortableExecutable::load_headers(&mut file)?;
        let entry_point = PortableExecutable::load_entry_point(&mut file, nt_headers)?;
        let mut pe = PortableExecutable {
            file,
            file_name: file_name.into(),
            file_path,
            nt_headers,
            section_headers,
            entry_point,
            section_protections: Vec::new(),
            loader_entry: LDR_DATA_TABLE_ENTRY {
                InLoadOrderLinks: LIST_ENTRY::default(),
                InMemoryOrderLinks: LIST_ENTRY::default(),
                u1: LDR_DATA_TABLE_ENTRY_u1 {
                    InInitializationOrderLinks: LIST_ENTRY::default(),
                },
                DllBase: null_mut(),
                EntryPoint: None,
                SizeOfImage: 0,
                FullDllName: UNICODE_STRING::default(),
                BaseDllName: UNICODE_STRING::default(),
                u2: LDR_DATA_TABLE_ENTRY_u2 { Flags: 0 },
                ObsoleteLoadCount: 0,
                TlsIndex: 0,
                HashLinks: LIST_ENTRY::default(),
                TimeDateStamp: 0,
                EntryPointActivationContext: null_mut(),
                Lock: null_mut(),
                DdagNode: null_mut(),
                NodeModuleLink: LIST_ENTRY::default(),
                LoadContext: null_mut(),
                ParentDllBase: null_mut(),
                SwitchBackContext: null_mut(),
                BaseAddressIndexNode: RTL_BALANCED_NODE::default(),
                MappingInfoIndexNode: RTL_BALANCED_NODE::default(),
                OriginalBase: 0,
                LoadTime: LARGE_INTEGER::default(),
                BaseNameHashValue: 0,
                LoadReason: 0,
                ImplicitPathOptions: 0,
                ReferenceCount: 0,
                DependentLoadFlags: 0,
                SigningLevel: 0,
            },
            ddag_node: LDR_DDAG_NODE {
                Modules: LIST_ENTRY::default(),
                ServiceTagList: null_mut(),
                LoadCount: 0,
                LoadWhileUnloadingCount: 0,
                LowestLink: 0,
                u: LDR_DDAG_NODE_u {
                    Dependencies: LDRP_CSLIST { Tail: null_mut() },
                },
                IncomingDependencies: LDRP_CSLIST { Tail: null_mut() },
                State: LDR_DDAG_STATE::default(),
                CondenseLink: SINGLE_LIST_ENTRY::default(),
                PreorderNumber: 0,
            },
        };
        pe.resolve_imports()?;
        pe.init_ldr_entry()?;
        // protect last
        pe.protect_sections()?;
        Ok(pe)
    }

    /// Loads the entry point from a mapped file
    ///
    /// # Arguments
    ///
    /// `file`: The mapped executable file
    fn load_entry_point(
        file: &mut MappedFile,
        nt_headers: &IMAGE_NT_HEADERS64,
    ) -> Result<PLDR_INIT_ROUTINE> {
        unsafe {
            // resolve the entry point
            // we transmute here because I have no earthly idea how to return a generic function
            let entry_point: PLDR_INIT_ROUTINE = std::mem::transmute(
                file.get_rva::<u8>(nt_headers.OptionalHeader.AddressOfEntryPoint as isize)
                    .ok_or(Error(Err::EPOutOfBounds))?,
            );
            Ok(entry_point)
        }
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
                return Err(Error(Err::UnsupportedArch).into());
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

    /// Protects all of the sections with their specified protections
    fn protect_sections(&mut self) -> Result<()> {
        for &section in self.section_headers {
            unsafe {
                self.section_protections.push(ProtectionGuard::new(
                    self.file
                        .get_rva_mut::<c_void>(section.VirtualAddress as isize)
                        .ok_or(Error(Err::SectOutOfBounds))?,
                    *section.Misc.VirtualSize() as usize,
                    PortableExecutable::section_flags_to_prot(section.Characteristics),
                )?)
            }
        }
        Ok(())
    }

    /// Resolves imports from the NT headers
    fn resolve_imports(&mut self) -> Result<()> {
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

    /// Resolves imports from the specified import descriptors. This
    /// is separate because some executables have separate IATs from the
    /// NT header IATs, and it is necessary to resolve them as well
    ///
    /// # Arguments
    ///
    /// `table`: The import descriptors
    pub fn resolve_import_descriptors(&mut self, table: &[IMAGE_IMPORT_DESCRIPTOR]) -> Result<()> {
        // we know the table is not null
        for &entry in table {
            // ignore empty entries
            if entry.Name == 0 {
                continue;
            }
            // load the name of the import. here we could crash if the string was on the edge
            // of the page. but that's a waste to check for every byte
            let name = self
                .file
                .get_rva::<i8>(entry.Name as isize)
                .ok_or(Error(Err::LibNameOutOfBounds))?;
            unsafe {
                debug!("Loading library {:?}", CStr::from_ptr(name));
                let library = LoadLibraryA(name);
                if library.is_null() {
                    return Err(std::io::Error::last_os_error().into());
                }
                // skip empty tables
                if entry.FirstThunk == 0 {
                    continue;
                }
                let mut thunk = self
                    .file
                    .get_rva_mut::<IMAGE_THUNK_DATA>(entry.FirstThunk as isize)
                    .ok_or(Error(Err::IATOutOfBounds))?;
                while (*thunk).u1.AddressOfData() != &0 {
                    let proc_name = if ((*thunk).u1.Ordinal() & IMAGE_ORDINAL_FLAG) != 0 {
                        (*(*thunk).u1.Ordinal() & !IMAGE_ORDINAL_FLAG) as *const i8
                    } else {
                        &(*self
                            .file
                            .get_rva::<IMAGE_IMPORT_BY_NAME>(*(*thunk).u1.AddressOfData() as isize)
                            .ok_or(Error(Err::ProcNameOutOfBounds))?)
                        .Name as *const i8
                    };
                    if ((*thunk).u1.Ordinal() & IMAGE_ORDINAL_FLAG) != 0 {
                        debug!(
                            "Loading procedure with ordinal {}",
                            (*thunk).u1.Ordinal() & !IMAGE_ORDINAL_FLAG
                        );
                    } else {
                        // if it is a pointer, make sure it is not null
                        if proc_name.is_null() {
                            return Err(Error(Err::NullProcName).into());
                        }
                        debug!(
                            "Loading procedure with name {:?}",
                            CStr::from_ptr(proc_name)
                        );
                    }
                    // load the function
                    let func = GetProcAddress(library, proc_name);
                    if func.is_null() {
                        return Err(std::io::Error::last_os_error().into());
                    }
                    let func_ptr = (*thunk).u1.Function_mut() as *mut ULONGLONG;
                    // write the function address
                    protected_write(func_ptr, func as ULONGLONG)?;
                    thunk = thunk.add(1);
                }
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
    pub unsafe fn run(mut self) -> Result<BOOLEAN> {
        Ok((self.entry_point.unwrap())(
            self.file.contents_mut(),
            DLL_PROCESS_ATTACH,
            null_mut(),
        ))
    }

    /// Converts section flags to page protection flags
    ///
    /// # Arguments
    ///
    /// `section_flags`: The section flags
    fn section_flags_to_prot(section_flags: u32) -> u32 {
        if section_flags & IMAGE_SCN_MEM_EXECUTE != 0 {
            PAGE_EXECUTE_READ
        } else if section_flags & IMAGE_SCN_MEM_WRITE != 0 {
            PAGE_READWRITE
        } else {
            PAGE_READONLY
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serial_test::serial;
    use winapi::shared::winerror::{
        ERROR_BAD_EXE_FORMAT, ERROR_MOD_NOT_FOUND, ERROR_PROC_NOT_FOUND,
    };

    #[test]
    #[serial]
    fn bad_dos() {
        let err: std::io::Error = PortableExecutable::load("test/baddos.exe")
            .err()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(err.raw_os_error().unwrap(), ERROR_BAD_EXE_FORMAT as i32);
    }

    #[test]
    #[serial]
    fn bad_section() {
        let err: std::io::Error = PortableExecutable::load("test/badsection.exe")
            .err()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(err.raw_os_error().unwrap(), ERROR_BAD_EXE_FORMAT as i32);
    }

    #[test]
    #[serial]
    fn bad_entry() {
        let err: Error = PortableExecutable::load("test/badentry.exe")
            .err()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(err.0, Err::EPOutOfBounds);
    }

    #[test]
    #[serial]
    fn bad_mod() {
        let err: std::io::Error = PortableExecutable::load("test/badmod.exe")
            .err()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(err.raw_os_error().unwrap(), ERROR_MOD_NOT_FOUND as i32);
    }

    #[test]
    #[serial]
    fn bad_proc() {
        let err: std::io::Error = PortableExecutable::load("test/badproc.exe")
            .err()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(err.raw_os_error().unwrap(), ERROR_PROC_NOT_FOUND as i32);
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
    #[serial]
    fn x86_image() {
        let err: Error = PortableExecutable::load("test/x86.exe")
            .err()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(err.0, Err::UnsupportedArch);
    }
}
