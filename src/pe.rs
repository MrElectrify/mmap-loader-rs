use crate::{
    error::{Err, Error},
    map::MappedFile,
    offsets::{offset_client::OffsetClient, OffsetsRequest},
    primitives::{protected_write, ProtectionGuard, RtlMutex},
    util::to_wide,
};
use anyhow::Result;
use log::{debug, error};
use ntapi::{
    ntldr::{
        LDR_DATA_TABLE_ENTRY_u1, LDR_DATA_TABLE_ENTRY_u2, LDR_DDAG_NODE_u, LdrModulesReadyToRun,
        LDRP_CSLIST, LDR_DATA_TABLE_ENTRY, LDR_DDAG_NODE, LDR_DDAG_STATE, PLDR_INIT_ROUTINE,
    },
    ntrtl::{
        InsertTailList, RemoveEntryList, RtlHashUnicodeString, RtlInitUnicodeString,
        HASH_STRING_ALGORITHM_DEFAULT,
    },
};
use std::{
    ffi::{c_void, CStr},
    path::Path,
    pin::Pin,
    ptr,
    ptr::null_mut,
};
use winapi::{
    shared::{
        guiddef::GUID,
        ntdef::{
            LARGE_INTEGER, LIST_ENTRY, RTL_BALANCED_NODE, SINGLE_LIST_ENTRY, ULONGLONG,
            UNICODE_STRING,
        },
        ntstatus::STATUS_SUCCESS,
    },
    um::{
        libloaderapi::{GetModuleHandleW, GetProcAddress, LoadLibraryA},
        winnt::{
            RtlAddFunctionTable, RtlDeleteFunctionTable, DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH,
            IMAGE_DEBUG_DIRECTORY, IMAGE_DEBUG_TYPE_CODEVIEW, IMAGE_DIRECTORY_ENTRY_DEBUG,
            IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_IMPORT,
            IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_DOS_HEADER, IMAGE_FILE_MACHINE_AMD64,
            IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS64,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_ORDINAL_FLAG, IMAGE_RUNTIME_FUNCTION_ENTRY,
            IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER, IMAGE_THUNK_DATA,
            IMAGE_TLS_DIRECTORY, PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE, PVOID,
            RTL_SRWLOCK,
        },
    },
};

/// The context of Nt functions and statics
#[allow(non_snake_case)]
pub struct NtContext<'a> {
    LdrpHashTable: RtlMutex<'a, [LIST_ENTRY; 32]>,
    LdrpHandleTlsData: unsafe extern "stdcall" fn(*mut LDR_DATA_TABLE_ENTRY) -> i32,
}

impl<'a> NtContext<'a> {
    /// Gets the loaded NTDLL hash
    ///
    /// # Arguments
    ///
    /// `ntdll`: The NTDLL instance pointer
    fn get_ntdll_hash(ntdll: *const u8) -> Result<String, Error> {
        unsafe {
            let dos_header = ntdll as *const IMAGE_DOS_HEADER;
            if dos_header.is_null() {
                return Err(Error(Err::FileNotFound));
            }
            let nt_headers = &*((dos_header as *const u8).offset((*dos_header).e_lfanew as isize)
                as *const IMAGE_NT_HEADERS64);
            let debug_entry = &*((dos_header as *const u8).offset(
                nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG as usize]
                    .VirtualAddress as isize,
            ) as *const IMAGE_DEBUG_DIRECTORY);
            if debug_entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW {
                return Err(Error(Err::NtDllDebugType));
            }
            let codeview_entry = &*((dos_header as *const u8)
                .offset((*debug_entry).AddressOfRawData as isize)
                as *const IMAGE_DEBUG_CODEVIEW);
            if !codeview_entry
                .rsds_signature
                .eq_ignore_ascii_case("RSDS".as_bytes())
            {
                return Err(Error(Err::NtDllRsdsSig));
            }
            Ok(format!(
                "{:08X}{:04X}{:04X}{}{:X}",
                codeview_entry.guid.Data1,
                codeview_entry.guid.Data2,
                codeview_entry.guid.Data3,
                codeview_entry
                    .guid
                    .Data4
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<String>>()
                    .join(""),
                codeview_entry.age
            ))
        }
    }

    /// Resolves the context used by the mapper
    ///
    /// # Arguments
    ///
    /// `server_hostname`: The hostname of the endpoint of the PDB server
    /// `server_port`: The port of the endpoint of the PDB server
    pub async fn resolve(
        server_hostname: &str,
        server_port: u16,
    ) -> Result<NtContext<'a>, anyhow::Error> {
        let mut client =
            OffsetClient::connect(format!("http://{}:{}", server_hostname, server_port)).await?;
        let ntdll = unsafe { GetModuleHandleW(to_wide("ntdll").as_ptr()) as *const u8 };
        let request = tonic::Request::new(OffsetsRequest {
            ntdll_hash: NtContext::get_ntdll_hash(ntdll)?,
        });
        let response = client.get_offsets(request).await?.into_inner();
        unsafe {
            Ok(NtContext {
                LdrpHashTable: RtlMutex::from_ref(
                    &mut *(ntdll.offset(response.ldrp_hash_table as isize)
                        as *mut [LIST_ENTRY; 32]),
                    &mut *(ntdll.offset(response.ldrp_module_datatable_lock as isize)
                        as *mut RTL_SRWLOCK),
                ),
                LdrpHandleTlsData: std::mem::transmute(
                    ntdll.offset(response.ldrp_handle_tls_data as isize),
                ),
            })
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct IMAGE_DEBUG_CODEVIEW {
    rsds_signature: [u8; 4],
    guid: GUID,
    age: u32,
}

pub struct PortableExecutable<'a> {
    file: MappedFile,
    file_name: Vec<u16>,
    file_path: Vec<u16>,
    nt_headers: &'a IMAGE_NT_HEADERS64,
    section_headers: &'a [IMAGE_SECTION_HEADER],
    entry_point: PLDR_INIT_ROUTINE,
    section_protections: Vec<ProtectionGuard>,
    loader_entry: Pin<Box<LDR_DATA_TABLE_ENTRY>>,
    ddag_node: Pin<Box<LDR_DDAG_NODE>>,
    context: &'a NtContext<'a>,
    ldr_entry_init: bool,
}

impl<'a> PortableExecutable<'a> {
    /// Adds the module to the loader hash table, enabling functions like
    /// `GetModuleHandle` to work
    fn add_to_hash_table(&mut self) -> Result<()> {
        // insert the entry into the hash table and other relevant structures
        unsafe {
            InsertTailList(
                &mut self.context.LdrpHashTable.lock()
                    [(self.loader_entry.BaseNameHashValue & 0x1f) as usize],
                &mut self.loader_entry.HashLinks,
            );
        }
        Ok(())
    }

    /// Removes the module from the loader hash table
    fn remove_from_hash_table(&mut self) -> Result<()> {
        // remove hash table and linked list entries
        let mut hash_table = self.context.LdrpHashTable.lock();
        // find our entry
        let first_entry = &mut hash_table[(self.loader_entry.BaseNameHashValue & 0x1f) as usize];
        let mut entry = first_entry.Flink;
        // if the next entry is the first one, we are done
        while !ptr::eq(entry as *const LIST_ENTRY, first_entry) {
            if ptr::eq(entry as *const _, &self.loader_entry.HashLinks as *const _) {
                // remove the entry
                unsafe {
                    RemoveEntryList(entry.as_mut().unwrap());
                }
                return Ok(());
            }
            entry = unsafe { (*entry).Flink };
        }
        debug!("Failed to find reference");
        Ok(())
    }

    /// Calls the function entry point
    ///
    /// # Arguments
    ///
    /// `reason`: The reason for the call. Ex: `DLL_PROCESS_ATTACH`
    fn call_entry_point(&mut self, reason: u32) -> u8 {
        if let Some(entry_point) = &self.entry_point {
            unsafe { entry_point(self.file.contents_mut(), reason, null_mut()) }
        } else {
            0
        }
    }

    /// Enables exception handling for the module
    fn enable_exceptions(&mut self) -> Result<()> {
        // get the exception table
        let exception_table = self.get_exception_table()?;
        if exception_table.is_empty() {
            return Ok(());
        }
        // add the table to the process
        if unsafe {
            RtlAddFunctionTable(
                exception_table.as_mut_ptr(),
                exception_table.len() as u32,
                self.file.contents() as u64,
            ) == false as u8
        } {
            return Err(Error(Err::ExceptionTableEntry).into());
        }
        Ok(())
    }

    /// Disables exception handling for the module
    fn disable_exceptions(&mut self) -> Result<()> {
        // get the exception table
        let exception_table = self.get_exception_table()?;
        if exception_table.is_empty() {
            return Ok(());
        }
        // remove the table from the process
        if unsafe { RtlDeleteFunctionTable(exception_table.as_mut_ptr()) == false as u8 } {
            return Err(Error(Err::ExceptionTableEntry).into());
        }
        Ok(())
    }

    /// Execute TLS callbacks
    ///
    /// # Arguments
    ///
    /// `reason`: The reason for the call to the callbacks
    fn execute_tls_callbacks(&mut self, reason: u32) -> Result<()> {
        let tls_directory =
            &self.nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS as usize];
        // navigate to the tls directory if it exists
        if tls_directory.VirtualAddress == 0 {
            return Ok(());
        }
        let tls_directory = self
            .file
            .get_rva::<IMAGE_TLS_DIRECTORY>(tls_directory.VirtualAddress as isize)
            .ok_or(Error(Err::TLSOutOfBounds))?;
        let mut tls_callback = unsafe {
            self.file
                .get_rva::<Option<unsafe extern "stdcall" fn(PVOID, u32, PVOID)>>(
                    ((*tls_directory).AddressOfCallBacks - self.file.contents() as u64) as isize,
                )
                .ok_or(Error(Err::CallbackOutOfBounds))?
        };
        // execute all of the TLS callbacks
        unsafe {
            while (*tls_callback).is_some() {
                debug!("Executing TLS callback at {:p}", tls_callback);
                (*tls_callback).unwrap()(self.file.contents_mut(), reason, null_mut());
                // TLS callbacks are in an array
                tls_callback = tls_callback.offset(1);
            }
        }
        Ok(())
    }

    /// Handle TLS data
    fn handle_tls_data(&mut self) -> Result<()> {
        if unsafe { (self.context.LdrpHandleTlsData)(self.loader_entry.as_mut().get_mut()) }
            != STATUS_SUCCESS
        {
            Err(Error(Err::TLSData).into())
        } else {
            Ok(())
        }
    }

    /// Gets the exception table for the module, and its size
    fn get_exception_table(&mut self) -> Result<&'a mut [IMAGE_RUNTIME_FUNCTION_ENTRY]> {
        let exception_dir =
            &self.nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION as usize];
        if exception_dir.VirtualAddress == 0 {
            // there is no exception table
            return Ok(&mut []);
        }
        let exception_table = self
            .file
            .get_rva_mut::<IMAGE_RUNTIME_FUNCTION_ENTRY>(exception_dir.VirtualAddress as isize)
            .ok_or(Error(Err::ExceptionTableOutOfBounds))?;
        return Ok(unsafe {
            std::slice::from_raw_parts_mut(
                exception_table,
                exception_dir.Size as usize / std::mem::size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>(),
            )
        });
    }

    /// Initializes the loader entry
    fn init_ldr_entry(&mut self) -> Result<()> {
        self.loader_entry.DllBase = self.file.contents_mut();
        self.loader_entry.DdagNode = self.ddag_node.as_mut().get_mut();
        unsafe {
            RtlInitUnicodeString(&mut self.loader_entry.BaseDllName, self.file_name.as_ptr());
            RtlInitUnicodeString(&mut self.loader_entry.FullDllName, self.file_path.as_ptr());
        }
        // add the module hash value to the loader entry
        let mut hash = 0;
        unsafe {
            if RtlHashUnicodeString(
                &self.loader_entry.BaseDllName,
                true as u8,
                HASH_STRING_ALGORITHM_DEFAULT,
                &mut hash,
            ) != STATUS_SUCCESS
            {
                return Err(Error(Err::LdrEntry).into());
            }
        }
        self.loader_entry.BaseNameHashValue = hash;
        // set that we need to process static imports
        unsafe {
            self.loader_entry.u2.set_ProcessStaticImport(1);
        }
        // add the executable size
        self.loader_entry.SizeOfImage = self.nt_headers.OptionalHeader.SizeOfImage;
        self.ddag_node.State = LdrModulesReadyToRun;
        self.ddag_node.LoadCount = u32::MAX;
        // add to the loader hash table
        self.add_to_hash_table()?;
        // store that we initialized the loader entry such that we can remove it
        self.ldr_entry_init = true;
        Ok(())
    }

    /// Loads the portable executable, processing any options
    ///
    /// # Arguments
    ///
    /// `path`: The path to the executable file
    /// `context`: The resolved Nt Context
    pub fn load(path: &str, context: &'a NtContext<'a>) -> Result<PortableExecutable<'a>> {
        // first make sure we got all of the required functions
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
            file_name: to_wide(&file_name.to_string_lossy()),
            file_path: to_wide(&file_path.to_string_lossy()),
            nt_headers,
            section_headers,
            entry_point,
            section_protections: Vec::new(),
            loader_entry: Box::pin(LDR_DATA_TABLE_ENTRY {
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
            }),
            ddag_node: Box::pin(LDR_DDAG_NODE {
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
            }),
            context,
            ldr_entry_init: false,
        };
        pe.init_ldr_entry()?;
        pe.resolve_imports()?;
        pe.protect_sections()?;
        pe.enable_exceptions()?;
        pe.execute_tls_callbacks(DLL_PROCESS_ATTACH)?;
        pe.handle_tls_data()?;
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
        let address_of_ep = nt_headers.OptionalHeader.AddressOfEntryPoint;
        if address_of_ep == 0 {
            // PEs can sometimes not have entry points
            return Ok(None);
        }
        unsafe {
            // we transmute here because I have no earthly idea how to return a generic function
            let entry_point: PLDR_INIT_ROUTINE = std::mem::transmute(
                file.get_rva::<u8>(address_of_ep as isize).ok_or(Error(Err::EPOutOfBounds))?,
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
    pub unsafe fn run(mut self) -> u8 {
        self.call_entry_point(DLL_PROCESS_ATTACH)
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

impl<'a> Drop for PortableExecutable<'a> {
    // unload the loader entry. this is used for GetModuleHandle
    fn drop(&mut self) {
        // call each tls callback with process_detach
        if let Err(e) = self.execute_tls_callbacks(DLL_PROCESS_DETACH) {
            error!("Failed to execute TLS callbacks on exit: {}", e.to_string())
        };
        // call the entry point with detach
        self.call_entry_point(DLL_PROCESS_DETACH);
        // disable exceptions afterwards in case a TLS callback uses them
        if let Err(e) = self.disable_exceptions() {
            error!("Failed to disable exceptions: {}", e.to_string())
        }
        // finally, remove ourselves from the hash table
        if self.ldr_entry_init {
            if let Err(e) = self.remove_from_hash_table() {
                error!("Failed to remove entry from hash table: {}", e.to_string())
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::server::Server;
    use lazy_static::lazy_static;
    use serial_test::serial;
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Once,
        thread,
    };
    use tokio::runtime::Runtime;
    use winapi::shared::winerror::{
        ERROR_BAD_EXE_FORMAT, ERROR_MOD_NOT_FOUND, ERROR_PROC_NOT_FOUND,
    };

    static INIT: Once = Once::new();

    lazy_static! {
        static ref NT_CONTEXT: NtContext<'static> = Runtime::new()
            .unwrap()
            .block_on(NtContext::resolve("localhost", 42221))
            .unwrap();
    }

    fn setup() {
        INIT.call_once(|| {
            let server = Server::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 42221),
                "test/cache.json".into(),
            )
            .unwrap();
            thread::spawn(move || {
                Runtime::new().unwrap().block_on(server.run()).unwrap();
            });
        });
    }

    #[test]
    #[serial]
    fn bad_dos() {
        setup();
        let err: std::io::Error = PortableExecutable::load("test/baddos.exe", &NT_CONTEXT)
            .err()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(err.raw_os_error().unwrap(), ERROR_BAD_EXE_FORMAT as i32);
    }

    #[test]
    #[serial]
    fn bad_section() {
        setup();
        let err: std::io::Error = PortableExecutable::load("test/badsection.exe", &NT_CONTEXT)
            .err()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(err.raw_os_error().unwrap(), ERROR_BAD_EXE_FORMAT as i32);
    }

    #[test]
    #[serial]
    fn bad_entry() {
        setup();
        let err: Error = PortableExecutable::load("test/badentry.exe", &NT_CONTEXT)
            .err()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(err.0, Err::EPOutOfBounds);
    }

    #[test]
    #[serial]
    fn bad_mod() {
        setup();
        let err: std::io::Error = PortableExecutable::load("test/badmod.exe", &NT_CONTEXT)
            .err()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(err.raw_os_error().unwrap(), ERROR_MOD_NOT_FOUND as i32);
    }

    #[test]
    #[serial]
    fn bad_proc() {
        setup();
        let err: std::io::Error = PortableExecutable::load("test/badproc.exe", &NT_CONTEXT)
            .err()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(err.raw_os_error().unwrap(), ERROR_PROC_NOT_FOUND as i32);
    }

    // we only support x86-64/ARM64 for now
    #[test]
    #[serial]
    fn bad_arch() {
        setup();
        let err: Error = PortableExecutable::load("test/x86.exe", &NT_CONTEXT)
            .err()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(err.0, Err::UnsupportedArch);
    }

    #[test]
    #[serial]
    fn basic_image() {
        setup();
        let image = PortableExecutable::load("test/basic.exe", &NT_CONTEXT).unwrap();
        unsafe {
            assert_eq!(image.run(), 23);
        }
    }

    #[test]
    #[serial]
    fn ldr_entry() {
        setup();
        {
            let _image = PortableExecutable::load("test/basic.exe", &NT_CONTEXT).unwrap();
            let handle = unsafe { GetModuleHandleW(to_wide("basic.exe").as_ptr()) };
            assert!(!handle.is_null());
        }
        let handle = unsafe { GetModuleHandleW(to_wide("basic.exe").as_ptr()) };
        assert!(handle.is_null());
    }

    #[test]
    #[serial]
    fn tls() {
        setup();
        let image = PortableExecutable::load("test/tls.exe", &NT_CONTEXT).unwrap();
        unsafe {
            assert_eq!(image.run(), 7);
        }
    }
}
