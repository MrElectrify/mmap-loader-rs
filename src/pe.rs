use crate::{
    error::Error,
    map::MappedFile,
    offsets::{
        offset_client::OffsetClient, offset_server::Offset, OffsetsRequest, OffsetsResponse,
    },
    primitives::{protected_write, rtl_rb_tree_insert, ProtectionGuard, RtlMutex},
    server::OffsetHandler,
    util::to_wide,
};
use log::debug;
use ntapi::{
    ntldr::{
        LDR_DATA_TABLE_ENTRY_u1, LDR_DATA_TABLE_ENTRY_u2, LDR_DDAG_NODE_u, LdrModulesReadyToRun,
        LDRP_CSLIST, LDR_DATA_TABLE_ENTRY, LDR_DDAG_NODE, LDR_DDAG_STATE, PLDR_INIT_ROUTINE,
    },
    ntpsapi::NtCurrentPeb,
    ntrtl::{
        InsertTailList, RemoveEntryList, RtlHashUnicodeString, RtlImageDirectoryEntryToData,
        RtlInitUnicodeString, RtlRbRemoveNode, HASH_STRING_ALGORITHM_DEFAULT, RTL_RB_TREE,
    },
};
use std::{
    ffi::{c_void, CStr, OsString},
    os::windows::prelude::OsStrExt,
    os::windows::prelude::*,
    path::Path,
    pin::Pin,
    ptr,
    ptr::null_mut,
};
use tonic::transport::Certificate;
use tonic::transport::Channel;
use tonic::transport::ClientTlsConfig;
use winapi::{
    shared::{
        guiddef::GUID,
        minwindef::HMODULE,
        ntdef::{
            LARGE_INTEGER, LIST_ENTRY, RTL_BALANCED_NODE, SINGLE_LIST_ENTRY, ULONGLONG,
            UNICODE_STRING,
        },
        ntstatus::STATUS_SUCCESS,
        winerror::ERROR_FILE_NOT_FOUND,
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

/// The context of internal Nt functions and statics that are
/// required for the mapper to work
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct NtContext {
    LdrpHashTable: RtlMutex<[LIST_ENTRY; 32]>,
    LdrpHandleTlsData: unsafe extern "stdcall" fn(*mut LDR_DATA_TABLE_ENTRY) -> i32,
    LdrpReleaseTlsEntry: unsafe extern "stdcall" fn(*mut LDR_DATA_TABLE_ENTRY, null: usize) -> i32,
    LdrpMappingInfoIndex: RtlMutex<RTL_RB_TREE>,
    LdrpModuleBaseAddressIndex: RtlMutex<RTL_RB_TREE>,
    RtlInitializeHistoryTable: unsafe extern "stdcall" fn(),
}

unsafe impl Send for NtContext {}

/// This allows us to hold a pointer across a wait point
struct Module(*const u8);

unsafe impl Send for Module {}

impl NtContext {
    /// Gets the loaded NTDLL hash
    ///
    /// # Arguments
    ///
    /// `ntdll`: The NTDLL instance pointer
    fn get_ntdll_hash(ntdll: *const u8) -> Result<String, Error> {
        unsafe {
            let dos_header = ntdll as *const IMAGE_DOS_HEADER;
            if dos_header.is_null() {
                return Err(Error::NtDllNotLoaded);
            }
            let nt_headers = &*((dos_header as *const u8).offset((*dos_header).e_lfanew as isize)
                as *const IMAGE_NT_HEADERS64);
            let debug_entry = &*((dos_header as *const u8).offset(
                nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG as usize]
                    .VirtualAddress as isize,
            ) as *const IMAGE_DEBUG_DIRECTORY);
            if debug_entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW {
                return Err(Error::NtDllDebugType);
            }
            let codeview_entry = &*((dos_header as *const u8)
                .offset(debug_entry.AddressOfRawData as isize)
                as *const IMAGE_DEBUG_CODEVIEW);
            if !codeview_entry
                .rsds_signature
                .eq_ignore_ascii_case("RSDS".as_bytes())
            {
                return Err(Error::NtDllRsdsSig);
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

    /// Processes an offsets response
    ///
    /// # Arguments
    ///
    /// `response`: The response to process
    fn process_response(response: OffsetsResponse, ntdll: *const u8) -> NtContext {
        unsafe {
            NtContext {
                LdrpHashTable: RtlMutex::from_ref(
                    &mut *(ntdll.offset(response.ldrp_hash_table as isize)
                        as *mut [LIST_ENTRY; 32]),
                    &mut *(ntdll.offset(response.ldrp_module_datatable_lock as isize)
                        as *mut RTL_SRWLOCK),
                ),
                #[allow(clippy::missing_transmute_annotations)]
                LdrpHandleTlsData: std::mem::transmute(
                    ntdll.offset(response.ldrp_handle_tls_data as isize),
                ),
                #[allow(clippy::missing_transmute_annotations)]
                LdrpReleaseTlsEntry: std::mem::transmute(
                    ntdll.offset(response.ldrp_release_tls_entry as isize),
                ),
                LdrpMappingInfoIndex: RtlMutex::from_ref(
                    &mut *(ntdll.offset(response.ldrp_mapping_info_index as isize)
                        as *mut RTL_RB_TREE),
                    &mut *(ntdll.offset(response.ldrp_module_datatable_lock as isize)
                        as *mut RTL_SRWLOCK),
                ),
                LdrpModuleBaseAddressIndex: RtlMutex::from_ref(
                    &mut *(ntdll.offset(response.ldrp_module_base_address_index as isize)
                        as *mut RTL_RB_TREE),
                    &mut *(ntdll.offset(response.ldrp_module_datatable_lock as isize)
                        as *mut RTL_SRWLOCK),
                ),
                #[allow(clippy::missing_transmute_annotations)]
                RtlInitializeHistoryTable: std::mem::transmute(
                    ntdll.offset(response.rtl_initialize_history_table as isize),
                ),
            }
        }
    }

    /// Resolves the context used by the mapper
    ///
    /// # Arguments
    ///
    /// `server_hostname`: The hostname of the endpoint of the PDB server
    ///
    /// `server_port`: The port of the endpoint of the PDB server
    pub async fn resolve<S: AsRef<str>>(
        server_hostname: S,
        server_port: u16,
    ) -> anyhow::Result<NtContext> {
        let channel = Channel::from_shared(format!(
            "http://{}:{}",
            server_hostname.as_ref(),
            server_port
        ))?;
        let mut client = OffsetClient::new(channel.connect().await?);
        // wrap this in a `Module` so we can send it across await points
        let ntdll = Module(unsafe { GetModuleHandleW(to_wide("ntdll").as_ptr()) as *const u8 });
        let request = tonic::Request::new(OffsetsRequest {
            ntdll_hash: NtContext::get_ntdll_hash(ntdll.0)?,
        });
        let response = client.get_offsets(request).await?.into_inner();
        Ok(NtContext::process_response(response, ntdll.0))
    }

    /// Resolves the context used by the mapper, over a secure TLS connection
    ///
    /// # Arguments
    ///
    /// `server_hostname`: The hostname of the endpoint of the PDB server
    ///
    /// `server_port`: The port of the endpoint of the PDB server
    ///
    /// `ca_cert`: A custom CA certificate. This is necessary if you have a
    /// self-signed certificate on the other end. If not specified, webPKI
    /// will use their store to verify the endpoint
    ///
    /// `domain`: The domain name to be verified
    pub async fn resolve_tls<S: AsRef<str>>(
        server_hostname: S,
        server_port: u16,
        ca_cert: Option<Certificate>,
        domain: Option<S>,
    ) -> anyhow::Result<NtContext> {
        let mut tls_config = ClientTlsConfig::new();
        // add a CA certificate in case a self-signed cert is used
        if let Some(ca_cert) = ca_cert {
            tls_config = tls_config.ca_certificate(ca_cert);
        }
        // add a pinned domain in case domain name verification is wanted
        if let Some(domain) = domain {
            tls_config = tls_config.domain_name(domain.as_ref());
        }
        let channel = Channel::from_shared(format!(
            "http://{}:{}",
            server_hostname.as_ref(),
            server_port
        ))?
        .tls_config(tls_config)?;
        let mut client = OffsetClient::new(channel.connect().await?);
        // wrap this in a `Module` so we can send it across await points
        let ntdll = Module(unsafe { GetModuleHandleW(to_wide("ntdll").as_ptr()) as *const u8 });
        let request = tonic::Request::new(OffsetsRequest {
            ntdll_hash: NtContext::get_ntdll_hash(ntdll.0)?,
        });
        let response = client.get_offsets(request).await?.into_inner();
        Ok(NtContext::process_response(response, ntdll.0))
    }

    /// Resolves the context used by the mapper
    ///
    /// # Arguments
    ///
    /// `handler`: The local handler
    pub async fn resolve_local(handler: &OffsetHandler) -> anyhow::Result<NtContext> {
        // wrap this in a `Module` so we can send it across await points
        let ntdll = Module(unsafe { GetModuleHandleW(to_wide("ntdll").as_ptr()) as *const u8 });
        let request = tonic::Request::new(OffsetsRequest {
            ntdll_hash: NtContext::get_ntdll_hash(ntdll.0)?,
        });
        let response = handler.get_offsets(request).await?.into_inner();
        Ok(NtContext::process_response(response, ntdll.0))
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct IMAGE_DEBUG_CODEVIEW {
    rsds_signature: [u8; 4],
    guid: GUID,
    age: u32,
}

/// Sets the image as the primary image. Useful
/// if you want `GetModuleHandle(null)` to return
/// the handle to the mapped image. Returns the
/// previous primary image base. The caller must ensure
/// that the module is valid while the primary image is
/// set, and must restore the old image base before it goes out
/// of scope
///
/// # Arguments
///
/// `image_base`: The base address of the image
unsafe fn set_as_primary_image(image_base: PVOID) -> PVOID {
    let peb = NtCurrentPeb();
    let old_base = (*peb).ImageBaseAddress;
    (*peb).ImageBaseAddress = image_base;
    old_base
}

/// A portable executable that is all nicely wrapped up in a class
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
    context: NtContext,
    added_to_hash_tbl: bool,
    added_to_index: bool,
    added_to_peb: bool,
    called_entry_point: bool,
    last_primary: Option<PVOID>,
}

macro_rules! from_field_mut {
    ($parent: path, $field: tt, $field_ptr: expr) => {
        ($field_ptr as usize - memoffset::offset_of!($parent, $field)) as *mut $parent
    };
}

impl<'a> PortableExecutable<'a> {
    /// Adds the module to the loader hash table, enabling functions like
    /// `GetModuleHandle` to work
    fn add_to_hash_table(&mut self) {
        // insert the entry into the hash table and other relevant structures
        unsafe {
            InsertTailList(
                &mut self.context.LdrpHashTable.lock()
                    [(self.loader_entry.BaseNameHashValue & 0x1f) as usize],
                &mut self.loader_entry.HashLinks,
            );
            self.added_to_hash_tbl = true;
        }
    }

    /// Removes the module from the loader hash table
    fn remove_from_hash_table(&mut self) {
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
            }
            entry = unsafe { (*entry).Flink };
        }
        debug!("Failed to find reference");
    }

    /// Adds the module to the index red-black trees
    fn add_to_index(&mut self) {
        // add it to the mapping information table
        unsafe {
            rtl_rb_tree_insert(
                &mut self.context.LdrpMappingInfoIndex.lock(),
                &mut self.loader_entry.MappingInfoIndexNode,
                |l, r| {
                    let l = from_field_mut!(LDR_DATA_TABLE_ENTRY, MappingInfoIndexNode, l);
                    let r = from_field_mut!(LDR_DATA_TABLE_ENTRY, MappingInfoIndexNode, r);
                    (*l).TimeDateStamp < (*r).TimeDateStamp
                        || ((*l).TimeDateStamp <= (*r).TimeDateStamp
                            && (*l).SizeOfImage < (*r).SizeOfImage)
                },
            );
            rtl_rb_tree_insert(
                &mut self.context.LdrpModuleBaseAddressIndex.lock(),
                &mut self.loader_entry.BaseAddressIndexNode,
                |l, r| {
                    let l = from_field_mut!(LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode, l);
                    let r = from_field_mut!(LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode, r);
                    (*l).DllBase < (*r).DllBase
                },
            )
        }
        self.added_to_index = true;
    }

    /// Removes the module from the index red-black trees
    fn remove_from_index(&mut self) {
        unsafe {
            RtlRbRemoveNode(
                &mut (*self.context.LdrpMappingInfoIndex.lock()),
                &mut self.loader_entry.MappingInfoIndexNode,
            );
            RtlRbRemoveNode(
                &mut (*self.context.LdrpModuleBaseAddressIndex.lock()),
                &mut self.loader_entry.BaseAddressIndexNode,
            );
        }
    }

    /// Adds the module to the PEB structures
    fn add_to_peb(&mut self) {
        unsafe {
            let peb = NtCurrentPeb();
            let ldr = (*peb).Ldr;
            InsertTailList(
                &mut (*ldr).InLoadOrderModuleList,
                &mut self.loader_entry.InLoadOrderLinks,
            );
            InsertTailList(
                &mut (*ldr).InMemoryOrderModuleList,
                &mut self.loader_entry.InMemoryOrderLinks,
            );
        }
        self.added_to_peb = true;
    }

    /// Removes the modules from the PEB structures
    fn remove_from_peb(&mut self) {
        unsafe {
            RemoveEntryList(&mut self.loader_entry.InLoadOrderLinks);
            RemoveEntryList(&mut self.loader_entry.InMemoryOrderLinks);
        }
    }

    /// Calls the function entry point
    ///
    /// # Arguments
    ///
    /// `reason`: The reason for the call. Ex: `DLL_PROCESS_ATTACH`
    unsafe fn call_entry_point(&mut self, reason: u32) -> u8 {
        if let Some(entry_point) = &self.entry_point {
            entry_point(self.file.contents_mut(), reason, null_mut())
        } else {
            0
        }
    }

    /// Enables exception handling for the module
    fn enable_exceptions(&mut self) -> Result<(), Error> {
        // get the exception table
        let exception_table = self.get_exception_table();
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
            return Err(Error::ExceptionTableEntry);
        }
        unsafe { (self.context.RtlInitializeHistoryTable)() }
        Ok(())
    }

    /// Disables exception handling for the module
    fn disable_exceptions(&mut self) -> Result<(), Error> {
        // get the exception table
        let exception_table = self.get_exception_table();
        if exception_table.is_empty() {
            return Ok(());
        }
        // remove the table from the process
        if unsafe { RtlDeleteFunctionTable(exception_table.as_mut_ptr()) == false as u8 } {
            return Err(Error::ExceptionTableEntry);
        }
        Ok(())
    }

    /// Execute TLS callbacks
    ///
    /// # Arguments
    ///
    /// `reason`: The reason for the call to the callbacks
    fn execute_tls_callbacks(&mut self, reason: u32) -> Result<(), Error> {
        let tls_directory =
            &self.nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS as usize];
        // navigate to the tls directory if it exists
        if tls_directory.VirtualAddress == 0 {
            return Ok(());
        }
        let tls_directory = self
            .file
            .get_rva::<IMAGE_TLS_DIRECTORY>(tls_directory.VirtualAddress as isize)
            .ok_or(Error::TLSOutOfBounds)?;
        let tls_callbacks = unsafe { (*tls_directory).AddressOfCallBacks };
        // it is possible that callbacks may not exist
        if tls_callbacks == 0 {
            return Ok(());
        }
        let mut tls_callback = self
            .file
            .get_rva::<Option<unsafe extern "stdcall" fn(PVOID, u32, PVOID)>>(
                (tls_callbacks - self.file.contents() as u64) as isize,
            )
            .ok_or(Error::CallbackOutOfBounds)?;
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

    /// Frees all TLS data
    fn free_tls_data(&mut self) -> Result<(), Error> {
        if unsafe { (self.context.LdrpReleaseTlsEntry)(self.loader_entry.as_mut().get_mut(), 0) }
            != STATUS_SUCCESS
        {
            Err(Error::TLSData)
        } else {
            Ok(())
        }
    }

    /// Handle TLS data
    fn handle_tls_data(&mut self) -> Result<(), Error> {
        if unsafe { (self.context.LdrpHandleTlsData)(self.loader_entry.as_mut().get_mut()) }
            != STATUS_SUCCESS
        {
            Err(Error::TLSData)
        } else {
            Ok(())
        }
    }

    /// Gets the exception table for the module, and its size
    fn get_exception_table(&mut self) -> &'a mut [IMAGE_RUNTIME_FUNCTION_ENTRY] {
        let mut size: u32 = 0;
        let table = unsafe {
            #[allow(clippy::missing_transmute_annotations)]
            std::mem::transmute(RtlImageDirectoryEntryToData(
                self.file.contents_mut(),
                1,
                IMAGE_DIRECTORY_ENTRY_EXCEPTION,
                &mut size,
            ))
        };
        unsafe {
            std::slice::from_raw_parts_mut(
                table,
                size as usize / std::mem::size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>(),
            )
        }
    }

    /// Initializes the loader entry
    fn init_ldr_entry(&mut self) -> Result<(), Error> {
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
                return Err(Error::LdrEntry);
            }
        }
        self.loader_entry.BaseNameHashValue = hash;
        // set that we need to process static imports
        unsafe {
            self.loader_entry.u2.set_ProcessStaticImport(1);
        }
        // add the executable size
        self.loader_entry.TimeDateStamp = self.nt_headers.FileHeader.TimeDateStamp;
        self.loader_entry.SizeOfImage = self.nt_headers.OptionalHeader.SizeOfImage;
        self.ddag_node.State = LdrModulesReadyToRun;
        self.ddag_node.LoadCount = u32::MAX;
        // add to the loader hash table
        self.add_to_hash_table();
        // add to the red-black trees for traversal
        self.add_to_index();
        // add to the PEB linked lists
        self.add_to_peb();
        Ok(())
    }

    /// Loads the portable executable, processing any options
    ///
    /// # Arguments
    ///
    /// `path`: The path to the executable file
    ///
    /// `context`: The resolved Nt Context
    pub fn load(path: &str, context: NtContext) -> Result<PortableExecutable<'a>, anyhow::Error> {
        PortableExecutable::load_as_primary(path, context, false)
    }

    /// Loads the portable executable, processing any options
    ///
    /// # Arguments
    ///
    /// `path`: The path to the executable file
    ///
    /// `context`: The resolved Nt Context
    ///
    /// `primary`: Whether or not this module should be the primary
    /// module, and be returned upon invocation of `GetModuleHandle(null)`
    pub fn load_as_primary(
        path: &str,
        context: NtContext,
        primary: bool,
    ) -> Result<PortableExecutable<'a>, anyhow::Error> {
        // first make sure we got all of the required functions
        let mut file = MappedFile::load(path)?;
        let path = Path::new(path);
        let file_name: Vec<u16> = path
            .file_name()
            .ok_or_else(|| std::io::Error::from_raw_os_error(ERROR_FILE_NOT_FOUND as i32))?
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // remove the "extended length path syntax"
        let file_path: Vec<u16> = path
            .canonicalize()?
            .as_os_str()
            .encode_wide()
            .skip(4)
            .chain(std::iter::once(0))
            .collect();
        debug!(
            "Loading {} at path {}",
            OsString::from_wide(&file_name[..])
                .as_os_str()
                .to_string_lossy(),
            OsString::from_wide(&file_path[..])
                .as_os_str()
                .to_string_lossy()
        );
        let (nt_headers, section_headers) = PortableExecutable::load_headers(&mut file)?;
        let entry_point = PortableExecutable::load_entry_point(&mut file, nt_headers)?;
        let mut pe = PortableExecutable {
            file,
            file_name,
            file_path,
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
                ObsoleteLoadCount: u16::MAX,
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
            added_to_hash_tbl: false,
            added_to_index: false,
            added_to_peb: false,
            called_entry_point: false,
            last_primary: None,
        };
        pe.init_ldr_entry()?;
        pe.resolve_imports()?;
        pe.protect_sections()?;
        pe.enable_exceptions()?;
        if primary {
            pe.set_self_as_primary_image();
        }
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
    ) -> Result<PLDR_INIT_ROUTINE, Error> {
        let address_of_ep = nt_headers.OptionalHeader.AddressOfEntryPoint;
        if address_of_ep == 0 {
            // PEs can sometimes not have entry points
            return Ok(None);
        }
        unsafe {
            // we transmute here because I have no earthly idea how to return a generic function
            let entry_point: PLDR_INIT_ROUTINE = std::mem::transmute(
                file.get_rva::<u8>(address_of_ep as isize)
                    .ok_or(Error::EPOutOfBounds)?,
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
    ) -> Result<(&'a IMAGE_NT_HEADERS64, &'a [IMAGE_SECTION_HEADER]), Error> {
        unsafe {
            let dos_header = &*file
                .get_rva::<IMAGE_DOS_HEADER>(0)
                .ok_or(Error::DOSOutOfBounds)?;
            let nt_headers = &*file
                .get_rva::<IMAGE_NT_HEADERS64>(dos_header.e_lfanew as isize)
                .ok_or(Error::NTOutOfBounds)?;
            // ensure supported architecture
            if nt_headers.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
                || nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
            {
                return Err(Error::UnsupportedArch);
            }
            // load section headers
            let section_headers = std::slice::from_raw_parts(
                file.get_rva_size_chk::<IMAGE_SECTION_HEADER>(
                    dos_header.e_lfanew as isize
                        + std::mem::size_of::<IMAGE_NT_HEADERS64>() as isize,
                    nt_headers.FileHeader.NumberOfSections as usize
                        * std::mem::size_of::<IMAGE_SECTION_HEADER>(),
                )
                .ok_or(Error::SectOutOfBounds)?,
                nt_headers.FileHeader.NumberOfSections as usize,
            );
            Ok((nt_headers, section_headers))
        }
    }

    /// Returns the handle for the loaded process
    pub fn module_handle(&mut self) -> HMODULE {
        self.file.contents() as HMODULE
    }

    /// Protects all of the sections with their specified protections
    fn protect_sections(&mut self) -> Result<(), anyhow::Error> {
        for &section in self.section_headers {
            unsafe {
                self.section_protections.push(ProtectionGuard::new(
                    self.file
                        .get_rva_mut::<c_void>(section.VirtualAddress as isize)
                        .ok_or(Error::SectOutOfBounds)?,
                    *section.Misc.VirtualSize() as usize,
                    PortableExecutable::section_flags_to_prot(section.Characteristics),
                )?)
            }
        }
        Ok(())
    }

    /// Resolves imports from the NT headers
    fn resolve_imports(&mut self) -> anyhow::Result<()> {
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
                .ok_or(Error::IDOutOfBounds)?;
            // ignore the alignment check here to better support packed/encrypted executables
            self.resolve_import_descriptors(&*ptr::slice_from_raw_parts(
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
    pub fn resolve_import_descriptors(
        &mut self,
        table: &[IMAGE_IMPORT_DESCRIPTOR],
    ) -> anyhow::Result<()> {
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
                .ok_or(Error::LibNameOutOfBounds)?;
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
                    .ok_or(Error::IATOutOfBounds)?;
                while (*thunk).u1.AddressOfData() != &0 {
                    let proc_name = if ((*thunk).u1.Ordinal() & IMAGE_ORDINAL_FLAG) != 0 {
                        (*(*thunk).u1.Ordinal() & !IMAGE_ORDINAL_FLAG) as *const i8
                    } else {
                        &(*self
                            .file
                            .get_rva::<IMAGE_IMPORT_BY_NAME>(*(*thunk).u1.AddressOfData() as isize)
                            .ok_or(Error::ProcNameOutOfBounds)?)
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
                            return Err(Error::NullProcName.into());
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
    /// the underlying executable is safe. This function panics if the executable
    /// entry point has already been called
    pub unsafe fn run(&mut self) -> u8 {
        if self.called_entry_point {
            panic!("OEP already called")
        }
        let res = self.call_entry_point(DLL_PROCESS_ATTACH);
        self.called_entry_point = true;
        res
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

    /// Sets this mapped image as the primary image,
    /// as if by calling `set_as_primary_image(self.module_handle())`.
    fn set_self_as_primary_image(&mut self) {
        self.last_primary =
            Some(unsafe { set_as_primary_image(self.module_handle() as *mut c_void) });
    }
}

impl<'a> Drop for PortableExecutable<'a> {
    // unload the loader entry. this is used for GetModuleHandle
    fn drop(&mut self) {
        // call each tls callback with process_detach
        if let Err(e) = self.execute_tls_callbacks(DLL_PROCESS_DETACH) {
            debug!("Failed to execute TLS callbacks on exit: {}", e.to_string())
        };
        // call the entry point with detach
        unsafe { self.call_entry_point(DLL_PROCESS_DETACH) };
        // disable exceptions afterwards in case a TLS callback uses them
        if let Err(e) = self.disable_exceptions() {
            debug!("Failed to disable exceptions: {}", e.to_string())
        }
        // remove ourselves from the PEB
        if self.added_to_peb {
            self.remove_from_peb();
        }
        // remove ourselves from the index RB trees
        if self.added_to_index {
            self.remove_from_index();
        }
        // remove ourselves from the hash table
        if self.added_to_hash_tbl {
            self.remove_from_hash_table();
        }
        // free TLS data
        if let Err(e) = self.free_tls_data() {
            debug!("Failed to free TLS data: {}", e.to_string())
        }
        // ensure we are not the primary image anymore
        if let Some(last_image) = self.last_primary {
            unsafe { set_as_primary_image(last_image) };
        }
    }
}

unsafe impl<'a> Send for PortableExecutable<'a> {}

#[cfg(test)]
mod test {
    use super::*;
    use lazy_static::lazy_static;
    use serial_test::serial;
    use std::ptr::null;
    use tokio::runtime::Runtime;
    use winapi::{
        shared::winerror::{ERROR_BAD_EXE_FORMAT, ERROR_MOD_NOT_FOUND, ERROR_PROC_NOT_FOUND},
        um::libloaderapi::GetModuleFileNameW,
    };

    lazy_static! {
        static ref NT_CONTEXT: NtContext = Runtime::new()
            .unwrap()
            .block_on(NtContext::resolve_local(
                &OffsetHandler::new("test/cache.json").unwrap()
            ))
            .unwrap();
    }

    #[test]
    #[serial]
    fn bad_dos() {
        let err: std::io::Error = PortableExecutable::load("test/baddos.exe", NT_CONTEXT.clone())
            .err()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(err.raw_os_error().unwrap(), ERROR_BAD_EXE_FORMAT as i32);
    }

    #[test]
    #[serial]
    fn bad_section() {
        let err: std::io::Error =
            PortableExecutable::load("test/badsection.exe", NT_CONTEXT.clone())
                .err()
                .unwrap()
                .downcast()
                .unwrap();
        assert_eq!(err.raw_os_error().unwrap(), ERROR_BAD_EXE_FORMAT as i32);
    }

    #[test]
    #[serial]
    fn bad_entry() {
        let err: Error = PortableExecutable::load("test/badentry.exe", NT_CONTEXT.clone())
            .err()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(err, Error::EPOutOfBounds);
    }

    #[test]
    #[serial]
    fn bad_mod() {
        let err: std::io::Error = PortableExecutable::load("test/badmod.exe", NT_CONTEXT.clone())
            .err()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(err.raw_os_error().unwrap(), ERROR_MOD_NOT_FOUND as i32);
    }

    #[test]
    #[serial]
    fn bad_proc() {
        let err: std::io::Error = PortableExecutable::load("test/badproc.exe", NT_CONTEXT.clone())
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
        let err: Error = PortableExecutable::load("test/x86.exe", NT_CONTEXT.clone())
            .err()
            .unwrap()
            .downcast()
            .unwrap();
        assert_eq!(err, Error::UnsupportedArch);
    }

    #[test]
    #[serial]
    fn basic_image() {
        let mut image = PortableExecutable::load("test/basic.exe", NT_CONTEXT.clone()).unwrap();
        unsafe {
            assert_eq!(image.run(), 23);
        }
    }

    #[test]
    #[serial]
    fn ldr_entry() {
        let mut file_name_buf = [0 as u16; 128];
        let handle;
        {
            let _image = PortableExecutable::load("test/basic.exe", NT_CONTEXT.clone()).unwrap();
            handle = unsafe { GetModuleHandleW(to_wide("basic.exe").as_ptr()) };
            assert!(!handle.is_null());
            let name_len = unsafe {
                GetModuleFileNameW(
                    handle,
                    file_name_buf.as_mut_ptr(),
                    file_name_buf.len() as u32,
                )
            };
            assert_ne!(name_len, 0);
        }
        assert!(unsafe { GetModuleHandleW(to_wide("basic.exe").as_ptr()) }.is_null());
        assert_eq!(
            unsafe {
                GetModuleFileNameW(
                    handle,
                    file_name_buf.as_mut_ptr(),
                    file_name_buf.len() as u32,
                )
            },
            0
        );
    }

    #[test]
    #[serial]
    fn tls() {
        let mut image = PortableExecutable::load("test/tls.exe", NT_CONTEXT.clone()).unwrap();
        unsafe {
            assert_eq!(image.run(), 7);
        }
    }

    #[test]
    #[serial]
    fn primary_image() {
        let original_handle = unsafe { GetModuleHandleW(null()) };
        {
            let mut image = PortableExecutable::load("test/basic.exe", NT_CONTEXT.clone()).unwrap();
            assert_ne!(image.module_handle(), unsafe { GetModuleHandleW(null()) });
            image.set_self_as_primary_image();
            assert_eq!(image.module_handle(), unsafe { GetModuleHandleW(null()) });
        }
        assert_eq!(original_handle, unsafe { GetModuleHandleW(null()) });
    }

    #[tokio::test]
    #[serial]
    #[cfg(feature = "server")]
    async fn tls_server() {
        use crate::server::Server;
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
        use tonic::transport::Identity;
        // start the server
        let endpoint = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 44443));
        // we stole these certificates from the tonic test suite
        let cert = tokio::fs::read("test/server.pem").await.unwrap();
        let key = tokio::fs::read("test/server.key").await.unwrap();
        let identity = Identity::from_pem(cert, key);
        let server = Server::new(endpoint, "test/tls_cache.json", Some(identity)).unwrap();
        // resolve
        let ca_cert = tokio::fs::read("test/ca.pem").await.unwrap();
        let ca_cert = Certificate::from_pem(ca_cert);
        tokio::select! {
            _ = server.run() => {},
            res = NtContext::resolve_tls("localhost", 44443, Some(ca_cert), None) => { res.unwrap(); }
        };
    }
}
