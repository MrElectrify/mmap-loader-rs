fn main() {
    windows::build! {
        Windows::Win32::{
            Foundation::{CloseHandle, HANDLE},
            Storage::FileSystem::*,
            System::{
                Diagnostics::Debug::*,
                Memory::{
                    CreateFileMappingA,
                    MapViewOfFile,
                    UnmapViewOfFile,
                    VirtualQuery,
                    FILE_MAP,
                    MEMORY_BASIC_INFORMATION,
                    PAGE_PROTECTION_FLAGS
                },
                SystemServices::{
                    DLL_PROCESS_ATTACH,
                    IMAGE_DOS_HEADER,
                },
            },
        }
    }
}
