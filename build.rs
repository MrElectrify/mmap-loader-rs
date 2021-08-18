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
                    FILE_MAP,
                    PAGE_PROTECTION_FLAGS
                },
            },
        }
    }
}
