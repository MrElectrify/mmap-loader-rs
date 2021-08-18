fn main() {
    windows::build! {
        Windows::Win32::Foundation::{CloseHandle, HANDLE},
        Windows::Win32::Storage::FileSystem::*,
        Windows::Win32::System::{
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
