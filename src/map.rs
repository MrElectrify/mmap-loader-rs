use std::{convert::TryFrom, ptr::null_mut};

use crate::bindings::Windows::Win32::{Foundation, System::Threading::GetCurrentProcess};

use ntapi::{
    ntmmapi::{NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection},
    winapi::{
        shared::ntdef,
        shared::ntdef::NTSTATUS,
        um::winnt::{PAGE_EXECUTE, PVOID, SECTION_ALL_ACCESS, SEC_IMAGE},
    },
};

struct MappedFile {
    image_base: PVOID,
}

impl TryFrom<Foundation::HANDLE> for MappedFile {
    type Error = NTSTATUS;

    fn try_from(file_handle: Foundation::HANDLE) -> Result<Self, Self::Error> {
        // try to create a section
        let mut section_handle: ntdef::HANDLE = null_mut();
        unsafe {
            match NtCreateSection(
                &mut section_handle,
                SECTION_ALL_ACCESS,
                null_mut(),
                null_mut(),
                PAGE_EXECUTE,
                SEC_IMAGE,
                file_handle.0 as ntdef::HANDLE,
            ) {
                0 => {},
                err => return Err(err)
            };
        }
        // track the raw handle
        let mut section_handle = crate::primitives::RawHandle::from(section_handle);
        Ok(Self {
            image_base: null_mut(),
        })
    }
}

impl Drop for MappedFile {
    fn drop(&mut self) {
        unsafe {
            NtUnmapViewOfSection(GetCurrentProcess().0 as ntdef::HANDLE, self.image_base);
        }
    }
}
