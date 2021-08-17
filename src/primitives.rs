use crate::bindings::Windows::Win32::Foundation::{CloseHandle, HANDLE};

use ntapi::winapi::shared::ntdef;

/// A raw HANDLE that is closed when dropped
pub struct RawHandle {
    pub handle: HANDLE,
}

impl From<ntdef::HANDLE> for RawHandle {
    fn from(handle: ntdef::HANDLE) -> Self {
        Self {
            handle: HANDLE(handle as isize)
        }
    }
}

impl Drop for RawHandle {
    fn drop(&mut self) {
        if self.handle.is_null() {
            return;
        }
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
