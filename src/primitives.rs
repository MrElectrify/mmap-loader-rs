use std::ptr::{null, null_mut};

use crate::bindings::Windows::Win32::{
    Foundation::{CloseHandle, HANDLE, PSTR},
    System::Diagnostics::Debug::*,
};

// A Win32 error with its associated string
pub struct Error {
    pub code: u32,
}

impl Error {
    /// Retrieves the error string, if the error is valid
    pub fn str(&self) -> Option<String> {
        let mut buf = [0; 256];
        unsafe {
            let size = FormatMessageA(
                FORMAT_MESSAGE_FROM_SYSTEM,
                null(),
                self.code as u32,
                0,
                PSTR(buf.as_mut_ptr()),
                0,
                null_mut(),
            );
            let str: String = String::from_utf8_lossy(&buf[..size as usize])
                .to_owned()
                .to_string();
            Some(str)
        }
    }
}

impl From<u32> for Error {
    fn from(code: u32) -> Self {
        Self { code }
    }
}

impl From<WIN32_ERROR> for Error {
    fn from(val: WIN32_ERROR) -> Self {
        Self::from(val.0)
    }
}

/// A raw HANDLE that is closed when dropped
pub struct Handle {
    pub handle: HANDLE,
}

impl From<HANDLE> for Handle {
    fn from(handle: HANDLE) -> Self {
        Self { handle }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if self.handle.is_null() || self.handle.is_invalid() {
            return;
        }
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
