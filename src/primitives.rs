use std::ptr::{null, null_mut};

use crate::bindings::Windows::Win32::{
    Foundation::{CloseHandle, HANDLE, PSTR},
    System::Diagnostics::Debug::*,
};

// A Win32 error with its associated string
#[derive(Debug)]
pub struct Error {
    pub code: WIN32_ERROR,
}

impl Error {
    /// Retrieves the error string, if the error is valid
    pub fn str(&self) -> Option<String> {
        let mut buf = [0; 256];
        unsafe {
            let size = FormatMessageA(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                null(),
                self.code.0 as u32,
                0,
                PSTR(buf.as_mut_ptr()),
                buf.len() as u32,
                null_mut(),
            );
            let str: String = String::from_utf8_lossy(&buf[..size as usize])
                .to_owned()
                .to_string();
            Some(str)
        }
    }
}

impl From<WIN32_ERROR> for Error {
    fn from(code: WIN32_ERROR) -> Self {
        Self { code }
    }
}

impl From<u32> for Error {
    fn from(code: u32) -> Self {
        Self::from(WIN32_ERROR(code))
    }
}

/// A raw HANDLE that is closed when dropped
#[derive(Debug)]
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn empty_error() {
        let e = Error::from(ERROR_SUCCESS);
        assert_eq!(e.code, ERROR_SUCCESS);
        assert_eq!(
            e.str().unwrap(),
            "The operation completed successfully.\r\n"
        );
    }

    #[test]
    fn generic_error() {
        let e = Error::from(ERROR_ACCESS_DENIED);
        assert_eq!(e.code, ERROR_ACCESS_DENIED);
        assert_eq!(e.str().unwrap(), "Access is denied.\r\n");
    }
}
