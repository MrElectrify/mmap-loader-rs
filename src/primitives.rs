use winapi::um::{handleapi::CloseHandle, winnt::HANDLE};

/// A raw HANDLE that is closed when dropped
#[derive(Debug)]
pub struct Handle {
    pub handle: HANDLE,
}

impl Handle {
    /// Returns whether or not the handle is null or `INVALID_HANDLE_VALUE`
    pub fn is_invalid(&self) -> bool {
        self.is_null() || (self.handle as i64) == -1
    }
    /// Returns whether or not the handle is null
    pub fn is_null(&self) -> bool {
        self.handle.is_null()
    }
}

impl From<HANDLE> for Handle {
    fn from(handle: HANDLE) -> Self {
        Self { handle }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if self.is_invalid() {
            return;
        }
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
