use winapi::um::{handleapi::CloseHandle, winnt::HANDLE};

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
        if self.handle.is_null() {
            return;
        }
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
