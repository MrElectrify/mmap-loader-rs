use std::ffi::c_void;

use anyhow::Result;

use winapi::{
    shared::minwindef::DWORD,
    um::{
        handleapi::CloseHandle,
        memoryapi::VirtualProtect,
        winnt::{HANDLE, PAGE_READWRITE},
    },
};

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

/// Protects a region of memory for the lifetime of the object
pub struct ProtectionGuard {
    addr: *mut c_void,
    size: usize,
    old_prot: DWORD,
}

impl ProtectionGuard {
    /// Protects a region of the memory
    ///
    /// # Arguments
    ///
    /// `addr`: The base address to protect
    /// `size`: The number of bytes to protect
    /// `prot`: The protection to protect with
    pub fn new(addr: *mut c_void, size: usize, prot: DWORD) -> Result<Self> {
        let mut old_prot = 0;
        unsafe {
            match VirtualProtect(addr, size, prot, &mut old_prot) {
                0 => Err(std::io::Error::last_os_error().into()),
                _ => Ok(ProtectionGuard {
                    addr,
                    size,
                    old_prot,
                }),
            }
        }
    }
}

impl Drop for ProtectionGuard {
    fn drop(&mut self) {
        let mut dummy = 0;
        unsafe {
            VirtualProtect(self.addr, self.size, self.old_prot, &mut dummy);
        }
    }
}

/// Writes to protected memory, enforcing a new protection for
/// the duration of the write
///
/// # Arguments
///
/// `addr`: The address to write to
/// `val`: The value to write
pub unsafe fn protected_write<T>(addr: *mut T, val: T) -> Result<()> {
    // protect the value first with READWRITE
    let _ = ProtectionGuard::new(
        addr as *mut c_void,
        std::mem::size_of_val(&val),
        PAGE_READWRITE,
    )?;
    // write the value
    *addr = val;
    Ok(())
}
