use std::{
    cell::UnsafeCell,
    ffi::c_void,
    io::Result,
    ops::{Deref, DerefMut},
};

use ntapi::ntrtl::{RtlReleaseSRWLockExclusive, RtlTryAcquireSRWLockExclusive};
use winapi::{
    shared::minwindef::DWORD,
    um::{
        handleapi::CloseHandle,
        memoryapi::VirtualProtect,
        winnt::{HANDLE, PAGE_READWRITE, RTL_SRWLOCK},
    },
};

/// A raw HANDLE that is closed when dropped
#[derive(Debug)]
pub struct Handle {
    pub handle: HANDLE,
}

/// Protects a region of memory for the lifetime of the object
pub struct ProtectionGuard {
    addr: *mut c_void,
    size: usize,
    old_prot: DWORD,
}

/// A mutex based on an RTL Slim Read/Write lock
pub struct RtlMutex<'a, T> {
    val_ref: UnsafeCell<&'a mut T>,
    lock_ref: UnsafeCell<&'a mut RTL_SRWLOCK>,
}

/// A mutex guard that allows access to the value, and locks it upon `Drop`
pub struct RtlMutexGuard<'a, T> {
    mutex: &'a RtlMutex<'a, T>,
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
    let _prot_guard = ProtectionGuard::new(
        addr as *mut c_void,
        std::mem::size_of_val(&val),
        PAGE_READWRITE,
    )?;
    // write the value
    *addr = val;
    Ok(())
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
                0 => Err(std::io::Error::last_os_error()),
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

impl<'a, T> RtlMutex<'a, T> {
    /// Locks the mutex and allows for access of the variable
    pub fn lock(&'a self) -> RtlMutexGuard<'a, T> {
        unsafe {
            RtlTryAcquireSRWLockExclusive(*self.lock_ref.get());
        }
        RtlMutexGuard { mutex: self }
    }

    /// Creates a new mutex wrapped around a Rtl Slim Read/Write lock
    ///
    /// # Arguments
    ///
    /// `val_ref`: The reference to the value protected by the lock
    /// `lock`: The lock
    pub fn from_ref(val_ref: &'a mut T, lock_ref: &'a mut RTL_SRWLOCK) -> RtlMutex<'a, T> {
        RtlMutex {
            val_ref: UnsafeCell::new(val_ref),
            lock_ref: UnsafeCell::new(lock_ref),
        }
    }
}

unsafe impl<'a, T> Send for RtlMutex<'a, T> {}
unsafe impl<'a, T> Sync for RtlMutex<'a, T> {}

impl<'a, T> Deref for RtlMutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { *self.mutex.val_ref.get() }
    }
}

impl<'a, T> DerefMut for RtlMutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { *self.mutex.val_ref.get() }
    }
}

impl<'a, T> Drop for RtlMutexGuard<'a, T> {
    fn drop(&mut self) {
        unsafe { RtlReleaseSRWLockExclusive(*self.mutex.lock_ref.get()) }
    }
}
