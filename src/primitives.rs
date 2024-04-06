use ntapi::ntrtl::{
    RtlRbInsertNodeEx, RtlReleaseSRWLockExclusive, RtlTryAcquireSRWLockExclusive, RTL_RB_TREE,
};
use std::{ffi::c_void, io::Result, ops::{Deref, DerefMut}, ptr, ptr::null_mut};
use winapi::{
    shared::{minwindef::DWORD, ntdef::PRTL_BALANCED_NODE},
    um::{
        handleapi::CloseHandle,
        memoryapi::VirtualProtect,
        winnt::{HANDLE, PAGE_READWRITE, RTL_SRWLOCK},
    },
};

/// Insert a node into a red-black tree
///
/// # Arguments
///
/// `tree`: The tree that is being operated on
///
/// `node`: The node to insert
///
/// `compare`: The function that returns true if the first node is *less* than the second node
pub unsafe fn rtl_rb_tree_insert<F: Fn(PRTL_BALANCED_NODE, PRTL_BALANCED_NODE) -> bool>(
    tree: &mut RTL_RB_TREE,
    node: PRTL_BALANCED_NODE,
    compare: F,
) {
    // find the node and position to insert
    let (parent, right) = rtl_rb_tree_find_insert_location(tree, node, compare);
    RtlRbInsertNodeEx(tree, parent, right as u8, node);
}

/// Accesses a node based on the encoding mode
///
/// # Arguments
///
/// `tree`: The tree that the node is part of
///
/// `node`: The node that is attempting to be accessed.
/// The pointer to pointer must not be null
unsafe fn rtl_rb_tree_access_node(
    tree: &mut RTL_RB_TREE,
    node: *const PRTL_BALANCED_NODE,
) -> PRTL_BALANCED_NODE {
    if (tree.Min as u64 & 1) != 0 {
        if (*node).is_null() {
            return null_mut();
        }
        // it is xor-encoded in relation to its address
        (node as u64 ^ (*node) as u64) as PRTL_BALANCED_NODE
    } else {
        *node
    }
}

/// Finds the proper insert location for an RTL red-black tree
///
/// # Arguments
///
/// `tree`: The tree
///
/// `node`: The node to insert
///
/// `compare`: The function that returns true if the first node is *less* than the second node
unsafe fn rtl_rb_tree_find_insert_location<
    F: Fn(PRTL_BALANCED_NODE, PRTL_BALANCED_NODE) -> bool,
>(
    tree: &mut RTL_RB_TREE,
    node: PRTL_BALANCED_NODE,
    compare: F,
) -> (PRTL_BALANCED_NODE, bool) {
    let mut cur_node = rtl_rb_tree_access_node(tree, &tree.Root);
    let mut next_node;
    let mut right = false;
    while !cur_node.is_null() {
        if compare(node, cur_node) {
            // the node is less, and goes left
            next_node = rtl_rb_tree_access_node(tree, &(*cur_node).u.s().Left);
            if next_node.is_null() {
                right = false;
                break;
            }
        } else {
            next_node = rtl_rb_tree_access_node(tree, &(*cur_node).u.s().Right);
            if next_node.is_null() {
                right = true;
                break;
            }
        }
        cur_node = next_node;
    }
    (cur_node, right)
}

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
#[derive(Clone)]
pub struct RtlMutex<T> {
    val_ref: *mut T,
    lock_ref: *mut RTL_SRWLOCK,
}

/// A mutex guard that allows access to the value, and locks it upon `Drop`
pub struct RtlMutexGuard<'a, T> {
    mutex: &'a RtlMutex<T>,
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
    ptr::write_unaligned(addr, val);
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
    ///
    /// `size`: The number of bytes to protect
    ///
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

impl<T> RtlMutex<T> {
    /// Locks the mutex and allows for access of the variable
    pub fn lock(&self) -> RtlMutexGuard<T> {
        unsafe {
            RtlTryAcquireSRWLockExclusive(self.lock_ref);
        }
        RtlMutexGuard { mutex: self }
    }

    /// Creates a new mutex wrapped around a Rtl Slim Read/Write lock
    ///
    /// # Arguments
    ///
    /// `val_ref`: The reference to the value protected by the lock
    /// `lock`: The lock
    pub fn from_ref(val_ref: *mut T, lock_ref: *mut RTL_SRWLOCK) -> RtlMutex<T> {
        RtlMutex { val_ref, lock_ref }
    }
}

unsafe impl<T> Send for RtlMutex<T> {}
unsafe impl<T> Sync for RtlMutex<T> {}

impl<'a, T> Deref for RtlMutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.mutex.val_ref }
    }
}

impl<'a, T> DerefMut for RtlMutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.mutex.val_ref }
    }
}

impl<'a, T> Drop for RtlMutexGuard<'a, T> {
    fn drop(&mut self) {
        unsafe { RtlReleaseSRWLockExclusive(self.mutex.lock_ref) }
    }
}
