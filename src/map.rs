use anyhow::Result;

use crate::{primitives::Handle, util::to_wide};

use std::{
    ffi::c_void,
    io::Error,
    ptr::{null, null_mut},
};

use winapi::um::{fileapi::*, memoryapi::*, winbase::*, winnt::*};

// A mapped executable image file in the process's address space
#[derive(Debug)]
pub struct MappedFile {
    file: Handle,
    mapping: Handle,
    contents: *mut c_void,
}

impl MappedFile {
    /// Returns the contents of the mapped file
    pub fn contents(&self) -> *const c_void {
        self.contents
    }

    /// Gets the data at an RVA offset, checking to make sure
    ///
    /// # Arguments
    ///
    /// `offset`: The RVA offset to the data
    /// `required_size`: The required size of the allocation
    pub fn get_rva_size_chk<T>(&self, offset: isize, required_size: usize) -> Option<*const T> {
        unsafe {
            let res = (self.contents as *const u8).offset(offset) as *const T;
            // query the memory location and ensure it is valid
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            if VirtualQuery(res as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) == 0
                || mbi.State == MEM_FREE
                || res as usize + required_size > mbi.BaseAddress as usize + mbi.RegionSize
            {
                return None;
            }
            Some(res)
        }
    }

    /// Gets the mutable data at an RVA offset, checking to make sure
    ///
    /// # Arguments
    ///
    /// `offset`: The RVA offset to the data
    /// `required_size`: The required size of the allocation
    pub fn get_rva_size_chk_mut<T>(
        &mut self,
        offset: isize,
        required_size: usize,
    ) -> Option<*mut T> {
        unsafe {
            let res = (self.contents as *mut u8).offset(offset) as *mut T;
            // query the memory location and ensure it is valid
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            if VirtualQuery(res as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) == 0
                || mbi.State == MEM_FREE
                || res as usize + required_size > mbi.BaseAddress as usize + mbi.RegionSize
            {
                return None;
            }
            Some(res)
        }
    }

    /// Gets the data at an RVA offset. Performs necessary checks to ensure
    /// that the entire type fits within the allocation
    ///
    /// # Arguments
    ///
    /// `offset`: The RVA offset to the data
    pub fn get_rva<T>(&self, offset: isize) -> Option<*const T> {
        self.get_rva_size_chk(offset, std::mem::size_of::<T>())
    }

    /// Gets the mutable data at an RVA offset. Performs necessary checks to ensure
    /// that the entire type fits within the allocation
    ///
    /// # Arguments
    ///
    /// `offset`: The RVA offset to the data
    pub fn get_rva_mut<T>(&mut self, offset: isize) -> Option<*mut T> {
        self.get_rva_size_chk_mut(offset, std::mem::size_of::<T>())
    }

    /// Creates a mapped executable file
    ///
    /// # Arguments
    ///
    /// `path`: The path to the executable image file
    pub fn load(path: &str) -> Result<Self> {
        unsafe {
            // first open the file
            let file: Handle = CreateFileW(
                to_wide(path).as_ptr(),
                SYNCHRONIZE | GENERIC_READ | GENERIC_EXECUTE,
                FILE_SHARE_READ,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
            .into();
            if file.is_invalid() {
                return Err(Error::last_os_error().into());
            }
            // create a file mapping
            let mapping: Handle = CreateFileMappingA(
                file.handle,
                null_mut(),
                PAGE_EXECUTE_READ | SEC_IMAGE,
                0,
                0,
                null(),
            )
            .into();
            if mapping.is_invalid() {
                return Err(Error::last_os_error().into());
            }
            // actually map the file
            let contents = MapViewOfFile(mapping.handle, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, 0);
            if contents.is_null() {
                return Err(Error::last_os_error().into());
            }
            Ok(Self {
                file,
                mapping,
                contents,
            })
        }
    }
}

impl Drop for MappedFile {
    fn drop(&mut self) {
        // we need to unmap the file before the handle is freed
        unsafe {
            UnmapViewOfFile(self.contents);
        }
        // the handles will be dropped by the compiler
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serial_test::serial;

    #[test]
    #[should_panic]
    fn bad_file() {
        let _ = MappedFile::load("badpath").unwrap();
    }

    #[test]
    fn bad_file_err() {
        let err = MappedFile::load("badpath")
            .unwrap_err()
            .downcast::<Error>()
            .unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    #[serial]
    fn basic_file() {
        let file = MappedFile::load("test/basic.exe").unwrap();
        assert_eq!(file.contents as usize, 0x140000000);
        unsafe {
            // check the MZ header
            assert_eq!(
                std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                    file.contents as *const u8,
                    2
                )),
                "MZ"
            );
        }
    }
}
