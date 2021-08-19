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

    /// Gets the data at an RVA offset
    ///
    /// # Arguments
    ///
    /// `offset`: The RVA offset to the data
    pub unsafe fn get_rva<T>(&self, offset: isize) -> *const T {
        (self.contents as *const u8).offset(offset) as *const T
    }

    /// Gets the function at an RVA offset
    ///
    /// # Arguments
    ///
    /// `offset`: The RVA offset to the function
    pub unsafe fn get_rva_fn<Args, Ret, T: Fn(Args) -> Ret>(&self, offset: isize) -> T {
        std::mem::transmute((self.contents as *const u8).offset(offset))
    }

    /// Returns the size of the mapped file
    pub fn len(&self) -> Result<usize> {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        unsafe {
            let size = VirtualQuery(self.contents, &mut mbi, std::mem::size_of_val(&mbi));
            if size == 0 {
                return Err(Error::last_os_error().into());
            }
        }
        Ok(mbi.RegionSize)
    }

    /// Creates a mapped executable file
    ///
    /// # Arguments
    ///
    /// `path`: The path to the executable image file
    pub fn load(path: &str) -> Result<Self> {
        unsafe {
            // first open the file
            let file = CreateFileW(
                to_wide(path).as_ptr(),
                SYNCHRONIZE | GENERIC_READ | GENERIC_EXECUTE,
                FILE_SHARE_READ,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            );
            if file.is_null() {
                return Err(Error::last_os_error().into());
            }
            // track the file
            let file = Handle::from(file);
            // create a file mapping
            let mapping = CreateFileMappingA(
                file.handle,
                null_mut(),
                PAGE_EXECUTE_READ | SEC_IMAGE,
                0,
                0,
                null(),
            );
            if mapping.is_null() {
                return Err(Error::last_os_error().into());
            }
            // track the mapping
            let mapping = Handle::from(mapping);
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

    #[test]
    #[should_panic]
    fn bad_file() {
        let _ = MappedFile::load(&"badpath".to_owned()).unwrap();
    }

    #[test]
    fn bad_file_err() {
        let err = MappedFile::load(&"badpath".to_owned())
            .unwrap_err()
            .downcast::<Error>()
            .unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn good_file() {
        let file = MappedFile::load(&"test.exe".to_owned()).unwrap();
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
