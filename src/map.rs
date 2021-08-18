use std::{ffi::c_void, ptr::null_mut};

use crate::{
    bindings::Windows::Win32::{
        Foundation::{HANDLE, PSTR},
        Storage::FileSystem::*,
        System::{
            Diagnostics::Debug::*,
            Memory::{
                CreateFileMappingA, MapViewOfFile, UnmapViewOfFile, FILE_MAP_EXECUTE,
                FILE_MAP_READ, PAGE_EXECUTE_READ, SEC_IMAGE,
            },
        },
    },
    primitives::{Error, Handle},
};

// A mapped executable image file in the process's address space
#[derive(Debug)]
pub struct MappedFile {
    file: Handle,
    mapping: Handle,
    pub contents: *mut c_void,
}

impl MappedFile {
    /// Creates a mapped executable file
    ///
    /// # Arguments
    ///
    /// `path`: The path to the executable image file
    pub fn create(path: &str) -> Result<Self, Error> {
        unsafe {
            // first open the file
            let file = CreateFileA(
                path,
                SYNCHRONIZE | FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
                FILE_SHARE_NONE,
                null_mut(),
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES::default(),
                HANDLE::default(),
            );
            if file.is_invalid() {
                return Err(GetLastError().into());
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
                PSTR(null_mut()),
            );
            if mapping.is_null() {
                return Err(GetLastError().into());
            }
            // track the mapping
            let mapping = Handle::from(mapping);
            // actually map the file
            let contents = MapViewOfFile(mapping.handle, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, 0);
            if contents.is_null() {
                return Err(GetLastError().into());
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
        let _ = MappedFile::create("badpath").unwrap();
    }

    #[test]
    fn bad_file_err() {
        let err = MappedFile::create("badpath").unwrap_err();
        assert_eq!(err.code, ERROR_FILE_NOT_FOUND);
        assert_eq!(
            err.str().unwrap(),
            "The system cannot find the file specified.\r\n"
        );
    }

    #[test]
    fn good_file() {
        let file = MappedFile::create("test.exe").unwrap();
        assert_eq!(file.contents as usize, 0x140000000);
        unsafe {
            // check the MZ header
            assert_eq!(std::str::from_utf8_unchecked(std::slice::from_raw_parts(file.contents as *const u8, 2)), "MZ");
        }
    }
}
