use std::{
    ffi::{CString, NulError},
    os::unix::ffi::OsStrExt,
    path::Path,
};

use lockc_common::{AccessedPath, PATH_LEN};

pub(crate) trait AccessedPathExt {
    fn new<P: AsRef<Path>>(path: P) -> Result<Self, NulError>
    where
        Self: Sized;
}

impl AccessedPathExt for AccessedPath {
    fn new<P: AsRef<Path>>(path: P) -> Result<Self, NulError> {
        let mut path_b = CString::new(path.as_ref().as_os_str().as_bytes())?.into_bytes_with_nul();
        path_b.resize(PATH_LEN, 0);
        Ok(AccessedPath {
            path: path_b.try_into().unwrap(),
        })
    }
}
