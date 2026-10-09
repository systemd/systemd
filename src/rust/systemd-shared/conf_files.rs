// SPDX-License-Identifier: LGPL-2.1-or-later

//! Configuration files found by the lookup helpers, `conf-files.h`.

use core::ffi::CStr;

use crate::fd::BorrowedFd;
use crate::sys;

/// One file found by a lookup, C's `ConfFile`.
#[repr(transparent)]
pub struct ConfFile(sys::ConfFile);

impl ConfFile {
    /// The path as found: the original directory prefix and the file name.
    pub fn original_path(&self) -> &CStr {
        // SAFETY: the lookup always sets the original path.
        unsafe { CStr::from_ptr(self.0.original_path) }
    }

    /// An `O_PATH` descriptor of the resolved path, `None` if it does not exist.
    pub fn fd(&self) -> Option<BorrowedFd<'_>> {
        // SAFETY: the entry owns the descriptor for as long as it lives.
        (self.0.fd >= 0).then(|| unsafe { BorrowedFd::borrow_raw(self.0.fd) })
    }
}

/// The result of a lookup, freed with `conf_file_free_array()`.
pub struct ConfFiles {
    files: *mut *mut sys::ConfFile,
    n: usize,
}

impl ConfFiles {
    /// Takes ownership of what a lookup returned.
    ///
    /// # Safety
    ///
    /// `files` must be NULL with `n` zero, or a `malloc()`ed array of `n` non-NULL entries from a lookup that
    /// nothing else frees.
    pub(crate) unsafe fn from_raw(files: *mut *mut sys::ConfFile, n: usize) -> ConfFiles {
        ConfFiles { files, n }
    }

    /// The files in lookup order.
    pub fn iter(&self) -> impl Iterator<Item = &ConfFile> + '_ {
        // SAFETY: the array holds n valid entries for as long as we live, ConfFile is a transparent wrapper.
        (0..self.n).map(move |i| unsafe { &*(*self.files.add(i)).cast::<ConfFile>() })
    }
}

impl Drop for ConfFiles {
    fn drop(&mut self) {
        // SAFETY: we own the array and its entries.
        unsafe { sys::conf_file_free_array(self.files, self.n) }
    }
}
