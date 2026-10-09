// SPDX-License-Identifier: LGPL-2.1-or-later

//! Directory listings, `recurse-dir.h`.

use core::ffi::CStr;
use core::ptr::{self, NonNull};

use crate::errno::{check, Errno, Result};
use crate::fd::BorrowedFd;
use crate::sys;

pub use sys::{RecurseDirFlags, RECURSE_DIR_ENSURE_TYPE, RECURSE_DIR_IGNORE_DOT, RECURSE_DIR_SORT};

/// The entries of a directory, freed with `free()`.
pub struct DirectoryEntries(NonNull<sys::DirectoryEntries>);

/// `readdir_all()`, on an open directory, not a placeholder.
pub fn readdir_all(dir: BorrowedFd<'_>, flags: RecurseDirFlags) -> Result<DirectoryEntries> {
    if dir.as_raw() < 0 {
        return Err(Errno::EBADF);
    }
    let mut de: *mut sys::DirectoryEntries = ptr::null_mut();
    // SAFETY: de is a valid out-pointer that receives a malloc()ed listing on success.
    check(unsafe { sys::readdir_all(dir.as_raw(), flags, &mut de) })?;
    NonNull::new(de).map(DirectoryEntries).ok_or(Errno::ENOMEM)
}

impl DirectoryEntries {
    /// The entries in listing order. A record is only as long as its name needs, never a whole `dirent`, so
    /// they stay pointers that only fields are read through.
    fn entries(&self) -> impl Iterator<Item = *const sys::dirent> + '_ {
        // SAFETY: the header is alive for as long as we are.
        let de = unsafe { self.0.as_ref() };
        // SAFETY: entries holds n_entries pointers into the listing's buffer.
        (0..de.n_entries).map(move |i| unsafe { *de.entries.add(i) }.cast_const())
    }

    /// The names of the entries in listing order.
    pub fn names(&self) -> impl Iterator<Item = &CStr> + '_ {
        self.entries().map(|d| {
            // SAFETY: only d_name is projected, which the kernel NUL-terminates within the record.
            unsafe { CStr::from_ptr(ptr::addr_of!((*d).d_name).cast()) }
        })
    }
}

impl core::fmt::Debug for DirectoryEntries {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.names()).finish()
    }
}

impl Drop for DirectoryEntries {
    fn drop(&mut self) {
        // SAFETY: the listing is a single allocation that is ours.
        unsafe { sys::free(self.0.as_ptr().cast()) };
    }
}
