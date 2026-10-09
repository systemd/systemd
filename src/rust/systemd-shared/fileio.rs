// SPDX-License-Identifier: LGPL-2.1-or-later

//! Reading files, `fileio.h`.

use core::ffi::{c_char, CStr};
use core::ptr::{self, NonNull};

use crate::errno::{check, Errno, Result};
use crate::fd::BorrowedFd;
use crate::sys;

pub use sys::{
    ReadFullFileFlags, READ_FULL_FILE_FAIL_WHEN_LARGER, READ_FULL_FILE_SECURE,
    READ_FULL_FILE_VERIFY_REGULAR, READ_FULL_FILE_WARN_WORLD_READABLE,
};

/// What `read_full_file_full()` read: the buffer libc allocated, NUL-terminated, freed on drop, and erased
/// first if it was read with `READ_FULL_FILE_SECURE`.
pub struct Contents {
    data: NonNull<c_char>,
    size: usize,
    secure: bool,
}

impl Contents {
    /// The contents up to the first NUL, for contents read as a string.
    pub fn as_cstr(&self) -> &CStr {
        // SAFETY: read_full_file_full() NUL-terminates the buffer.
        unsafe { CStr::from_ptr(self.data.as_ptr()) }
    }
}

impl AsRef<[u8]> for Contents {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl core::ops::Deref for Contents {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // SAFETY: the buffer holds size bytes for as long as we live.
        unsafe { core::slice::from_raw_parts(self.data.as_ptr().cast(), self.size) }
    }
}

// The contents may be secrets, never print them.
impl core::fmt::Debug for Contents {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Contents")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl Drop for Contents {
    fn drop(&mut self) {
        // SAFETY: the buffer is ours and came from malloc().
        unsafe {
            if self.secure {
                sys::erase_and_free(self.data.as_ptr().cast());
            } else {
                sys::free(self.data.as_ptr().cast());
            }
        }
    }
}

/// `-EINVAL` unless `filename` is a single path component: everything else goes through the chase helpers.
pub(crate) fn check_filename(filename: &CStr) -> Result<()> {
    // SAFETY: filename is a C string.
    if unsafe { sys::filename_is_valid(filename.as_ptr()) } {
        Ok(())
    } else {
        Err(Errno::EINVAL)
    }
}

/// A string has no `ret_size`, which makes `read_full_file_full()` refuse embedded NUL bytes.
fn read(
    dir: BorrowedFd<'_>,
    filename: Option<&CStr>,
    offset: u64,
    size: usize,
    flags: ReadFullFileFlags,
    string: bool,
) -> Result<Contents> {
    filename.map_or(Ok(()), check_filename)?;
    // An unlimited size cannot be exceeded, C asserts on asking for that, and on asking for both decodings.
    let decode = sys::READ_FULL_FILE_UNBASE64 | sys::READ_FULL_FILE_UNHEX;
    if (size == usize::MAX && flags & READ_FULL_FILE_FAIL_WHEN_LARGER != 0) || flags & decode == decode {
        return Err(Errno::EINVAL);
    }

    let mut data: *mut c_char = ptr::null_mut();
    let mut n = 0;
    // SAFETY: filename is a C string or NULL, data and n are valid out-pointers, data receives a malloc()ed
    // buffer on success.
    check(unsafe {
        sys::read_full_file_full(
            dir.as_raw(),
            filename.map_or(ptr::null(), CStr::as_ptr),
            offset,
            size,
            flags,
            ptr::null(),
            &mut data,
            if string { ptr::null_mut() } else { &mut n },
        )
    })?;

    let data = NonNull::new(data).ok_or(Errno::ENOMEM)?;
    let size = if string {
        // SAFETY: the buffer is NUL-terminated.
        unsafe { CStr::from_ptr(data.as_ptr()) }.count_bytes()
    } else {
        n
    };

    Ok(Contents {
        data,
        size,
        secure: flags & READ_FULL_FILE_SECURE != 0,
    })
}

/// `read_full_file_full()` without the socket connecting part: `filename`, a single path component, in `dir`,
/// or `dir` itself when `None`.
pub fn read_full_file_full(
    dir: BorrowedFd<'_>,
    filename: Option<&CStr>,
    offset: u64,
    size: usize,
    flags: ReadFullFileFlags,
) -> Result<Contents> {
    read(dir, filename, offset, size, flags, false)
}

/// Like [`read_full_file_full()`], for a file that is a string: one that contains a NUL byte is refused with
/// `-EBADMSG`, as `read_full_file_full()` does when C passes no `ret_size`.
pub fn read_full_file_full_string(
    dir: BorrowedFd<'_>,
    filename: Option<&CStr>,
    offset: u64,
    size: usize,
    flags: ReadFullFileFlags,
) -> Result<Contents> {
    read(dir, filename, offset, size, flags, true)
}

/// `read_boolean_file_at()`: `filename`, a single path component, in `dir`.
pub fn read_boolean_file_at(dir: BorrowedFd<'_>, filename: &CStr) -> Result<bool> {
    check_filename(filename)?;
    // SAFETY: filename is a C string.
    check(unsafe { sys::read_boolean_file_at(dir.as_raw(), filename.as_ptr()) }).map(|r| r > 0)
}
