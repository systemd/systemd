// SPDX-License-Identifier: LGPL-2.1-or-later

//! Service credentials, `creds-util.h`.

use core::ffi::{c_char, c_int, CStr};
use core::ptr;

use crate::chase;
use crate::errno::{check, Errno, Result};
use crate::fd::{BorrowedFd, OwnedFd};
use crate::fileio::{self, Contents, READ_FULL_FILE_SECURE};
use crate::sys;

/// `open_credentials_dir()`, with the directory `get_credentials_dir()` names resolved below `root`.
/// `-ENXIO` if the service has no credentials.
pub fn open_credentials_dir_at(root: BorrowedFd<'_>) -> Result<OwnedFd> {
    let mut d: *const c_char = ptr::null();
    // SAFETY: d receives a pointer into the environment on success.
    check(unsafe { sys::get_credentials_dir(&mut d) })?;
    // SAFETY: on success d points to a NUL-terminated string in the environment, which nothing modifies while
    // we use it.
    let d = unsafe { CStr::from_ptr(d) };
    chase::chase_and_openat(root, root, d, 0, (sys::O_DIRECTORY | sys::O_CLOEXEC) as c_int)
}

fn check_name(name: &CStr) -> Result<()> {
    // SAFETY: name is a C string.
    if unsafe { sys::credential_name_valid(name.as_ptr()) } {
        Ok(())
    } else {
        Err(Errno::EINVAL)
    }
}

/// `read_credential()` relative to the credentials directory `dir`. The contents are erased when dropped,
/// like `_cleanup_(erase_and_freep)` does.
pub fn read_credential_at(dir: BorrowedFd<'_>, name: &CStr) -> Result<Contents> {
    check_name(name)?;
    fileio::read_full_file_full(dir, Some(name), u64::MAX, usize::MAX, READ_FULL_FILE_SECURE)
}

/// Like [`read_credential_at()`], for a credential that is a string: one with a NUL byte is refused with
/// `-EBADMSG`, as `read_credential()` does when C passes no `ret_size`.
pub fn read_credential_string_at(dir: BorrowedFd<'_>, name: &CStr) -> Result<Contents> {
    check_name(name)?;
    fileio::read_full_file_full_string(dir, Some(name), u64::MAX, usize::MAX, READ_FULL_FILE_SECURE)
}
