// SPDX-License-Identifier: LGPL-2.1-or-later

//! File descriptor helpers. Descriptors are `BorrowedFd`/`OwnedFd`, the way std spells `int fd` and
//! `_cleanup_close_ int fd`.

use core::ffi::c_char;
use core::ptr;
use std::os::fd::{AsRawFd, BorrowedFd};

use crate::cstr::OwnedCStr;
use crate::errno::{check, Errno, Result};
use crate::sys;

/// `fd_get_path()`.
///
/// ```
/// use std::os::fd::AsFd;
///
/// let root = std::fs::File::open("/").unwrap();
/// assert_eq!(systemd_shared::fd::get_path(root.as_fd()).unwrap().as_cstr(), c"/");
/// ```
pub fn get_path(fd: BorrowedFd<'_>) -> Result<OwnedCStr> {
    let mut p: *mut c_char = ptr::null_mut();
    // SAFETY: p is a valid out-pointer that receives a malloc()ed string on success.
    check(unsafe { sys::fd_get_path(fd.as_raw_fd(), &mut p) })?;
    // SAFETY: we own p.
    unsafe { OwnedCStr::from_raw(p) }.ok_or(Errno::ENOMEM)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn path_of_root() {
        let root = std::fs::File::open("/").unwrap();
        assert_eq!(get_path(root.as_fd()).unwrap().as_cstr(), c"/");
    }
}
