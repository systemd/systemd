// SPDX-License-Identifier: LGPL-2.1-or-later

//! Temporary files that atomically replace their target, `tmpfile-util.h`.

use core::ffi::{c_char, c_int, CStr};
use core::ptr;

use crate::cstr::OwnedCStr;
use crate::errno::{check, Errno, Result};
use crate::fd::{BorrowedFd, OwnedFd};
use crate::fileio::check_filename;
use crate::sys;

pub use sys::{LinkTmpfileFlags, LINK_TMPFILE_REPLACE};

/// A file opened with `open_tmpfile_linkable_at()`, removed again when dropped before [`link()`] put it in place,
/// like `CLEANUP_TMPFILE_AT()`.
///
/// [`link()`]: LinkableTmpfile::link
#[derive(Debug)]
pub struct LinkableTmpfile<'a> {
    fd: OwnedFd,
    dir: BorrowedFd<'a>,
    path: Option<OwnedCStr>,
}

impl<'a> LinkableTmpfile<'a> {
    /// `open_tmpfile_linkable_at()`: a file that will replace `target`, a single path component, in `dir`, an
    /// open directory.
    pub fn open_at(dir: BorrowedFd<'a>, target: &CStr, flags: c_int) -> Result<LinkableTmpfile<'a>> {
        if dir.as_raw() < 0 {
            return Err(Errno::EBADF);
        }
        // O_EXCL means something else with O_TMPFILE, C asserts against it
        if flags & (sys::O_EXCL as c_int) != 0 {
            return Err(Errno::EINVAL);
        }
        check_filename(target)?;
        let mut path: *mut c_char = ptr::null_mut();
        // SAFETY: target is a C string, path receives a malloc()ed string or stays NULL for O_TMPFILE.
        let r = unsafe { sys::open_tmpfile_linkable_at(dir.as_raw(), target.as_ptr(), flags, &mut path) };
        // SAFETY: the path is ours, and the descriptor or -errno too.
        let (path, fd) = unsafe { (OwnedCStr::from_raw(path), OwnedFd::from_result(r)) };
        Ok(LinkableTmpfile { fd: fd?, dir, path })
    }

    /// The file.
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// `link_tmpfile_at()`: puts the file in place as `target`, a single path component.
    pub fn link(mut self, target: &CStr, flags: LinkTmpfileFlags) -> Result<()> {
        check_filename(target)?;
        // SAFETY: the path is a C string or NULL, as open_tmpfile_linkable_at() left it.
        check(unsafe {
            sys::link_tmpfile_at(
                self.fd.as_raw(),
                self.dir.as_raw(),
                self.path.as_ref().map_or(ptr::null(), |p| p.as_ptr()),
                target.as_ptr(),
                flags,
            )
        })?;
        // In place now, nothing to clean up.
        self.path = None;
        Ok(())
    }
}

impl Drop for LinkableTmpfile<'_> {
    fn drop(&mut self) {
        let Some(path) = self.path.take() else { return };
        let mut dir = self.dir.as_raw();
        let mut name = path.as_ptr().cast_mut();
        let mut data = sys::cleanup_tmpfile_data {
            dir_fd: &mut dir,
            filename: &mut name,
        };
        // SAFETY: data points at the directory and the path, which cleanup_tmpfile_data_done() only unlinks;
        // the path itself is freed with its OwnedCStr.
        unsafe { sys::cleanup_tmpfile_data_done(&mut data) };
    }
}
