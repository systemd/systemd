// SPDX-License-Identifier: LGPL-2.1-or-later

//! File descriptors: [`OwnedFd`] is `_cleanup_close_ int fd`, [`BorrowedFd`] is the `int fd` argument of a
//! function that does not take ownership.

use core::ffi::{c_char, c_int};
use core::marker::PhantomData;
use core::ptr;

use crate::cstr::OwnedCStr;
use crate::errno::{check, Errno, Result};
use crate::sys;

/// An open file descriptor, closed with `safe_close()` on drop.
#[derive(Debug)]
pub struct OwnedFd(c_int);

impl OwnedFd {
    /// Takes ownership of a descriptor, or passes on the error a C helper returned instead of one, like
    /// `fd = foo(); if (fd < 0) return fd;` in C.
    ///
    /// # Safety
    ///
    /// A non-negative `r` must be an open descriptor that nothing else closes.
    pub unsafe fn from_result(r: c_int) -> Result<OwnedFd> {
        check(r).map(OwnedFd)
    }

    /// Borrows the descriptor.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        BorrowedFd {
            fd: self.0,
            owner: PhantomData,
        }
    }

    /// The descriptor, for passing to C.
    pub fn as_raw(&self) -> c_int {
        self.0
    }

    /// Gives the descriptor to C, `TAKE_FD()`.
    #[must_use = "the descriptor leaks unless it is closed"]
    pub fn into_raw(self) -> c_int {
        let fd = self.0;
        core::mem::forget(self);
        fd
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        // SAFETY: we own the descriptor.
        unsafe { sys::safe_close(self.0) };
    }
}

/// A descriptor that stays open for `'a`, or the `XAT_FDROOT` placeholder for the host's root directory that the
/// `*at()` helpers accept.
#[derive(Clone, Copy, Debug)]
pub struct BorrowedFd<'a> {
    fd: c_int,
    owner: PhantomData<&'a OwnedFd>,
}

impl BorrowedFd<'static> {
    /// `XAT_FDROOT`.
    pub const XAT_FDROOT: BorrowedFd<'static> = BorrowedFd {
        fd: sys::XAT_FDROOT,
        owner: PhantomData,
    };
}

impl BorrowedFd<'_> {
    /// Borrows a descriptor C owns.
    ///
    /// # Safety
    ///
    /// `fd` must stay open for the lifetime of the value.
    pub const unsafe fn borrow_raw(fd: c_int) -> Self {
        BorrowedFd {
            fd,
            owner: PhantomData,
        }
    }

    /// The descriptor, for passing to C.
    pub fn as_raw(self) -> c_int {
        self.fd
    }
}

/// `fd_reopen()`: opens what `fd` refers to anew, `XAT_FDROOT` the root directory.
pub fn reopen(fd: BorrowedFd<'_>, flags: c_int) -> Result<OwnedFd> {
    // C asserts against creating
    if flags & (sys::O_CREAT as c_int) != 0 {
        return Err(Errno::EINVAL);
    }
    // SAFETY: plain call into libsystemd-shared, the new descriptor or -errno is ours.
    unsafe { OwnedFd::from_result(sys::fd_reopen(fd.as_raw(), flags)) }
}

/// `loop_write()`: writes all of `buf` to an open descriptor, not a placeholder.
pub fn loop_write(fd: BorrowedFd<'_>, buf: &[u8]) -> Result<()> {
    if fd.as_raw() < 0 {
        return Err(Errno::EBADF);
    }
    // SAFETY: buf is valid for buf.len() bytes.
    check(unsafe { sys::loop_write(fd.as_raw(), buf.as_ptr().cast(), buf.len()) }).map(|_| ())
}

/// `fchmod()`.
pub fn fchmod(fd: BorrowedFd<'_>, mode: sys::mode_t) -> Result<()> {
    // SAFETY: plain call into libc.
    if unsafe { sys::fchmod(fd.as_raw(), mode) } < 0 {
        return Err(Errno::last_os_error());
    }
    Ok(())
}

/// `fd_get_path()`.
pub fn get_path(fd: BorrowedFd<'_>) -> Result<OwnedCStr> {
    let mut p: *mut c_char = ptr::null_mut();
    // SAFETY: p is a valid out-pointer that receives a malloc()ed string on success.
    check(unsafe { sys::fd_get_path(fd.as_raw(), &mut p) })?;
    // SAFETY: we own p.
    unsafe { OwnedCStr::from_raw(p) }.ok_or(Errno::ENOMEM)
}
