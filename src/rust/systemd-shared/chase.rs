// SPDX-License-Identifier: LGPL-2.1-or-later

//! Path resolution, `chase.h`.

use core::ffi::{c_char, c_int, CStr};
use core::ptr;

use crate::cstr::OwnedCStr;
use crate::errno::{check, Errno, Result};
use crate::fd::{BorrowedFd, OwnedFd};
use crate::sys;

pub use sys::{ChaseFlags, CHASE_MAX_MODE, CHASE_MKDIR_0755, CHASE_SAFE};

/// Flags the helpers assert against in C are `-EINVAL` here.
fn check_flags(flags: ChaseFlags, refused: ChaseFlags) -> Result<()> {
    let autofs = sys::CHASE_NO_AUTOFS | sys::CHASE_TRIGGER_AUTOFS;
    if flags & (refused | sys::CHASE_PREFIX_ROOT | sys::CHASE_NONEXISTENT | sys::CHASE_STEP) != 0
        || flags & autofs == autofs
    {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// `chase_and_openat()`: opens `path` below `root`, relative to `dir`.
pub fn chase_and_openat(
    root: BorrowedFd<'_>,
    dir: BorrowedFd<'_>,
    path: &CStr,
    flags: ChaseFlags,
    open_flags: c_int,
) -> Result<OwnedFd> {
    check_flags(flags, sys::CHASE_MUST_BE_SOCKET)?;
    // SAFETY: path is a C string, the resolved path is not asked for; the descriptor or -errno is ours.
    unsafe {
        OwnedFd::from_result(sys::chase_and_openat(
            root.as_raw(),
            dir.as_raw(),
            path.as_ptr(),
            flags,
            open_flags,
            ptr::null_mut(),
        ))
    }
}

/// `chase_and_accessat()`: `faccessat()` on `path` below `root`, relative to `dir`.
pub fn chase_and_accessat(
    root: BorrowedFd<'_>,
    dir: BorrowedFd<'_>,
    path: &CStr,
    flags: ChaseFlags,
    mode: c_int,
) -> Result<()> {
    check_flags(flags, 0)?;
    // SAFETY: path is a C string, the resolved path is not asked for.
    check(unsafe {
        sys::chase_and_accessat(
            root.as_raw(),
            dir.as_raw(),
            path.as_ptr(),
            flags,
            mode,
            ptr::null_mut(),
        )
    })
    .map(|_| ())
}

/// `chase_and_open_parent_at()`: the parent directory of `path` below `root`, and the last component.
pub fn chase_and_open_parent_at(
    root: BorrowedFd<'_>,
    dir: BorrowedFd<'_>,
    path: &CStr,
    flags: ChaseFlags,
) -> Result<(OwnedFd, OwnedCStr)> {
    check_flags(flags, 0)?;
    let mut filename: *mut c_char = ptr::null_mut();
    // SAFETY: path is a C string, filename receives a malloc()ed string on success.
    let r = unsafe {
        sys::chase_and_open_parent_at(root.as_raw(), dir.as_raw(), path.as_ptr(), flags, &mut filename)
    };
    // SAFETY: the file name is ours, and the descriptor or -errno too.
    let (filename, fd) = unsafe { (OwnedCStr::from_raw(filename), OwnedFd::from_result(r)) };
    Ok((fd?, filename.ok_or(Errno::EBADMSG)?))
}
