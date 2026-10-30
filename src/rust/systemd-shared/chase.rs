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
pub fn openat(
    root: BorrowedFd<'_>,
    dir: BorrowedFd<'_>,
    path: &CStr,
    flags: ChaseFlags,
    open_flags: c_int,
) -> Result<OwnedFd> {
    check_flags(flags, sys::CHASE_MUST_BE_SOCKET)?;
    // xopenat_full() asserts these too: one inode type, no O_CREAT with an O_PATH automount trigger
    let directory = flags & sys::CHASE_MUST_BE_DIRECTORY != 0 || open_flags & sys::O_DIRECTORY as c_int != 0;
    let o_path = open_flags & sys::O_PATH as c_int != 0;
    let creates = open_flags & sys::O_CREAT as c_int != 0;
    if (flags & sys::CHASE_MUST_BE_REGULAR != 0 && directory)
        || (flags & sys::CHASE_TRIGGER_AUTOFS != 0 && o_path && creates)
    {
        return Err(Errno::EINVAL);
    }
    // SAFETY: path is a C string, the resolved path is not asked for; the descriptor or -errno is ours.
    unsafe {
        OwnedFd::from_return(sys::chase_and_openat(
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
pub fn accessat(
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
pub fn open_parent_at(
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
    let (filename, fd) = unsafe { (OwnedCStr::from_raw(filename), OwnedFd::from_return(r)) };
    Ok((fd?, filename.ok_or(Errno::EBADMSG)?))
}
