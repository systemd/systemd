// SPDX-License-Identifier: LGPL-2.1-or-later

//! Paths, `path-util.h`.

use core::ffi::{c_char, CStr};
use core::ptr;

use crate::cstr::OwnedCStr;
use crate::errno::{Errno, Result};
use crate::sys;

/// C's `POINTER_MAX`, ends the argument list of the variadic path helpers.
const POINTER_MAX: *const c_char = ptr::without_provenance(usize::MAX);

/// `path_join()`: the parts with a "/" between them unless one is there already. Empty parts are skipped,
/// doubled slashes stay. `-ENOMEM` instead of aborting when memory runs out.
///
/// ```ignore
/// use systemd_shared::path;
///
/// let p = path::join(&[c"/run/voa", c"debian", c"kernel-keyring"]).unwrap();
/// assert_eq!(p.as_cstr(), c"/run/voa/debian/kernel-keyring");
/// ```
pub fn join(parts: &[&CStr]) -> Result<OwnedCStr> {
    if parts.is_empty() {
        return OwnedCStr::try_from(c"");
    }

    // The C helper takes the parts as variadic arguments, which a slice cannot be passed on as, so the
    // string grows by one part per call, the way path_extend() is used.
    let mut x: *mut c_char = ptr::null_mut();
    for p in parts {
        // SAFETY: x is NULL or the string of the previous call, which is reallocated in place; p is a C
        // string and the sentinel ends the list.
        if unsafe { sys::path_extend_internal(&mut x, p.as_ptr(), POINTER_MAX) }.is_null() {
            // SAFETY: a failed call leaves x alone, free() accepts NULL.
            unsafe { sys::free(x.cast()) };
            return Err(Errno::ENOMEM);
        }
    }
    // SAFETY: a malloc()ed NUL-terminated string that nothing else frees.
    unsafe { OwnedCStr::from_raw(x) }.ok_or(Errno::ENOMEM)
}
