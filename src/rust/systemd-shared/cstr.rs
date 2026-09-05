// SPDX-License-Identifier: LGPL-2.1-or-later

//! Strings that C allocated.

use core::ffi::{c_char, c_void, CStr};
use core::fmt;
use core::ptr::NonNull;

use crate::sys;

/// A NUL-terminated string that was `malloc()`ed by C and is `free()`d on drop, the `_cleanup_free_ char *`
/// of Rust.
pub struct OwnedCStr(NonNull<c_char>);

impl OwnedCStr {
    /// Takes ownership of a string returned by a C helper, `None` for NULL.
    ///
    /// # Safety
    ///
    /// `p` must be NULL or a `malloc()`ed NUL-terminated string that nothing else frees.
    pub unsafe fn from_raw(p: *mut c_char) -> Option<Self> {
        NonNull::new(p).map(OwnedCStr)
    }

    /// Borrows the string.
    pub fn as_cstr(&self) -> &CStr {
        // SAFETY: invariant of from_raw().
        unsafe { CStr::from_ptr(self.0.as_ptr()) }
    }

    /// Gives the string back to C, `TAKE_PTR()`.
    pub fn into_raw(self) -> *mut c_char {
        let p = self.0.as_ptr();
        core::mem::forget(self);
        p
    }
}

impl Drop for OwnedCStr {
    fn drop(&mut self) {
        // SAFETY: invariant of from_raw().
        unsafe { sys::free(self.0.as_ptr().cast::<c_void>()) }
    }
}

impl core::ops::Deref for OwnedCStr {
    type Target = CStr;

    fn deref(&self) -> &CStr {
        self.as_cstr()
    }
}

impl fmt::Display for OwnedCStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_cstr().to_string_lossy())
    }
}

impl fmt::Debug for OwnedCStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_cstr(), f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn null_is_none() {
        // SAFETY: NULL is explicitly allowed.
        assert!(unsafe { OwnedCStr::from_raw(ptr::null_mut()) }.is_none());
    }

    #[test]
    fn owns_and_releases() {
        // SAFETY: strdup() returns a malloc()ed string we own.
        let s = unsafe { OwnedCStr::from_raw(sys::strdup(c"hello".as_ptr())) }.unwrap();
        assert_eq!(s.as_cstr(), c"hello");
        assert_eq!(s.to_string(), "hello");
        assert_eq!(format!("{s:?}"), "\"hello\"");

        let raw = s.into_raw();
        // SAFETY: we took the pointer back, so we free it.
        unsafe { sys::free(raw.cast::<c_void>()) };
    }
}
