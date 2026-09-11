// SPDX-License-Identifier: LGPL-2.1-or-later

//! `char **` string arrays.

use core::ffi::{c_char, CStr};
use core::ptr;

use crate::cstr::OwnedCStr;
use crate::errno::{check, Errno, Result};
use crate::sys;

/// An owned NULL-terminated array of C strings, freed with `strv_free()`.
pub struct Strv(*mut *mut c_char);

impl Strv {
    /// An empty array (NULL, which every strv helper accepts).
    pub const fn new() -> Strv {
        Strv(ptr::null_mut())
    }

    /// Takes ownership of an strv returned by a C helper.
    ///
    /// # Safety
    ///
    /// `l` must be NULL or an strv that nothing else frees.
    pub unsafe fn from_raw(l: *mut *mut c_char) -> Strv {
        Strv(l)
    }

    /// `strv_split_full()`.
    ///
    /// ```
    /// use systemd_shared::strv::Strv;
    /// use systemd_shared::sys;
    ///
    /// let words = Strv::split(c"one two  three", c" ", sys::EXTRACT_RELAX).unwrap();
    /// assert_eq!(words.len(), 3);
    /// assert_eq!(words.join(c",").unwrap().as_cstr(), c"one,two,three");
    /// ```
    pub fn split(s: &CStr, separators: &CStr, flags: sys::ExtractFlags) -> Result<Strv> {
        let mut l: *mut *mut c_char = ptr::null_mut();
        // SAFETY: all pointers are valid for the call, l receives an owned strv on success.
        check(unsafe { sys::strv_split_full(&mut l, s.as_ptr(), separators.as_ptr(), flags) })?;
        Ok(Strv(l))
    }

    /// `strv_length()`.
    pub fn len(&self) -> usize {
        // SAFETY: self.0 is a valid strv or NULL.
        unsafe { sys::strv_length(self.0) }
    }

    /// `strv_isempty()`, a static inline helper reached through its trampoline.
    pub fn is_empty(&self) -> bool {
        // SAFETY: self.0 is a valid strv or NULL.
        unsafe { sys::strv_isempty(self.0) }
    }

    /// `strv_join()`.
    pub fn join(&self, separator: &CStr) -> Result<OwnedCStr> {
        // SAFETY: strv_join() returns a malloc()ed string, NULL on OOM.
        unsafe { OwnedCStr::from_raw(sys::strv_join(self.0, separator.as_ptr())) }.ok_or(Errno::ENOMEM)
    }

    /// `strv_extend()`.
    pub fn push(&mut self, value: &CStr) -> Result<()> {
        // SAFETY: self.0 is updated in place by strv_extend().
        check(unsafe { sys::strv_extend(&mut self.0, value.as_ptr()) }).map(|_| ())
    }

    /// Iterates over the strings.
    pub fn iter(&self) -> impl Iterator<Item = &CStr> + '_ {
        // SAFETY: indices stay below strv_length(), every element is a NUL-terminated string.
        (0..self.len()).map(move |i| unsafe { CStr::from_ptr(*self.0.add(i)) })
    }

    /// The raw array, for passing to C.
    pub fn as_ptr(&self) -> *const *mut c_char {
        self.0
    }

    /// Gives the array to C, `TAKE_PTR()`.
    pub fn into_raw(self) -> *mut *mut c_char {
        let l = self.0;
        core::mem::forget(self);
        l
    }
}

impl Default for Strv {
    fn default() -> Self {
        Strv::new()
    }
}

impl Drop for Strv {
    fn drop(&mut self) {
        // SAFETY: strv_free() accepts NULL and frees every element plus the array.
        unsafe {
            sys::strv_free(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        let v = Strv::new();
        assert!(v.is_empty());
        assert_eq!(v.len(), 0);
        assert_eq!(v.iter().count(), 0);
        assert_eq!(v.join(c",").unwrap().as_cstr(), c"");
    }

    #[test]
    fn split_join_push() {
        let mut v = Strv::split(c"one two  three", c" ", sys::EXTRACT_RELAX).unwrap();
        assert_eq!(v.len(), 3);
        assert!(!v.is_empty());
        assert_eq!(
            v.iter().map(|s| s.to_str().unwrap()).collect::<Vec<_>>(),
            ["one", "two", "three"]
        );
        assert_eq!(v.join(c",").unwrap().as_cstr(), c"one,two,three");

        v.push(c"four").unwrap();
        assert_eq!(v.len(), 4);
        assert_eq!(v.join(c" ").unwrap().as_cstr(), c"one two three four");

        let raw = v.into_raw();
        // SAFETY: we own the array again.
        let v = unsafe { Strv::from_raw(raw) };
        assert_eq!(v.len(), 4);
    }
}
