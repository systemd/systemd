// SPDX-License-Identifier: LGPL-2.1-or-later

//! sd-json.

use core::ffi::{c_char, CStr};
use core::fmt;
use core::ptr::{self, NonNull};

use crate::cstr::OwnedCStr;
use crate::errno::{check, Errno, Result};
use crate::refcount::{Ref, RefCounted};
use crate::sys;

// SAFETY: sd_json_variant_ref()/sd_json_variant_unref() are the type's reference counting functions.
unsafe impl RefCounted for sys::sd_json_variant {
    unsafe fn inc_ref(this: NonNull<Self>) {
        // SAFETY: the caller guarantees a live object.
        unsafe { sys::sd_json_variant_ref(this.as_ptr()) };
    }

    unsafe fn dec_ref(this: NonNull<Self>) {
        // SAFETY: the caller guarantees a live object and an owned reference.
        unsafe { sys::sd_json_variant_unref(this.as_ptr()) };
    }
}

/// A reference to an `sd_json_variant`.
#[derive(Clone)]
pub struct JsonVariant(Ref<sys::sd_json_variant>);

impl JsonVariant {
    /// `sd_json_variant_new_string()`.
    pub fn new_string(s: &CStr) -> Result<JsonVariant> {
        let mut v: *mut sys::sd_json_variant = ptr::null_mut();
        // SAFETY: v receives a new reference on success.
        check(unsafe { sys::sd_json_variant_new_string(&mut v, s.as_ptr()) })?;
        // SAFETY: we own the reference.
        unsafe { Ref::from_raw(v) }.map(JsonVariant).ok_or(Errno::EINVAL)
    }

    /// `sd_json_variant_new_integer()`.
    pub fn new_integer(i: i64) -> Result<JsonVariant> {
        let mut v: *mut sys::sd_json_variant = ptr::null_mut();
        // SAFETY: v receives a new reference on success.
        check(unsafe { sys::sd_json_variant_new_integer(&mut v, i) })?;
        // SAFETY: we own the reference.
        unsafe { Ref::from_raw(v) }.map(JsonVariant).ok_or(Errno::EINVAL)
    }

    /// `sd_json_parse()`.
    ///
    /// ```
    /// use systemd_shared::json::JsonVariant;
    ///
    /// let v = JsonVariant::parse(c"{\"a\": [1, 2]}", 0).unwrap();
    /// assert_eq!(v.format(0).unwrap().as_cstr(), c"{\"a\":[1,2]}");
    /// ```
    pub fn parse(s: &CStr, flags: sys::sd_json_parse_flags_t) -> Result<JsonVariant> {
        let mut v: *mut sys::sd_json_variant = ptr::null_mut();
        // SAFETY: v receives a new reference on success, line/column are optional.
        check(unsafe { sys::sd_json_parse(s.as_ptr(), flags, &mut v, ptr::null_mut(), ptr::null_mut()) })?;
        // SAFETY: we own the reference.
        unsafe { Ref::from_raw(v) }.map(JsonVariant).ok_or(Errno::EINVAL)
    }

    /// `sd_json_variant_format()`.
    pub fn format(&self, flags: sys::sd_json_format_flags_t) -> Result<OwnedCStr> {
        let mut s: *mut c_char = ptr::null_mut();
        // SAFETY: s receives a malloc()ed string on success.
        check(unsafe { sys::sd_json_variant_format(self.as_ptr(), flags, &mut s) })?;
        // SAFETY: we own s.
        unsafe { OwnedCStr::from_raw(s) }.ok_or(Errno::ENOMEM)
    }

    /// The raw pointer, for passing to C.
    pub fn as_ptr(&self) -> *mut sys::sd_json_variant {
        self.0.as_ptr()
    }
}

impl fmt::Debug for JsonVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.format(0) {
            Ok(s) => write!(f, "JsonVariant({s})"),
            Err(e) => write!(f, "JsonVariant(<{e}>)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let v = JsonVariant::new_string(c"hello").unwrap();
        assert_eq!(v.format(0).unwrap().as_cstr(), c"\"hello\"");

        let i = JsonVariant::new_integer(-42).unwrap();
        assert_eq!(i.format(0).unwrap().as_cstr(), c"-42");
        assert_eq!(format!("{i:?}"), "JsonVariant(-42)");

        let p = JsonVariant::parse(c"{\"a\": [1, 2]}", 0).unwrap();
        assert_eq!(p.format(0).unwrap().as_cstr(), c"{\"a\":[1,2]}");
        let p2 = p.clone();
        assert_eq!(p.as_ptr(), p2.as_ptr());

        assert_eq!(JsonVariant::parse(c"{", 0).unwrap_err(), Errno::EINVAL);
    }
}
