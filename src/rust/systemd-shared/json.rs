// SPDX-License-Identifier: LGPL-2.1-or-later

//! sd-json.

use core::ffi::{c_char, c_int, CStr};
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
    /// ```ignore
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

/// `parse_json_argument()`: parses the argument of `--json=` into `flags`. `Ok(0)` means the argument was
/// `help` and the program is done, as in C. `None`, an option without its argument, is `-EINVAL`.
pub fn parse_argument(arg: Option<&CStr>, flags: &mut sys::sd_json_format_flags_t) -> Result<c_int> {
    let arg = arg.ok_or(Errno::EINVAL)?;
    // SAFETY: arg is a C string, flags a valid out-pointer.
    check(unsafe { sys::parse_json_argument(arg.as_ptr(), flags) })
}

/// `sd_json_format_enabled()`: whether the flags ask for JSON output.
pub fn format_enabled(flags: sys::sd_json_format_flags_t) -> bool {
    // SAFETY: plain call into libsystemd-shared.
    unsafe { sys::sd_json_format_enabled(flags) != 0 }
}

// Sensitive values are censored, as for logging.
impl fmt::Debug for JsonVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.format(sys::SD_JSON_FORMAT_CENSOR_SENSITIVE) {
            Ok(s) => write!(f, "JsonVariant({s})"),
            Err(e) => write!(f, "JsonVariant(<{e}>)"),
        }
    }
}
