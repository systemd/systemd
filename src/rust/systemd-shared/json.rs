// SPDX-License-Identifier: LGPL-2.1-or-later

//! The `--json=` handling of the C programs.

use core::ffi::{c_int, CStr};

use crate::errno::{check, Errno, Result};
use crate::sys;

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
