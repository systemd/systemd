// SPDX-License-Identifier: LGPL-2.1-or-later

//! The `--json=` handling of the C programs.

use core::ffi::CStr;

use crate::errno::{check, Errno, Result};
use crate::sys;

/// `parse_json_argument()`: the flags the argument of `--json=` asks for. `Ok(None)` means the argument was
/// `help` and the program is done, as in C. An `arg` of `None`, an option without its argument, is `-EINVAL`.
pub fn parse_argument(arg: Option<&CStr>) -> Result<Option<sys::sd_json_format_flags_t>> {
    let arg = arg.ok_or(Errno::EINVAL)?;
    let mut flags = sys::SD_JSON_FORMAT_OFF;
    // SAFETY: arg is a C string, flags a valid out-pointer.
    let r = check(unsafe { sys::parse_json_argument(arg.as_ptr(), &mut flags) })?;
    Ok((r > 0).then_some(flags))
}

/// `sd_json_format_enabled()`: whether the flags ask for JSON output.
pub fn format_enabled(flags: sys::sd_json_format_flags_t) -> bool {
    // SAFETY: plain call into libsystemd-shared.
    unsafe { sys::sd_json_format_enabled(flags) != 0 }
}
