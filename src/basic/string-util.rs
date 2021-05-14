// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::ptr;

/// Extract the i'nth line from the specified string. Returns > 0 if there are more lines after that,
/// and == 0 if we are looking at the last line or already beyond the last line. As special
/// optimization, if the first line is requested and the string only consists of one line we return
/// NULL, indicating the input string should be used as is, and avoid a memory allocation for a very
/// common case.
#[no_mangle]
pub unsafe extern "C" fn string_extract_line(s: *const c_char, i: usize, ret: *mut *mut c_char) -> c_int {
    let s = CStr::from_ptr(s).to_string_lossy();
    let mut lines = s.lines().enumerate().peekable();

    while let Some((j, item)) = lines.next() {
        if i == j && lines.peek() == None {
            // Special case: the iterator will terminate if there's only one line, but it
            // terminates with a newline character, so ensure to check for that too
            if i == 0 && !s.ends_with("\n") {
                *ret = ptr::null_mut();
            } else {
                *ret = match CString::new(item) {
                    Ok(res) => res.into_raw(),
                    Err(_error) => return -1,
                };
            }

            return 0;
        }

        if i == j {
            *ret = match CString::new(item) {
                Ok(res) => res.into_raw(),
                Err(_error) => return -1,
            };

            return 1;
        }
    }

    *ret = match CString::new("") {
        Ok(res) => res.into_raw(),
        Err(_error) => return -1,
    };

    return 0
}
