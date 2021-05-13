// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Extract the i'nth line from the specified string. Returns > 0 if there are more lines after that,
/// and == 0 if we are looking at the last line or already beyond the last line. As special
/// optimization, if the first line is requested and the string only consists of one line we return
/// NULL, indicating the input string should be used as is, and avoid a memory allocation for a very
/// common case.
#[no_mangle]
pub extern "C" fn string_extract_line(s: *const c_char, i: usize, ret: *mut *mut c_char) -> i32 {
    if ret.is_null() {
        panic!("string_extract_line(): 'ret' cannot be NULL");
    }

    let s = unsafe {
        CStr::from_ptr(s)
            .to_string_lossy()
            .into_owned()
    };
    let mut found: bool = false;

    for (j, item) in s.lines().enumerate() {
        if i == j {
            unsafe {
                *ret = CString::new(item)
                    .expect("CString::new failed")
                    .into_raw();
            }

            // TODO: can we peek forward in the iterator? If so, can remove this variable
            found = true;
            continue;
        }
        if found {
            return 1;
        }
    }

    if !found {
        unsafe {
            *ret = CString::new("")
                .expect("CString::new failed")
                .into_raw();
        }
    }

    return 0
}
