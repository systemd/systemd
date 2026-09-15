// SPDX-License-Identifier: LGPL-2.1-or-later

//! systemd's logging, driven from Rust.
//!
//! The `log_*!` macros mirror their C counterparts: `log_info!("...")` logs, `log_error_errno!(e, "...")`
//! logs and evaluates to the [`Errno`](crate::Errno), so `return Err(log_error_errno!(r, "..."))` reads
//! like `return log_error_errno(r, "...")` in C. Messages are formatted into a `LINE_MAX` buffer on the
//! stack and handed to `log_dispatch_internal()`, the same path `log_internalv()` takes after `vsnprintf()`:
//! no allocation, and long messages are truncated the way C truncates them.

use core::ffi::{c_int, CStr};
use core::fmt::{self, Write};
use core::ptr;

use crate::sys;

pub use sys::{LOG_ALERT, LOG_CRIT, LOG_DEBUG, LOG_EMERG, LOG_ERR, LOG_INFO, LOG_NOTICE, LOG_WARNING};

/// `log_setup()`, as called from every C main function.
pub fn setup() {
    // SAFETY: plain call into libsystemd-shared.
    unsafe { sys::log_setup() }
}

/// The current maximum log level, `log_get_max_level()`.
pub fn max_level() -> c_int {
    // SAFETY: plain call into libsystemd-shared.
    unsafe { sys::log_get_max_level() }
}

/// Sets the maximum log level and returns the previous one, `log_set_max_level()`.
pub fn set_max_level(level: c_int) -> c_int {
    // SAFETY: plain call into libsystemd-shared.
    unsafe { sys::log_set_max_level(level) }
}

/// Turns a NUL-terminated string literal into a `CStr` at compile time. Backend of the `log_*!` macros.
#[doc(hidden)]
pub const fn __cstr(s: &'static str) -> &'static CStr {
    match CStr::from_bytes_with_nul(s.as_bytes()) {
        Ok(c) => c,
        Err(_) => panic!("not a NUL-terminated string"),
    }
}

const LINE_MAX: usize = sys::LINE_MAX as usize;

struct Buffer {
    bytes: [u8; LINE_MAX],
    len: usize,
}

impl fmt::Write for Buffer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(LINE_MAX - 1 - self.len);
        self.bytes[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// Backend of the `log_*!` macros.
#[doc(hidden)]
pub fn __log(level: u32, error: c_int, file: &CStr, line: u32, func: &CStr, args: fmt::Arguments<'_>) {
    let level = level as c_int;

    // Same early-out as log_internalv() in C, LOG_PRI() is the low three bits.
    if max_level() < (level & 7) {
        return;
    }

    let mut buffer = Buffer {
        bytes: [0; LINE_MAX],
        len: 0,
    };
    // Buffer::write_str() never fails, it truncates like vsnprintf() does.
    let _ = buffer.write_fmt(args);
    buffer.bytes[buffer.len] = 0;

    // SAFETY: file, func and the buffer are NUL-terminated, the buffer is writable and outlives the call
    // (log_dispatch_internal() splits it at newlines in place), the optional fields are NULL as in
    // log_internalv().
    unsafe {
        sys::log_dispatch_internal(
            level,
            error,
            file.as_ptr(),
            line as c_int,
            func.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            buffer.bytes.as_mut_ptr().cast(),
        );
    }
}

/// Logs at the given level, `log_full()` in C.
#[macro_export]
macro_rules! log_full {
    ($level:expr, $($arg:tt)*) => {
        $crate::log::__log(
            $level,
            0,
            const { $crate::log::__cstr(concat!(file!(), "\0")) },
            line!(),
            const { $crate::log::__cstr(concat!(module_path!(), "\0")) },
            format_args!($($arg)*),
        )
    };
}

/// Logs at the given level with an errno and evaluates to the [`Errno`](crate::Errno), `log_full_errno()`
/// in C.
#[macro_export]
macro_rules! log_full_errno {
    ($level:expr, $error:expr, $($arg:tt)*) => {{
        let __e: $crate::errno::Errno = ::core::convert::From::from($error);
        $crate::log::__log(
            $level,
            __e.code(),
            const { $crate::log::__cstr(concat!(file!(), "\0")) },
            line!(),
            const { $crate::log::__cstr(concat!(module_path!(), "\0")) },
            format_args!($($arg)*),
        );
        __e
    }};
}

/// `log_error()`.
#[macro_export]
macro_rules! log_error { ($($arg:tt)*) => { $crate::log_full!($crate::log::LOG_ERR, $($arg)*) }; }
/// `log_warning()`.
#[macro_export]
macro_rules! log_warning { ($($arg:tt)*) => { $crate::log_full!($crate::log::LOG_WARNING, $($arg)*) }; }
/// `log_notice()`.
#[macro_export]
macro_rules! log_notice { ($($arg:tt)*) => { $crate::log_full!($crate::log::LOG_NOTICE, $($arg)*) }; }
/// `log_info()`.
#[macro_export]
macro_rules! log_info { ($($arg:tt)*) => { $crate::log_full!($crate::log::LOG_INFO, $($arg)*) }; }
/// `log_debug()`.
#[macro_export]
macro_rules! log_debug { ($($arg:tt)*) => { $crate::log_full!($crate::log::LOG_DEBUG, $($arg)*) }; }

/// `log_error_errno()`.
#[macro_export]
macro_rules! log_error_errno { ($error:expr, $($arg:tt)*) => { $crate::log_full_errno!($crate::log::LOG_ERR, $error, $($arg)*) }; }
/// `log_warning_errno()`.
#[macro_export]
macro_rules! log_warning_errno { ($error:expr, $($arg:tt)*) => { $crate::log_full_errno!($crate::log::LOG_WARNING, $error, $($arg)*) }; }
/// `log_notice_errno()`.
#[macro_export]
macro_rules! log_notice_errno { ($error:expr, $($arg:tt)*) => { $crate::log_full_errno!($crate::log::LOG_NOTICE, $error, $($arg)*) }; }
/// `log_info_errno()`.
#[macro_export]
macro_rules! log_info_errno { ($error:expr, $($arg:tt)*) => { $crate::log_full_errno!($crate::log::LOG_INFO, $error, $($arg)*) }; }
/// `log_debug_errno()`.
#[macro_export]
macro_rules! log_debug_errno { ($error:expr, $($arg:tt)*) => { $crate::log_full_errno!($crate::log::LOG_DEBUG, $error, $($arg)*) }; }

/// `log_oom()`.
#[macro_export]
macro_rules! log_oom {
    () => {
        $crate::log_full_errno!(
            $crate::log::LOG_ERR,
            $crate::errno::Errno::ENOMEM,
            "Out of memory."
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Errno;

    #[test]
    fn errno_macros_evaluate_to_the_errno() {
        let e: Errno = log_debug_errno!(sys::ENOENT as c_int, "not there: {}", "x");
        assert_eq!(e, Errno::ENOENT);

        let e2 = log_debug_errno!(e, "again");
        assert_eq!(e2, e);

        let e3 = log_debug_errno!(std::io::Error::from(Errno::EBUSY), "io::Error converts too");
        assert_eq!(e3, Errno::EBUSY);

        // log_oom!() logs at LOG_ERR, keep it out of the test output.
        let old = set_max_level(LOG_CRIT as c_int);
        assert_eq!(log_oom!(), Errno::ENOMEM);
        set_max_level(old);
    }

    #[test]
    fn plain_macros_are_unit() {
        let _: () = log_debug!("hello {}", 42);
    }

    #[test]
    fn long_and_odd_messages_do_not_panic() {
        log_debug!("{}", "x".repeat(3 * LINE_MAX));
        log_debug!("a\0b");
        log_debug!("");
    }

    #[test]
    fn buffer_truncates_like_vsnprintf() {
        let mut b = Buffer {
            bytes: [0; LINE_MAX],
            len: 0,
        };
        write!(b, "{}", "y".repeat(LINE_MAX + 10)).unwrap();
        assert_eq!(b.len, LINE_MAX - 1);
        b.bytes[b.len] = 0;
        assert_eq!(
            CStr::from_bytes_until_nul(&b.bytes).unwrap().to_bytes().len(),
            LINE_MAX - 1
        );
    }
}
