// SPDX-License-Identifier: LGPL-2.1-or-later

//! systemd's logging, driven from Rust.
//!
//! The `log_*!` macros mirror their C counterparts: `log_info!("...")` logs, `log_error_errno!(e, "...")`
//! logs and evaluates to the [`Errno`](crate::Errno), so `return Err(log_error_errno!(r, "..."))` reads
//! like `return log_error_errno(r, "...")` in C. Messages are formatted into a `LINE_MAX` buffer on the
//! stack and handed to `log_dispatch_internal()`, the same path `log_internalv()` takes after `vsnprintf()`:
//! no allocation, and long messages are truncated the way C truncates them. Rust has no `__func__`,
//! `CODE_FUNC=` carries the module path instead.

use core::ffi::{c_int, CStr};
use core::fmt::{self, Write};
use core::ptr;

use crate::sys;

/// The syslog levels, as the `int` the C helpers take.
pub const LOG_EMERG: c_int = sys::LOG_EMERG as c_int;
/// See [`LOG_EMERG`].
pub const LOG_ALERT: c_int = sys::LOG_ALERT as c_int;
/// See [`LOG_EMERG`].
pub const LOG_CRIT: c_int = sys::LOG_CRIT as c_int;
/// See [`LOG_EMERG`].
pub const LOG_ERR: c_int = sys::LOG_ERR as c_int;
/// See [`LOG_EMERG`].
pub const LOG_WARNING: c_int = sys::LOG_WARNING as c_int;
/// See [`LOG_EMERG`].
pub const LOG_NOTICE: c_int = sys::LOG_NOTICE as c_int;
/// See [`LOG_EMERG`].
pub const LOG_INFO: c_int = sys::LOG_INFO as c_int;
/// See [`LOG_EMERG`].
pub const LOG_DEBUG: c_int = sys::LOG_DEBUG as c_int;

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

/// Sets the maximum log level and returns the previous one, `log_set_max_level()`. A level outside
/// [`LOG_EMERG`]..=[`LOG_DEBUG`] aborts, like C's assertion.
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

/// Whether a message at `level` is logged, the check C's `log_full_errno()` makes before it evaluates the
/// arguments. `LOG_PRI()` is the low three bits. Backend of the `log_*!` macros.
#[doc(hidden)]
pub fn __enabled(level: c_int) -> bool {
    max_level() >= (level & 7)
}

/// Backend of the `log_*!` macros.
#[doc(hidden)]
pub fn __log(level: c_int, error: c_int, file: &CStr, line: u32, func: &CStr, args: fmt::Arguments<'_>) {
    if !__enabled(level) {
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

/// Logs at the given level, `log_full()` in C. The arguments are only evaluated if the level is enabled.
#[macro_export]
macro_rules! log_full {
    ($level:expr, $($arg:tt)*) => {{
        let __level: ::core::ffi::c_int = $level;
        if $crate::log::__enabled(__level) {
            $crate::log::__log(
                __level,
                0,
                const { $crate::log::__cstr(::core::concat!(::core::file!(), "\0")) },
                ::core::line!(),
                const { $crate::log::__cstr(::core::concat!(::core::module_path!(), "\0")) },
                ::core::format_args!($($arg)*),
            );
        }
    }};
}

/// The bit `SYNTHETIC_ERRNO()` sets: the error did not come from the system, the record carries no `ERRNO=`.
#[doc(hidden)]
pub const __SYNTHETIC_ERRNO: c_int = 1 << 30;

/// Logs at the given level with an errno and evaluates to the [`Errno`](crate::Errno), `log_full_errno()`
/// in C. `SYNTHETIC_ERRNO(EINVAL)` as the error is `SYNTHETIC_ERRNO(EINVAL)` in C: an error the program
/// detected itself, logged without `ERRNO=`. The level and the error are always evaluated, the message
/// arguments only if the level is enabled.
#[macro_export]
macro_rules! log_full_errno {
    (@log $level:expr, $error:expr, $flags:expr, $($arg:tt)*) => {{
        let __level: ::core::ffi::c_int = $level;
        let __e: $crate::errno::Errno = ::core::convert::From::from($error);
        if $crate::log::__enabled(__level) {
            $crate::log::__log(
                __level,
                __e.code() | $flags,
                const { $crate::log::__cstr(::core::concat!(::core::file!(), "\0")) },
                ::core::line!(),
                const { $crate::log::__cstr(::core::concat!(::core::module_path!(), "\0")) },
                ::core::format_args!($($arg)*),
            );
        }
        __e
    }};
    ($level:expr, SYNTHETIC_ERRNO($errno:ident), $($arg:tt)*) => {
        $crate::log_full_errno!(@log $level, $crate::errno::Errno::$errno, $crate::log::__SYNTHETIC_ERRNO, $($arg)*)
    };
    ($level:expr, $error:expr, $($arg:tt)*) => {
        $crate::log_full_errno!(@log $level, $error, 0, $($arg)*)
    };
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
macro_rules! log_error_errno { ($($arg:tt)*) => { $crate::log_full_errno!($crate::log::LOG_ERR, $($arg)*) }; }
/// `log_warning_errno()`.
#[macro_export]
macro_rules! log_warning_errno { ($($arg:tt)*) => { $crate::log_full_errno!($crate::log::LOG_WARNING, $($arg)*) }; }
/// `log_notice_errno()`.
#[macro_export]
macro_rules! log_notice_errno { ($($arg:tt)*) => { $crate::log_full_errno!($crate::log::LOG_NOTICE, $($arg)*) }; }
/// `log_info_errno()`.
#[macro_export]
macro_rules! log_info_errno { ($($arg:tt)*) => { $crate::log_full_errno!($crate::log::LOG_INFO, $($arg)*) }; }
/// `log_debug_errno()`.
#[macro_export]
macro_rules! log_debug_errno { ($($arg:tt)*) => { $crate::log_full_errno!($crate::log::LOG_DEBUG, $($arg)*) }; }

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
