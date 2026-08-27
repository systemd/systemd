// SPDX-License-Identifier: LGPL-2.1-or-later

//! `DEFINE_MAIN_FUNCTION()` for Rust.

use core::ffi::{c_char, c_int};

use crate::command::Argv;
use crate::errno::Result;
use crate::sys;

/// Declares `main()` the way `DEFINE_MAIN_FUNCTION()` does in C, around a `fn(Argv<'_>) -> Result<()>`: it runs
/// `main_prepare()`, `log_setup()`, the body, and `main_finalize()`, and maps `Err` to `EXIT_FAILURE`.
/// Logging the error is the body's job, as in C. Panics are logged at `LOG_CRIT` with their location and
/// abort the program, like a failed `assert()`.
///
/// The crate root needs `#![no_main]`, and `#![no_std]` like all Rust code in the tree.
///
/// ```ignore
/// #![no_std]
/// #![no_main]
///
/// use systemd_shared::prelude::*;
///
/// fn run(argv: Argv<'_>) -> Result<()> {
///     log_info!("Hello, {} arguments.", argv.len());
///     Ok(())
/// }
///
/// define_main!(run);
/// ```
#[macro_export]
macro_rules! define_main {
    ($body:path) => {
        $crate::__define_main!(__main, $body);
    };
}

/// `DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE()`: like [`define_main!`], around a
/// `fn(Argv<'_>) -> Result<c_int>` whose `Ok` value is the exit status, so that a program can report a failure
/// other than `EXIT_FAILURE`.
#[macro_export]
macro_rules! define_main_with_positive_failure {
    ($body:path) => {
        $crate::__define_main!(__main_with_positive_failure, $body);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __define_main {
    ($backend:ident, $body:path) => {
        /// The C `main()`.
        ///
        /// # Safety
        ///
        /// Only the C runtime calls this, with its `argc` and `argv`.
        #[doc(hidden)]
        #[no_mangle]
        pub unsafe extern "C" fn main(
            argc: ::core::ffi::c_int,
            argv: *mut *mut ::core::ffi::c_char,
        ) -> ::core::ffi::c_int {
            let __body = $body;
            // SAFETY: the C runtime's argc and argv are passed through.
            unsafe { $crate::program::$backend(argc, argv, __body) }
        }
    };
}

/// Backend of [`define_main!`].
///
/// # Safety
///
/// `argc` and `argv` must be the arguments the C runtime handed to `main()`.
#[doc(hidden)]
pub unsafe fn __main(argc: c_int, argv: *mut *mut c_char, body: fn(Argv<'_>) -> Result<()>) -> c_int {
    // SAFETY: the caller passes main()'s arguments through.
    unsafe {
        run(argc, argv, false, |args| match body(args) {
            Ok(()) => 0,
            Err(e) => e.negative(),
        })
    }
}

/// Backend of [`define_main_with_positive_failure!`].
///
/// # Safety
///
/// `argc` and `argv` must be the arguments the C runtime handed to `main()`.
#[doc(hidden)]
pub unsafe fn __main_with_positive_failure(
    argc: c_int,
    argv: *mut *mut c_char,
    body: fn(Argv<'_>) -> Result<c_int>,
) -> c_int {
    // SAFETY: the caller passes main()'s arguments through.
    unsafe {
        run(argc, argv, true, |args| match body(args) {
            Ok(status) => {
                debug_assert!(status >= 0, "exit status must not be negative");
                status
            }
            Err(e) => e.negative(),
        })
    }
}

/// `_DEFINE_MAIN_FUNCTION()`.
///
/// # Safety
///
/// `argc` and `argv` must be the arguments the C runtime handed to `main()`.
unsafe fn run(
    argc: c_int,
    argv: *mut *mut c_char,
    positive_failure: bool,
    body: impl FnOnce(Argv<'_>) -> c_int,
) -> c_int {
    // SAFETY: the caller passes main()'s arguments through.
    unsafe { sys::main_prepare(argc, argv) };
    crate::log::setup();

    // SAFETY: the C runtime's argv is NULL-terminated and lives as long as the program, only the unsafe
    // rename_process() modifies it.
    let r = body(unsafe { Argv::from_raw(argc, argv) });

    let status = if positive_failure {
        // SAFETY: plain call into libsystemd-shared.
        unsafe { sys::exit_failure_if_nonzero(r) }
    } else {
        // SAFETY: plain call into libsystemd-shared.
        unsafe { sys::exit_failure_if_negative(r) }
    };
    // SAFETY: plain call into libsystemd-shared.
    unsafe { sys::main_finalize(r, status) };
    status
}
