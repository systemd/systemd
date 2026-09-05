// SPDX-License-Identifier: LGPL-2.1-or-later

//! `DEFINE_MAIN_FUNCTION()` for Rust.

use core::ffi::{c_char, c_int};
use std::ffi::CString;
use std::io::Write;
use std::panic::PanicHookInfo;

use crate::command::Argv;
use crate::errno::Result;
use crate::log::LOG_CRIT;
use crate::sys;

/// Declares `main()` the way `DEFINE_MAIN_FUNCTION()` does in C, around a `fn(Argv) -> Result<()>`: it runs
/// `main_prepare()`, `log_setup()`, the body, and `main_finalize()`, and maps `Err` to `EXIT_FAILURE`.
/// Logging the error is the body's job, as in C. Panics are logged at `LOG_CRIT` with their location and
/// abort the program, like a failed `assert()`.
///
/// The crate root needs `#![no_main]`: `main_prepare()` has to see the real `argv`, which `rename_process()`
/// later overwrites. `std::env::args()` keeps working.
///
/// ```ignore
/// #![no_main]
///
/// use systemd_shared::prelude::*;
///
/// fn run(argv: Argv) -> Result<()> {
///     log_info!("Hello, {} arguments.", argv.len());
///     Ok(())
/// }
///
/// define_main!(run);
/// ```
#[macro_export]
macro_rules! define_main {
    ($body:path) => {
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
            // SAFETY: the C runtime's argc and argv are passed through.
            unsafe { $crate::program::__main(argc, argv, $body) }
        }
    };
}

/// Backend of [`define_main!`].
///
/// # Safety
///
/// `argc` and `argv` must be the arguments the C runtime handed to `main()`.
#[doc(hidden)]
pub unsafe fn __main(argc: c_int, argv: *mut *mut c_char, body: fn(Argv) -> Result<()>) -> c_int {
    // SAFETY: the caller passes main()'s arguments through.
    unsafe { sys::main_prepare(argc, argv) };
    crate::log::setup();
    std::panic::set_hook(Box::new(panic_hook));

    // SAFETY: the C runtime's argv is NULL-terminated and lives as long as the program.
    let r = match body(unsafe { Argv::from_raw(argc, argv) }) {
        Ok(()) => 0,
        Err(e) => e.negative(),
    };

    // SAFETY: plain calls into libsystemd-shared.
    let status = unsafe {
        let status = sys::exit_failure_if_negative(r);
        sys::main_finalize(r, status);
        status
    };

    // Returning from a C main() skips std's own exit path, so flush what it buffered.
    let _ = std::io::stdout().flush();
    status
}

fn panic_hook(info: &PanicHookInfo<'_>) {
    let payload = info.payload();
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("(non-string payload)");
    let (file, line) = info
        .location()
        .map_or((String::new(), 0), |l| (l.file().to_owned(), l.line()));
    let file = CString::new(file).unwrap_or_default();
    crate::log::__log(
        LOG_CRIT,
        0,
        &file,
        line,
        c"panic",
        format_args!("Panic: {message}. Aborting."),
    );
}
