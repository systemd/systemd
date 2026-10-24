// SPDX-License-Identifier: LGPL-2.1-or-later

//! Panics. Programs are built with `-C panic=abort`: a panic is logged at `LOG_CRIT` with its location, like a
//! failed `assert()` in C, and aborts the program.

use core::ffi::CStr;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::log::LOG_CRIT;
use crate::sys;

static PANICKING: AtomicBool = AtomicBool::new(false);

/// Copies `s` into `buf` as a C string, truncated at the buffer size or at an embedded NUL.
fn to_cstr<'a>(s: &str, buf: &'a mut [u8]) -> &'a CStr {
    let n = s.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&s.as_bytes()[..n]);
    buf[n] = 0;
    CStr::from_bytes_until_nul(buf).unwrap_or(c"")
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    // A panic while logging the first one aborts right away.
    if !PANICKING.swap(true, Ordering::Relaxed) {
        let mut buf = [0u8; 256];
        match info.location() {
            Some(l) => crate::log::__log(
                LOG_CRIT,
                0,
                to_cstr(l.file(), &mut buf),
                l.line(),
                c"panic",
                format_args!(
                    "Panic at {}:{}: {}. Aborting.",
                    l.file(),
                    l.line(),
                    info.message()
                ),
            ),
            None => crate::log::__log(
                LOG_CRIT,
                0,
                c"",
                0,
                c"panic",
                format_args!("Panic: {}. Aborting.", info.message()),
            ),
        }
    }

    // Not expect(), clippy 1.85 does not report the call.
    // SAFETY: plain call into libc.
    #[allow(clippy::disallowed_methods)]
    unsafe {
        sys::abort()
    }
}

// The precompiled core and compiler_builtins crates are built for unwinding and refer to the personality
// routine. Nothing unwinds with panic=abort, so it never runs; should a foreign exception ever reach a Rust frame,
// abort.
#[no_mangle]
extern "C" fn rust_eh_personality() -> ! {
    // Not expect(), clippy 1.85 does not report the call.
    // SAFETY: plain call into libc.
    #[allow(clippy::disallowed_methods)]
    unsafe {
        sys::abort()
    }
}
