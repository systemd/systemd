// SPDX-License-Identifier: LGPL-2.1-or-later

//! [`print!`] and [`println!`]. They write to C's `stdout`, so that their output and that of C code called by
//! the program (`--help`, tables, ...) share one buffer and keep their order. Write errors are ignored, as
//! `printf()` ignores them.

use core::fmt::{self, Write};

use crate::sys;

struct Stdout;

impl Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // SAFETY: s is valid for s.len() bytes, stdout is libc's stream.
        let n = unsafe { sys::fwrite(s.as_ptr().cast(), 1, s.len(), sys::stdout) };
        if n == s.len() {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

/// Backend of [`print!`] and [`println!`].
#[doc(hidden)]
pub fn __print(args: fmt::Arguments<'_>) {
    let _ = Stdout.write_fmt(args);
}

/// Prints to `stdout`, `printf()`.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::stdio::__print(::core::format_args!($($arg)*))
    };
}

/// Prints to `stdout` with a newline, `printf("...\n")`.
#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n")
    };
    ($($arg:tt)*) => {
        $crate::stdio::__print(::core::format_args!("{}\n", ::core::format_args!($($arg)*)))
    };
}
