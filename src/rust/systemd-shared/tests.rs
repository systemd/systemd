// SPDX-License-Identifier: LGPL-2.1-or-later

//! Unit tests written in Rust run on the test runner of the C tests (`tests.h`): [`define_test_main!`] is
//! `DEFINE_TEST_MAIN()`, each test is a plain `fn()`, and a failing assertion panics, which logs and aborts
//! like a failed `ASSERT_*()` in C. `$TESTFUNCS` selects tests by name, as for the C tests.
//!
//! ```ignore
//! #![no_std]
//! #![no_main]
//!
//! use systemd_shared::prelude::*;
//!
//! fn test_strv_split() {
//!     let words = Strv::split(c"a b", c" ", 0).unwrap();
//!     assert_eq!(words.len(), 2);
//! }
//!
//! define_test_main!(LOG_INFO, [test_strv_split]);
//! ```

use core::ffi::{c_char, c_int};

use crate::sys;

/// C's `TestFunc`, a `void` test function and its name. Only [`define_test_main!`] creates these.
#[doc(hidden)]
#[repr(C)]
pub struct TestEntry {
    pub func: Option<extern "C" fn()>,
    pub name: *const c_char,
    /// The `has_ret` and `sd_booted` bits, always zero.
    pub flags: u8,
}

// SAFETY: the entries are immutable tables that only C reads.
unsafe impl Sync for TestEntry {}

crate::assert_layout!(
    TestEntry,
    sys::TestFunc,
    func = f,
    name = name,
    flags = _bitfield_1
);

/// Backend of [`define_test_main!`].
///
/// # Safety
///
/// `argc` and `argv` must be the arguments the C runtime handed to `main()`.
#[doc(hidden)]
pub unsafe fn __main(argc: c_int, argv: *mut *mut c_char, log_level: c_int, tests: &[TestEntry]) -> c_int {
    // SAFETY: the caller passes main()'s arguments through.
    unsafe { sys::test_prepare(argc, argv, log_level) };
    // SAFETY: the bounds are those of the slice.
    let r = unsafe { sys::run_test_table(tests.as_ptr().cast(), tests.as_ptr_range().end.cast()) };
    if r < 0 {
        sys::EXIT_FAILURE as c_int
    } else {
        r
    }
}

/// `DEFINE_TEST_MAIN(log_level)`: a `main()` that runs the listed tests, in this order.
#[macro_export]
macro_rules! define_test_main {
    ($log_level:expr, [$($test:ident),* $(,)?]) => {
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
            static __TESTS: &[$crate::tests::TestEntry] = &[$(
                $crate::tests::TestEntry {
                    func: {
                        extern "C" fn __test() {
                            $test()
                        }
                        Some(__test)
                    },
                    name: ::core::concat!(::core::stringify!($test), "\0")
                        .as_ptr()
                        .cast::<::core::ffi::c_char>(),
                    flags: 0,
                },
            )*];

            let __level: ::core::ffi::c_int = $log_level;
            // SAFETY: the C runtime's argc and argv are passed through.
            unsafe { $crate::tests::__main(argc, argv, __level, __TESTS) }
        }
    };
}
