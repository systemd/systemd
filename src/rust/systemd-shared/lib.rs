// SPDX-License-Identifier: LGPL-2.1-or-later

//! Rust interface to libsystemd-shared.
//!
//! [`sys`] is the bindgen-generated FFI crate: every function, type and constant of `src/basic/`,
//! `src/shared/`, the public `sd-*.h` headers and the libc/kernel surface systemd code sees, with C trampolines
//! for the static inline helpers. Nothing in it is safe to call; the modules here wrap what programs need in the
//! idiomatic form: owned types with `Drop` for what C frees explicitly, [`Result`] for the negative-errno
//! convention, closures for callbacks, `log_*!` macros that feed systemd's logging and the command line
//! framework of the C programs. A program that needs something [`sys`] has and this crate lacks adds the
//! wrapper here.
//!
//! Binaries written in Rust link libsystemd-shared dynamically, exactly like the C binaries do.
//!
//! There is no std, and like in the kernel's Rust code there is no `alloc` either: its collections abort the
//! program when memory runs out. [`alloc`] has a [`Box`](alloc::Box) and a [`Vec`](alloc::Vec) instead,
//! whose allocating functions return an error. This crate fills the other gaps std would fill: a panic is
//! logged at `LOG_CRIT` and aborts the program, and [`print!`] and [`println!`] write to C's `stdout`. A
//! program that pulls in std regardless does not link, std brings a second panic handler, and neither does one
//! that allocates through `alloc`, there is no global allocator.

#![no_std]

pub use systemd_shared_sys as sys;

/// Asserts at compile time that a Rust mirror of a C struct has its size, alignment and field offsets, with
/// `ours = theirs` where a field is named differently.
macro_rules! assert_layout {
    ($ours:ty, $c:ty, $($field:ident),+ $(,)?) => {
        crate::assert_layout!($ours, $c, $($field = $field),+);
    };
    ($ours:ty, $c:ty, $($field:ident = $c_field:ident),+ $(,)?) => {
        const _: () = assert!(::core::mem::size_of::<$ours>() == ::core::mem::size_of::<$c>());
        const _: () = assert!(::core::mem::align_of::<$ours>() == ::core::mem::align_of::<$c>());
        $(const _: () = assert!(::core::mem::offset_of!($ours, $field) == ::core::mem::offset_of!($c, $c_field));)+
    };
}
pub(crate) use assert_layout;

pub mod alloc;
pub mod chase;
pub mod command;
pub mod creds;
pub mod cstr;
pub mod errno;
pub mod event;
pub mod fd;
pub mod fileio;
pub mod json;
pub mod keyring;
pub mod log;
mod panic;
pub mod prelude;
pub mod program;
pub mod recurse_dir;
pub mod refcount;
pub mod stdio;
pub mod strv;
pub mod tests;
pub mod tmpfile;

pub use errno::{check, from_result, Errno, Result};
