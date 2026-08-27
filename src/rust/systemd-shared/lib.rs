// SPDX-License-Identifier: LGPL-2.1-or-later

//! Rust interface to libsystemd-shared.
//!
//! [`sys`] is the bindgen-generated FFI crate: every function, type and constant of `src/basic/`,
//! `src/shared/`, the public `sd-*.h` headers and the libc/kernel surface systemd code sees, with C trampolines
//! for the static inline helpers. Nothing in it is safe to call; the modules here wrap what programs need in the
//! idiomatic form: owned types with `Drop` for what C frees explicitly, [`Result`] for the negative-errno
//! convention, `log_*!` macros that feed systemd's logging and the command line framework of the C
//! programs. A program that needs something [`sys`] has and this crate lacks adds the wrapper here.
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

pub mod alloc;
pub mod cstr;
pub mod errno;
pub mod fd;
pub mod json;
pub mod log;
mod panic;
pub mod prelude;
pub mod stdio;
pub mod strv;

pub use errno::{check, from_result, Errno, Result};
