// SPDX-License-Identifier: LGPL-2.1-or-later

//! Rust interface to libsystemd-shared.
//!
//! [`sys`] is the bindgen-generated FFI crate: every function, type and constant of `src/basic/`,
//! `src/shared/`, the public `sd-*.h` headers and the libc/kernel surface systemd code sees, with C trampolines
//! for the static inline helpers. Nothing in it is safe to call; the modules here wrap what programs need in the
//! idiomatic form: owned types with `Drop` for what C frees explicitly, [`Result`] for the negative-errno
//! convention, closures for callbacks, `log_*!` macros that feed systemd's logging and the command line
//! framework of the C programs. A program that needs
//! something [`sys`] has and this crate lacks adds the wrapper here.
//!
//! Binaries written in Rust link libsystemd-shared dynamically, exactly like the C binaries do.

pub use systemd_shared_sys as sys;

pub mod command;
pub mod cstr;
pub mod errno;
pub mod event;
pub mod fd;
pub mod json;
pub mod log;
pub mod prelude;
pub mod program;
pub mod refcount;
pub mod strv;

pub use errno::{check, from_result, Errno, Result};
