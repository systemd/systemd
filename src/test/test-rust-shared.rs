// SPDX-License-Identifier: LGPL-2.1-or-later

//! Exercises libsystemd-shared from a program written in Rust: exported functions, a static inline
//! trampoline, a union passed by value, refcounted objects, error propagation, and an sd-event loop driven
//! from a closure. This is also the end-to-end test for the rust_executables machinery in meson.build.

#![no_main]

use core::ffi::{c_char, CStr};
use core::ptr;
use std::cell::Cell;
use std::os::fd::AsFd;
use std::rc::Rc;

use systemd_shared::prelude::*;
use systemd_shared::{fd, sys};

fn test_strv() -> Result<()> {
    let words = Strv::split(c"one two  three", c" ", sys::EXTRACT_RELAX)?;
    assert_eq!(words.len(), 3);
    assert!(!words.is_empty());
    assert_eq!(words.join(c",")?.as_cstr(), c"one,two,three");
    assert_eq!(
        words.iter().map(|s| s.to_str().unwrap()).collect::<Vec<_>>(),
        ["one", "two", "three"]
    );
    Ok(())
}

// The raw bindings, on purpose: this is what a program does for something the wrapper crate lacks.
fn test_id128() -> Result<()> {
    let mut id = sys::sd_id128_t::default();
    // SAFETY: plain call with a value.
    assert_ne!(unsafe { sys::sd_id128_is_null(id) }, 0);

    // SAFETY: id is a valid out-pointer.
    check(unsafe { sys::sd_id128_randomize(&mut id) })?;
    // SAFETY: plain call with a value.
    assert_eq!(unsafe { sys::sd_id128_is_null(id) }, 0);

    let mut buf: [c_char; sys::SD_ID128_STRING_MAX as usize] = [0; sys::SD_ID128_STRING_MAX as usize];
    // SAFETY: the buffer has SD_ID128_STRING_MAX bytes, as sd_id128_to_string() requires.
    let s = unsafe { CStr::from_ptr(sys::sd_id128_to_string(id, buf.as_mut_ptr())) };
    assert_eq!(s.to_bytes().len(), 32);
    log_info!("sd_id128_randomize(): {}", s.to_string_lossy());
    Ok(())
}

fn test_json() -> Result<()> {
    let v = JsonVariant::new_string(c"hello from rust")?;
    assert_eq!(v.format(0)?.as_cstr(), c"\"hello from rust\"");
    Ok(())
}

fn test_fd() -> Result<()> {
    let root = std::fs::File::open("/")?;
    assert_eq!(fd::get_path(root.as_fd())?.as_cstr(), c"/");

    let mut p: *mut c_char = ptr::null_mut();
    // SAFETY: p is a valid out-pointer, the fd is deliberately not open.
    match check(unsafe { sys::fd_get_path(1_000_000, &mut p) }) {
        Err(Errno::EBADF) => {
            log_debug!(
                "fd_get_path() on an unopened fd failed as expected: {}",
                Errno::EBADF
            );
            Ok(())
        }
        Err(e) => Err(log_error_errno!(e, "Unexpected error from fd_get_path(): {e}")),
        Ok(_) => Err(log_error_errno!(
            Errno::EUCLEAN,
            "fd_get_path() unexpectedly succeeded"
        )),
    }
}

fn test_event() -> Result<()> {
    let event = Event::try_default()?;
    let fired = Rc::new(Cell::new(false));
    let flag = Rc::clone(&fired);
    let _source = event.add_time_relative(
        sys::CLOCK_MONOTONIC as sys::clockid_t,
        10_000,
        0,
        move |source, usec| {
            flag.set(true);
            log_debug!("Timer fired at {usec} µs, leaving the event loop.");
            source.event().exit(0)
        },
    )?;
    assert_eq!(event.run_loop()?, 0);
    assert!(fired.get());
    Ok(())
}

fn test_constants() {
    assert_eq!(sys::UID_INVALID, sys::uid_t::MAX);
    assert_eq!(sys::USEC_INFINITY, u64::MAX);
    assert_eq!(sys::USEC_PER_SEC, 1_000_000);
    assert_eq!(sys::AT_FDCWD, -100);
    assert_eq!(sys::PROC_SUPER_MAGIC, 0x9fa0);
}

fn run(_argv: Argv) -> Result<()> {
    log_info!("Hello from Rust, dynamically linked against libsystemd-shared.");

    test_strv()?;
    test_id128()?;
    test_json()?;
    test_fd()?;
    test_event()?;
    test_constants();

    Ok(())
}

define_main!(run);
