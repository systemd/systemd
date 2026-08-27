// SPDX-License-Identifier: LGPL-2.1-or-later

//! Tests the systemd_shared crate, and through it libsystemd-shared from a program written in Rust: exported
//! functions, a static inline trampoline, a union passed by value, refcounted objects, the errno conventions,
//! the libc constants, file descriptors, logging, the fallible Box and Vec, and sd-event loops driven from closures.
//! This is also the end-to-end test for the rust_executables machinery in meson.build.

#![no_std]
#![no_main]

use core::ffi::{c_char, c_int, CStr};
use core::mem::{align_of, size_of};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use systemd_shared::cstr::{self, display};
use systemd_shared::prelude::*;
use systemd_shared::{fd, json, log, sys};

fn errno(code: u32) -> c_int {
    -c_int::try_from(code).unwrap()
}

/// Like `format!`, which needs the alloc crate, but into a C string and fallibly.
macro_rules! format_cstr {
    ($($arg:tt)*) => {
        cstr::try_format(format_args!($($arg)*)).unwrap()
    };
}

fn test_errno_check() {
    assert_eq!(check(0), Ok(0));
    assert_eq!(check(7), Ok(7));
    assert_eq!(check(errno(sys::ENOENT)), Err(Errno::ENOENT));
}

fn test_errno_sign() {
    let e = Errno::from_code(errno(sys::EINVAL));
    assert_eq!(e, Errno::EINVAL);
    assert_eq!(e.code(), -errno(sys::EINVAL));
    assert_eq!(e.negative(), errno(sys::EINVAL));
    assert_eq!(Errno::from(-errno(sys::EINVAL)), e);
    assert_eq!(size_of::<Result<()>>(), size_of::<c_int>());
}

fn test_errno_conversions() {
    assert_eq!(Errno::from(u8::try_from(300).unwrap_err()), Errno::ERANGE);
    let invalid = core::hint::black_box([0xffu8]);
    assert_eq!(
        Errno::from(core::str::from_utf8(&invalid).unwrap_err()),
        Errno::EINVAL
    );
    assert_eq!(Errno::from(AllocError), Errno::ENOMEM);
    assert_eq!(from_result(|| Ok(5)), 5);
    assert_eq!(from_result(|| Err(Errno::EAGAIN)), Errno::EAGAIN.negative());
}

fn test_errno_names() {
    assert_eq!(Errno::ENOENT.name(), Some(c"ENOENT"));
    assert_eq!(Errno::from_code(-100_000).name(), None);
    assert_eq!(
        format_cstr!("{}", Errno::ENOENT).as_cstr(),
        c"No such file or directory"
    );
    assert_eq!(format_cstr!("{:?}", Errno::EBADF).as_cstr(), c"Errno(EBADF)");
    assert_eq!(
        format_cstr!("{:?}", Errno::from_code(100_000)).as_cstr(),
        c"Errno(100000)"
    );
}

fn test_errno_last_os_error() {
    if cfg!(HAS_FEATURE_ADDRESS_SANITIZER) {
        log_info!("ASan aborts instead of failing the allocation, skipping");
        return;
    }
    // SAFETY: plain call into libc, which fails and sets errno. black_box() keeps the optimizer from eliding
    // the allocation and assuming it succeeded.
    let p = core::hint::black_box(unsafe { sys::malloc(usize::MAX) });
    assert!(p.is_null());
    assert_eq!(Errno::last_os_error(), Errno::ENOMEM);
}

fn test_log_errno_macros() {
    let e: Errno = log_debug_errno!(errno(sys::ENOENT), "not there: {}", "x");
    assert_eq!(e, Errno::ENOENT);
    assert_eq!(log_debug_errno!(e, "again"), e);

    // Only the log record tells a synthetic error apart.
    assert_eq!(
        log_debug_errno!(SYNTHETIC_ERRNO(EINVAL), "made up: {}", 1),
        Errno::EINVAL
    );

    // log_oom!() logs at LOG_ERR, keep it out of the test output.
    let old = log::set_max_level(LOG_CRIT);
    assert_eq!(log_oom!(), Errno::ENOMEM);
    log::set_max_level(old);
}

/// A character repeated, formatted without allocating.
struct Repeat(char, usize);

impl core::fmt::Display for Repeat {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        (0..self.1).try_for_each(|_| f.write_fmt(format_args!("{}", self.0)))
    }
}

fn test_log_messages() {
    let _: () = log_debug!("hello {}", 42);
    // Must not trip over a message beyond LINE_MAX (truncated like vsnprintf() does) or an embedded NUL
    // (ends the message early).
    log_debug!("{}", Repeat('x', 3 * sys::LINE_MAX as usize));
    log_debug!("a\0b");
    log_debug!("");
}

fn test_cstr() {
    // SAFETY: NULL is explicitly allowed.
    assert!(unsafe { OwnedCStr::from_raw(ptr::null_mut()) }.is_none());

    // SAFETY: strdup() returns a malloc()ed string we own.
    let s = unsafe { OwnedCStr::from_raw(sys::strdup(c"hello".as_ptr())) }.unwrap();
    assert_eq!(s.as_cstr(), c"hello");
    assert_eq!(format_cstr!("{s}").as_cstr(), c"hello");
    assert_eq!(format_cstr!("{s:?}").as_cstr(), c"\"hello\"");

    let raw = s.into_raw();
    // SAFETY: we took the pointer back, so we free it.
    unsafe { sys::free(raw.cast()) };

    assert_eq!(OwnedCStr::try_from(c"copy").unwrap().as_cstr(), c"copy");
    assert_eq!(OwnedCStr::try_from_bytes(b"bytes").unwrap().as_cstr(), c"bytes");
    assert_eq!(OwnedCStr::try_from_bytes(b"a\0b").unwrap_err(), Errno::EINVAL);
    assert_eq!(
        cstr::try_format(format_args!("{}-{}", 1, "two"))
            .unwrap()
            .as_cstr(),
        c"1-two"
    );
    struct Fails;
    impl core::fmt::Display for Fails {
        fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            Err(core::fmt::Error)
        }
    }
    assert_eq!(
        cstr::try_format(format_args!("{Fails}")).unwrap_err(),
        Errno::EINVAL
    );

    assert_eq!(
        cstr::strip_prefix(c"keyring-setup.os", b"keyring-setup."),
        Some(c"os")
    );
    assert_eq!(cstr::strip_prefix(c"os", b"os"), Some(c""));
    assert_eq!(cstr::strip_prefix(c"os", b"keyring"), None);

    // Invalid UTF-8 is replaced, not dropped.
    assert_eq!(format_cstr!("{}", display(c"a\xffb")).as_cstr(), c"a\u{FFFD}b");
}

fn test_strv() {
    let empty = Strv::new();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.iter().count(), 0);
    assert_eq!(empty.join(c",").unwrap().as_cstr(), c"");

    let mut v = Strv::split(c"one two  three", c" ", sys::EXTRACT_RELAX).unwrap();
    assert_eq!(v.len(), 3);
    assert!(!v.is_empty());
    assert!(v.iter().map(|s| s.to_str().unwrap()).eq(["one", "two", "three"]));
    assert_eq!(v.join(c",").unwrap().as_cstr(), c"one,two,three");

    v.push(c"four").unwrap();
    assert_eq!(v.len(), 4);
    assert_eq!(v.join(c" ").unwrap().as_cstr(), c"one two three four");

    let raw = v.into_raw();
    // SAFETY: we own the array again.
    let v = unsafe { Strv::from_raw(raw) };
    assert_eq!(v.len(), 4);
}

// The raw bindings, on purpose: this is what a program does for something the wrapper crate lacks.
fn test_id128() {
    let mut id = sys::sd_id128_t::default();
    // SAFETY: plain call with a value.
    assert_ne!(unsafe { sys::sd_id128_is_null(id) }, 0);

    // SAFETY: id is a valid out-pointer.
    check(unsafe { sys::sd_id128_randomize(&mut id) }).unwrap();
    // SAFETY: plain call with a value.
    assert_eq!(unsafe { sys::sd_id128_is_null(id) }, 0);

    let mut buf: [c_char; sys::SD_ID128_STRING_MAX as usize] = [0; sys::SD_ID128_STRING_MAX as usize];
    // SAFETY: the buffer has SD_ID128_STRING_MAX bytes, as sd_id128_to_string() requires.
    let s = unsafe { CStr::from_ptr(sys::sd_id128_to_string(id, buf.as_mut_ptr())) };
    assert_eq!(s.to_bytes().len(), 32);
    log_info!("sd_id128_randomize(): {}", display(s));
}

fn test_json() {
    let v = JsonVariant::new_string(c"hello").unwrap();
    assert_eq!(v.format(0).unwrap().as_cstr(), c"\"hello\"");

    let i = JsonVariant::new_integer(-42).unwrap();
    assert_eq!(i.format(0).unwrap().as_cstr(), c"-42");
    assert_eq!(format_cstr!("{i:?}").as_cstr(), c"JsonVariant(-42)");

    let p = JsonVariant::parse(c"{\"a\": [1, 2]}", 0).unwrap();
    assert_eq!(p.format(0).unwrap().as_cstr(), c"{\"a\":[1,2]}");
    let p2 = p.clone();
    assert_eq!(p.as_ptr(), p2.as_ptr());

    assert_eq!(JsonVariant::parse(c"{", 0).unwrap_err(), Errno::EINVAL);

    let mut flags = sys::SD_JSON_FORMAT_OFF;
    assert_eq!(json::parse_argument(Some(c"short"), &mut flags), Ok(1));
    assert!(json::format_enabled(flags));
    assert_eq!(json::parse_argument(None, &mut flags).unwrap_err(), Errno::EINVAL);
}

fn test_fd() {
    let flags = (sys::O_PATH | sys::O_DIRECTORY | sys::O_CLOEXEC) as c_int;
    let root = fd::reopen(BorrowedFd::XAT_FDROOT, flags).unwrap();
    assert!(root.as_raw() >= 0);
    assert_eq!(fd::get_path(root.as_fd()).unwrap().as_cstr(), c"/");
    let again = fd::reopen(root.as_fd(), flags).unwrap();
    assert_ne!(again.as_raw(), root.as_raw());
    assert_eq!(fd::get_path(again.as_fd()).unwrap().as_cstr(), c"/");
    // What the C helpers assert against is an error.
    assert_eq!(
        fd::reopen(root.as_fd(), (sys::O_RDONLY | sys::O_CREAT) as c_int).unwrap_err(),
        Errno::EINVAL
    );

    // SAFETY: the descriptor comes straight back from into_raw().
    let root = unsafe { OwnedFd::from_result(root.into_raw()) }.unwrap();
    // SAFETY: a negative value is an error and never owned.
    let bad = unsafe { OwnedFd::from_result(errno(sys::EBADF)) };
    assert_eq!(bad.unwrap_err(), Errno::EBADF);
    drop(root);
}

#[repr(align(64))]
struct CacheLine([u8; 64]);

fn test_alloc() {
    // malloc() for anything it aligns, grown with realloc().
    let mut bytes = Vec::new();
    for i in 0..10_000u32 {
        bytes.push(i.to_le_bytes()[0]).unwrap();
    }
    assert_eq!(bytes.len(), 10_000);
    assert!(bytes.capacity() >= 10_000);
    assert!(bytes
        .iter()
        .zip(0..10_000u32)
        .all(|(&b, i)| b == i.to_le_bytes()[0]));

    // posix_memalign() for the rest, and its realloc() fallback.
    let mut lines: Vec<CacheLine> = Vec::new();
    for i in 0..100u8 {
        lines.push(CacheLine([i; 64])).unwrap();
        assert_eq!(lines.as_ptr().addr() % align_of::<CacheLine>(), 0);
    }
    assert!(lines
        .iter()
        .enumerate()
        .all(|(i, l)| l.0 == [u8::try_from(i).unwrap(); 64]));

    // An alignment beyond the size, which malloc() does not guarantee either.
    #[repr(align(16))]
    struct Small(u8);
    let b = Box::new(Small(7)).unwrap();
    assert_eq!(ptr::from_ref(&*b).addr() % align_of::<Small>(), 0);
    assert_eq!(Box::into_inner(b).0, 7);

    // Zero-sized types need no memory.
    let mut units = Vec::new();
    for _ in 0..1000 {
        units.push(()).unwrap();
    }
    assert_eq!(units.len(), 1000);
    drop(Box::new(()).unwrap());

    let mut v = Vec::from_elem(1u32, 3).unwrap();
    v.extend_from_slice(&[2, 3]).unwrap();
    assert_eq!(v, [1, 1, 1, 2, 3]);
    assert_eq!(v.pop(), Some(3));
    v.truncate(1);
    assert_eq!(v, [1]);
    v.clear();
    assert!(v.is_empty());
    assert_eq!(v.pop(), None);
    assert_eq!(Vec::<u32>::with_capacity(5).unwrap().capacity(), 5);

    // A size the address space cannot hold and one malloc() refuses are errors, not aborts. black_box() keeps
    // the optimizer from eliding the failed allocation.
    assert_eq!(
        Vec::<u8>::with_capacity(core::hint::black_box(usize::MAX)).unwrap_err(),
        AllocError
    );
    // ASan aborts instead of failing the allocation.
    #[cfg(not(HAS_FEATURE_ADDRESS_SANITIZER))]
    assert_eq!(
        Vec::<u8>::with_capacity(core::hint::black_box(usize::MAX / 2)).unwrap_err(),
        AllocError
    );
}

fn test_print() {
    println!("Hello from Rust, dynamically linked against libsystemd-shared.");
    print!("{} + {} = ", 1, 2);
    println!("{}", 1 + 2);
}

static TIMER_FIRED: AtomicU32 = AtomicU32::new(0);
static TIMER_DROPPED: AtomicBool = AtomicBool::new(false);

/// Records that the closure owning it was dropped.
struct DropFlag(&'static AtomicBool);

impl DropFlag {
    fn is_set(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

fn test_event_timer() {
    let e = Event::new().unwrap();
    let flag = DropFlag(&TIMER_DROPPED);
    let source = e
        .add_time_relative(
            sys::CLOCK_MONOTONIC as sys::clockid_t,
            1000,
            0,
            move |source, _usec| {
                // A method call moves the whole guard into the closure, not just its field
                assert!(!flag.is_set());
                TIMER_FIRED.fetch_add(1, Ordering::Relaxed);
                source.event().ok_or(Errno::EINVAL)?.exit(7)
            },
        )
        .unwrap();
    assert_eq!(e.run_loop().unwrap(), 7);
    assert_eq!(TIMER_FIRED.load(Ordering::Relaxed), 1);

    // The closure lives until the source is freed.
    assert!(!TIMER_DROPPED.load(Ordering::Relaxed));
    drop(source);
    drop(e);
    assert!(TIMER_DROPPED.load(Ordering::Relaxed));
}

fn test_event_handler_error() {
    let e = Event::new().unwrap();
    let source = e
        .add_time_relative(sys::CLOCK_MONOTONIC as sys::clockid_t, 0, 0, |_source, _usec| {
            Err(Errno::EIO)
        })
        .unwrap();
    source.set_exit_on_failure(true).unwrap();
    assert_eq!(e.run_loop(), Err(Errno::EIO));
}

static DEFAULT_FIRED: AtomicBool = AtomicBool::new(false);

fn test_event_default() {
    let event = Event::try_default().unwrap();
    let event2 = event.clone();
    assert_eq!(event.as_ptr(), event2.as_ptr());

    let _source = event
        .add_time_relative(
            sys::CLOCK_MONOTONIC as sys::clockid_t,
            10_000,
            0,
            |source, usec| {
                DEFAULT_FIRED.store(true, Ordering::Relaxed);
                log_debug!("Timer fired at {usec} µs, leaving the event loop.");
                source.event().ok_or(Errno::EINVAL)?.exit(0)
            },
        )
        .unwrap();
    assert_eq!(event.run_loop().unwrap(), 0);
    assert!(DEFAULT_FIRED.load(Ordering::Relaxed));
}

fn test_constants() {
    assert_eq!(sys::UID_INVALID, sys::uid_t::MAX);
    assert_eq!(sys::USEC_INFINITY, u64::MAX);
    assert_eq!(sys::USEC_PER_SEC, 1_000_000);
    assert_eq!(sys::AT_FDCWD, -100);
    assert_eq!(sys::PROC_SUPER_MAGIC, 0x9fa0);
}

define_test_main!(
    LOG_DEBUG,
    [
        test_errno_check,
        test_errno_sign,
        test_errno_conversions,
        test_errno_names,
        test_errno_last_os_error,
        test_log_errno_macros,
        test_log_messages,
        test_cstr,
        test_strv,
        test_id128,
        test_json,
        test_fd,
        test_alloc,
        test_print,
        test_event_timer,
        test_event_handler_error,
        test_event_default,
        test_constants,
    ]
);
