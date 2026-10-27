// SPDX-License-Identifier: LGPL-2.1-or-later

//! Tests the systemd_shared crate, and through it libsystemd-shared from a program written in Rust: exported
//! functions, a static inline trampoline, a union passed by value, the errno conventions,
//! the libc constants, file descriptors, logging, the fallible Box and Vec, and the wrappers of keyrings, VOA
//! lookups, X.509 certificates, tables and files that systemd-keyring-setup uses.
//! This is also the end-to-end test for the Rust support in meson.build.

#![no_std]
#![no_main]

use core::alloc::Layout;
use core::ffi::{c_char, c_int, CStr};
use core::mem::{align_of, size_of};
use core::ptr::{self, NonNull};

use systemd_shared::alloc::{Allocator, Erasing, Malloc};
use systemd_shared::chase::{self, CHASE_MKDIR_0755};
use systemd_shared::cstr::{self, display};
use systemd_shared::keyring;
use systemd_shared::path;
use systemd_shared::prelude::*;
use systemd_shared::recurse_dir::{self, RECURSE_DIR_SORT};
use systemd_shared::table::{Table, TABLE_ERSATZ_DASH};
use systemd_shared::tmpfile::{LinkableTmpfile, LINK_TMPFILE_REPLACE};
use systemd_shared::voa::{self, Lookup};
use systemd_shared::{creds, fd, fileio, json, sys};

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
    // SAFETY: plain call into libsystemd-shared.
    let old = unsafe { sys::log_set_max_level(LOG_CRIT) };
    assert_eq!(log_oom!(), Errno::ENOMEM);
    // SAFETY: as above.
    unsafe { sys::log_set_max_level(old) };
}

/// A character repeated, formatted without allocating.
struct Repeat(char, usize);

impl core::fmt::Display for Repeat {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        (0..self.1).try_for_each(|_| f.write_fmt(format_args!("{}", self.0)))
    }
}

/// Formats like an argument whose Display impl calls into C and fails on the way: errno changes.
struct Clobber;

impl core::fmt::Display for Clobber {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // SAFETY: errno belongs to this thread.
        unsafe { *sys::__errno_location() = sys::ENOENT as c_int };
        f.write_str("clobbered")
    }
}

fn test_log_messages() {
    let _: () = log_debug!("hello {}", 42);
    // Must not trip over a message beyond LINE_MAX (truncated like vsnprintf() does) or an embedded NUL
    // (ends the message early).
    log_debug!("{}", Repeat('x', 3 * sys::LINE_MAX as usize));
    log_debug!("a\0b");
    log_debug!("");

    // Logging keeps errno intact like log_internalv() does, also when formatting an argument changes it.
    // SAFETY: errno belongs to this thread.
    unsafe { *sys::__errno_location() = sys::EIO as c_int };
    log_debug!("{}", Clobber);
    assert_eq!(Errno::last_os_error(), Errno::EIO);
}

fn test_cstr() {
    // SAFETY: NULL is explicitly allowed.
    assert!(unsafe { OwnedCStr::from_raw(ptr::null_mut()) }.is_none());

    // SAFETY: strdup() returns a malloc()ed string we own.
    let s = unsafe { OwnedCStr::from_raw(sys::strdup(c"hello".as_ptr())) }.unwrap();
    assert_eq!(s.as_cstr(), c"hello");
    assert_eq!(format_cstr!("{s}").as_cstr(), c"hello");
    assert_eq!(format_cstr!("{s:?}").as_cstr(), c"\"hello\"");

    assert_eq!(OwnedCStr::try_from(c"copy").unwrap().as_cstr(), c"copy");
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

    let mut v = Strv::split(c"one two  three", c" ", sys::EXTRACT_RELAX).unwrap();
    assert_eq!(v.len(), 3);
    assert!(!v.is_empty());
    assert!(v.iter().map(|s| s.to_str().unwrap()).eq(["one", "two", "three"]));

    v.push(c"four").unwrap();
    assert_eq!(v.len(), 4);
}

fn test_path() {
    let j = |parts: &[&CStr]| path::join(parts).unwrap();

    assert_eq!(j(&[c"/root", c"/a/b", c"/c"]).as_cstr(), c"/root/a/b/c");
    assert_eq!(j(&[c"/root", c"a/b", c"c"]).as_cstr(), c"/root/a/b/c");
    assert_eq!(j(&[c"/root", c"/", c"c"]).as_cstr(), c"/root/c");
    assert_eq!(j(&[c"/root", c"/"]).as_cstr(), c"/root/");
    assert_eq!(j(&[c"", c"/a/b", c"/c"]).as_cstr(), c"/a/b/c");
    assert_eq!(j(&[c"", c"a/b", c"c"]).as_cstr(), c"a/b/c");
    assert_eq!(j(&[c"", c"/", c"c"]).as_cstr(), c"/c");
    assert_eq!(j(&[c"", c"/"]).as_cstr(), c"/");
    assert_eq!(j(&[c"", c""]).as_cstr(), c"");
    assert_eq!(j(&[c""]).as_cstr(), c"");
    assert_eq!(j(&[]).as_cstr(), c"");
    assert_eq!(j(&[c"foo"]).as_cstr(), c"foo");
    assert_eq!(j(&[c"foo", c"bar"]).as_cstr(), c"foo/bar");
    assert_eq!(j(&[c"", c"foo", c"", c"bar", c""]).as_cstr(), c"foo/bar");
    assert_eq!(j(&[c"/", c"foo", c"/", c"bar", c"/"]).as_cstr(), c"/foo/bar/");
    assert_eq!(j(&[c"foo", c"bar", c"baz"]).as_cstr(), c"foo/bar/baz");
    assert_eq!(j(&[c"foo/", c"bar", c"/baz"]).as_cstr(), c"foo/bar/baz");
    assert_eq!(j(&[c"foo/", c"/bar/", c"/baz"]).as_cstr(), c"foo//bar//baz");

    // Owned strings are parts like any other.
    let dir = OwnedCStr::try_from(c"/run/voa").unwrap();
    assert_eq!(j(&[&dir, c"debian"]).as_cstr(), c"/run/voa/debian");
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
    let flags = json::parse_argument(Some(c"short")).unwrap();
    assert!(flags.is_some_and(json::format_enabled));
    assert_eq!(json::parse_argument(None).unwrap_err(), Errno::EINVAL);
}

fn test_fd() {
    let flags = (sys::O_PATH | sys::O_DIRECTORY | sys::O_CLOEXEC) as c_int;
    let root = fd::reopen(BorrowedFd::XAT_FDROOT, flags).unwrap();
    assert!(root.as_raw() >= 0);
    let again = fd::reopen(root.as_fd(), flags).unwrap();
    assert_ne!(again.as_raw(), root.as_raw());
    // What the C helpers assert against is an error.
    assert_eq!(
        fd::reopen(root.as_fd(), (sys::O_RDONLY | sys::O_CREAT) as c_int).unwrap_err(),
        Errno::EINVAL
    );

    // SAFETY: a negative value is an error and never owned.
    let bad = unsafe { OwnedFd::from_return(errno(sys::EBADF)) };
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

    // A boxed slice gives the spare capacity back, an empty or zero-sized one has no memory.
    let mut v: Vec<u32> = Vec::with_capacity(8).unwrap();
    v.extend_from_slice(&[1, 2, 3]).unwrap();
    v.shrink_to_fit().unwrap();
    assert_eq!(v.capacity(), 3);
    let b: Box<[u32]> = v.into_boxed_slice().unwrap();
    assert_eq!(*b, [1, 2, 3]);
    drop(b);
    assert!(Vec::<u8>::with_capacity(4)
        .unwrap()
        .into_boxed_slice()
        .unwrap()
        .is_empty());
    assert_eq!(units.into_boxed_slice().unwrap().len(), 1000);

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

    // The allocator itself takes zero-sized layouts, zeroes, grows and shrinks, as std's does.
    let zero = Layout::new::<()>();
    let p = Malloc.allocate(zero).unwrap();
    assert_eq!(p.len(), 0);
    // SAFETY: the block came from allocate() for the layout.
    unsafe { Malloc.deallocate(p.cast(), zero) };
    let eight = Layout::new::<[u8; 8]>();
    let p = Malloc.allocate_zeroed(eight).unwrap();
    assert_eq!(p.len(), 8);
    // SAFETY: the block is valid for reads of its length.
    assert!(unsafe { p.as_ref() }.iter().all(|&b| b == 0));
    // SAFETY: the block came from allocate_zeroed() for eight bytes and the new layout is larger.
    let p = unsafe { Malloc.grow(p.cast(), eight, Layout::new::<[u8; 16]>()) }.unwrap();
    assert_eq!(p.len(), 16);
    // SAFETY: the block holds 16 bytes now and the new layout is smaller.
    let p = unsafe { Malloc.shrink(p.cast(), Layout::new::<[u8; 16]>(), Layout::new::<[u8; 4]>()) }.unwrap();
    assert_eq!(p.len(), 4);
    // SAFETY: the block holds four bytes now and goes back once.
    unsafe { Malloc.deallocate(p.cast(), Layout::new::<[u8; 4]>()) };
}

fn test_alloc_erasing() {
    // Growing allocates anew and erases the old memory, the contents move along
    let mut secret = Vec::new_in(Erasing);
    for i in 0..1000u32 {
        secret.push(i.to_le_bytes()[0]).unwrap();
    }
    assert!(secret
        .iter()
        .zip(0..1000u32)
        .all(|(&b, i)| b == i.to_le_bytes()[0]));
    secret.extend_from_slice(b"hunter2").unwrap();
    assert!(secret.ends_with(b"hunter2"));
    let boxed: Box<[u8], Erasing> = secret.into_boxed_slice().unwrap();
    assert!(boxed.ends_with(b"hunter2"));

    // Alignments beyond malloc()'s and zero-sized types work as with Malloc
    let mut lines: Vec<CacheLine, Erasing> = Vec::new_in(Erasing);
    for i in 0..10u8 {
        lines.push(CacheLine([i; 64])).unwrap();
        assert_eq!(lines.as_ptr().addr() % align_of::<CacheLine>(), 0);
    }
    let mut units: Vec<(), Erasing> = Vec::new_in(Erasing);
    units.push(()).unwrap();

    let key = Box::new_in([0x42; 32], Erasing).unwrap();
    assert_eq!(Box::into_inner(key), [0x42; 32]);
}

/// Malloc, but a zero-sized request is a bug: Box and Vec never make one, like std's.
struct NoZeroSized;

// SAFETY: blocks come from Malloc and go back to it, a zero-sized request panics instead.
unsafe impl Allocator for NoZeroSized {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        assert_ne!(layout.size(), 0, "zero-sized allocation");
        Malloc.allocate(layout)
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        assert_ne!(layout.size(), 0, "zero-sized deallocation");
        // SAFETY: the block came from Malloc, as the caller guarantees.
        unsafe { Malloc.deallocate(ptr, layout) };
    }
}

fn test_alloc_zero_sized() {
    drop(Box::new_in((), NoZeroSized).unwrap());
    Box::into_inner(Box::new_in((), NoZeroSized).unwrap());

    let mut units = Vec::new_in(NoZeroSized);
    units.push(()).unwrap();
    drop(units.into_boxed_slice().unwrap());

    // The vector's own block goes back when it shrinks, the empty boxed slice has none.
    let mut v = Vec::with_capacity_in(4, NoZeroSized).unwrap();
    v.push(1u8).unwrap();
    v.clear();
    drop(v.into_boxed_slice().unwrap());
}

fn test_print() {
    println!("Hello from Rust, dynamically linked against libsystemd-shared.");
    print!("{} + {} = ", 1, 2);
    println!("{}", 1 + 2);
}

fn test_constants() {
    assert_eq!(sys::UID_INVALID, sys::uid_t::MAX);
    assert_eq!(sys::USEC_INFINITY, u64::MAX);
    assert_eq!(sys::USEC_PER_SEC, 1_000_000);
    assert_eq!(sys::AT_FDCWD, -100);
    assert_eq!(sys::PROC_SUPER_MAGIC, 0x9fa0);
}

/// A directory below /tmp, removed with its contents on drop. Everything in it is reached through its
/// descriptor.
struct TempDir {
    path: OwnedCStr,
    parent: OwnedFd,
    name: OwnedCStr,
    fd: OwnedFd,
}

impl TempDir {
    fn new() -> TempDir {
        let mut p: *mut c_char = ptr::null_mut();
        let flags = sys::O_CLOEXEC as c_int;
        // SAFETY: p receives a malloc()ed path on success, the descriptor or -errno is ours.
        let fd = unsafe { OwnedFd::from_return(sys::mkdtemp_open(ptr::null(), flags, &mut p)) }.unwrap();
        // SAFETY: the path is ours.
        let path = unsafe { OwnedCStr::from_raw(p) }.unwrap();
        let (parent, name) =
            chase::open_parent_at(BorrowedFd::XAT_FDROOT, BorrowedFd::XAT_FDROOT, &path, 0).unwrap();
        TempDir {
            path,
            parent,
            name,
            fd,
        }
    }

    fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    fn write(&self, rel: &CStr, contents: &CStr) {
        let flags = sys::WRITE_STRING_FILE_CREATE
            | sys::WRITE_STRING_FILE_TRUNCATE
            | sys::WRITE_STRING_FILE_MKDIR_0755;
        // SAFETY: both are C strings.
        check(unsafe {
            sys::write_string_file_at(self.fd.as_raw(), rel.as_ptr(), contents.as_ptr(), flags)
        })
        .unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // SAFETY: the name is a C string.
        unsafe {
            sys::rm_rf_at(
                self.parent.as_raw(),
                self.name.as_ptr(),
                sys::REMOVE_ROOT | sys::REMOVE_PHYSICAL,
            )
        };
    }
}

fn test_voa() {
    assert!(voa::identifier_is_valid(c"fedora", false));
    assert!(!voa::identifier_is_valid(c"Fedora", false));
    assert!(!voa::identifier_is_valid(c"a:b", false));
    assert!(voa::identifier_is_valid(c"a:b", true));
    assert!(voa::os_is_valid(c"fedora:43:workstation"));
    assert!(!voa::os_is_valid(c"arch:"));

    let root = TempDir::new();
    let root_fd = root.fd();

    // No os-release at all yields the documented default
    let (os, bare) = voa::os_identifiers(root_fd).unwrap();
    assert!(!bare);
    assert!(os.iter().eq([c"linux"]));

    root.write(c"usr/lib/os-release", c"ID=testos\nVERSION_ID=1\nIMAGE_ID=img");
    let (os, bare) = voa::os_identifiers(root_fd).unwrap();
    assert!(!bare);
    assert!(os.iter().eq([c"testos:1::img", c"testos"]));

    root.write(c"etc/voa/testos/image/default/x509/a-certificate.pem", c"a");
    root.write(c"usr/share/voa/testos/image/default/x509/b-certificate.pem", c"b");
    root.write(
        c"usr/share/voa/testos/trust-anchor-image/default/x509/c-certificate.pem",
        c"c",
    );

    let mut lookup = Lookup {
        os: &os,
        role: c"image",
        context: c"default",
        mode: voa::VOA_MODE_ARTIFACT_VERIFIER,
        technology: voa::VOA_TECHNOLOGY_X509,
        suffix: voa::VOA_X509_CERTIFICATE_SUFFIX,
    };
    let files = voa::list_verifiers(root_fd, &lookup, 0).unwrap();
    let names = [b"/a-certificate.pem".as_slice(), b"/b-certificate.pem".as_slice()];
    assert!(files
        .iter()
        .map(|f| f.original_path().to_bytes())
        .zip(names)
        .all(|(p, n)| p.ends_with(n)));
    assert_eq!(files.iter().count(), 2);
    for f in files.iter() {
        let contents = fileio::read_full_file_full(
            f.fd().unwrap(),
            None,
            u64::MAX,
            4096,
            fileio::READ_FULL_FILE_FAIL_WHEN_LARGER,
        )
        .unwrap();
        assert_eq!(contents.len(), 2);
    }

    lookup.mode = voa::VOA_MODE_TRUST_ANCHOR;
    let files = voa::list_verifiers(root_fd, &lookup, 0).unwrap();
    assert_eq!(files.iter().count(), 1);
    assert!(files
        .iter()
        .all(|f| f.original_path().to_bytes().ends_with(b"/c-certificate.pem")));

    lookup.context = c"other";
    assert_eq!(
        voa::list_verifiers(root_fd, &lookup, 0).unwrap().iter().count(),
        0
    );
}

#[cfg(HAVE_OPENSSL)]
const TEST_CERTIFICATE: &str = "\
-----BEGIN CERTIFICATE-----
MIIBmTCCAT+gAwIBAgIUZ4uOZJsauyCZT+Y1n4/gzCOZTtEwCgYIKoZIzj0EAwIw
ITEfMB0GA1UEAwwWdGVzdC1rZXlyaW5nLXV0aWwtY2VydDAgFw0yNjA4MzEwNzUx
MTRaGA8yMTI2MDgwNzA3NTExNFowITEfMB0GA1UEAwwWdGVzdC1rZXlyaW5nLXV0
aWwtY2VydDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNc3AuZYdnff2T2SsQLk
KnlchPOXz0jdcdZi69553EmFhlanCE/4TAgCobz9Nx2cXzkMeAKgvQrVUiMVPhY+
9QSjUzBRMB0GA1UdDgQWBBQUL7BjFMmgrpesb8YFEFMwCXmfHjAfBgNVHSMEGDAW
gBQUL7BjFMmgrpesb8YFEFMwCXmfHjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49
BAMCA0gAMEUCIA8Qpr29PVqMLOyyMqx1R1+NcwjbDWWQJsymyQGhhUW0AiEA2wlv
xf2X2CHdKDFOguJGhrj+rG4UJ+IEPmTRbRRAvL0=
-----END CERTIFICATE-----
";

#[cfg(HAVE_OPENSSL)]
const TEST_CERTIFICATE_2: &str = "\
-----BEGIN CERTIFICATE-----
MIIBoDCCAUegAwIBAgIUIaxtB5yuXspbj70dHTXLYpiAXIQwCgYIKoZIzj0EAwIw
JTEjMCEGA1UEAwwadGVzdC1rZXlyaW5nLXV0aWwtc3RyYW5nZXIwIBcNMjYwODMx
MDc1MTE0WhgPMjEyNjA4MDcwNzUxMTRaMCUxIzAhBgNVBAMMGnRlc3Qta2V5cmlu
Zy11dGlsLXN0cmFuZ2VyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgABkdJI8
jo/ql7tzpucCX2Rd7qpj58sRBiLt7xU2mrICIOg5Pd3Bb/mMTQE6DqYj0g2uN2DU
gd6WZzxkMwARaaNTMFEwHQYDVR0OBBYEFOUypKpAR+0EhRQ9VlR9ffURVrcJMB8G
A1UdIwQYMBaAFOUypKpAR+0EhRQ9VlR9ffURVrcJMA8GA1UdEwEB/wQFMAMBAf8w
CgYIKoZIzj0EAwIDRwAwRAIgYE0WHkumPoEm/0k1XaBby4DsaVP9IIq670yLTwIM
PeMCICvGIAjV5sZNAGyE1bRNIO2x8/tU8eimhPHMzjfN1u+h
-----END CERTIFICATE-----
";

#[cfg(HAVE_OPENSSL)]
const TEST_CERTIFICATE_SKID: [u8; 20] = [
    0x14, 0x2f, 0xb0, 0x63, 0x14, 0xc9, 0xa0, 0xae, 0x97, 0xac, 0x6f, 0xc6, 0x05, 0x10, 0x53, 0x30, 0x09,
    0x79, 0x9f, 0x1e,
];

#[cfg(HAVE_OPENSSL)]
fn test_x509() {
    use systemd_shared::libcrypto_note;
    use systemd_shared::log_openssl_errors;
    use systemd_shared::x509::{self, X509};

    // Expands the note macros once, the test loads libcrypto below
    libcrypto_note!(suggested);
    if let Err(e) = x509::dlopen_libcrypto(LOG_DEBUG) {
        log_info!("libcrypto is not available, skipping: {e}");
        return;
    }

    let (x, more) = X509::from_pem(TEST_CERTIFICATE.as_bytes()).unwrap();
    assert!(!more);

    let flags = x.extension_flags();
    assert_ne!(flags & sys::EXFLAG_BCONS, 0);
    assert_ne!(flags & sys::EXFLAG_CA, 0);
    assert_eq!(flags & sys::EXFLAG_INVALID, 0);
    assert_eq!(flags & sys::EXFLAG_KUSAGE, 0);

    assert_eq!(x.subject_key_id().unwrap().data(), TEST_CERTIFICATE_SKID);
    let serial = x.serial_number();
    assert_eq!(serial.data().len(), 20);
    assert_eq!(serial.data()[..3], [0x67, 0x8b, 0x8e]);
    assert_ne!(serial.type_(), sys::V_ASN1_NEG_INTEGER as c_int);

    let der = x.to_der().unwrap();
    assert_eq!(der.len(), 413);
    assert_eq!(der[..4], [0x30, 0x82, 0x01, 0x99]);
    assert!(der
        .windows(TEST_CERTIFICATE_SKID.len())
        .any(|w| w == TEST_CERTIFICATE_SKID));

    // PEM carries the certificate alone, in 64 column lines, and parses back to the same DER
    let pem = x.to_pem().unwrap();
    let pem = pem.to_str().unwrap();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert!(pem.ends_with("\n-----END CERTIFICATE-----\n"));
    assert!(pem.lines().all(|l| l.len() <= 64));
    let (again, more) = X509::from_pem(pem.as_bytes()).unwrap();
    assert!(!more);
    assert_eq!(*again.to_der().unwrap(), *der);

    // A private key in front of the certificate is skipped and not carried over
    let key = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n";
    let with_key = format_cstr!("{key}{TEST_CERTIFICATE}");
    let (y, more) = X509::from_pem(with_key.to_bytes()).unwrap();
    assert!(!more);
    assert_eq!(y.to_pem().unwrap().to_str().unwrap(), pem);

    // The first certificate of a bundle wins, the rest is reported
    let two = format_cstr!("{TEST_CERTIFICATE}{TEST_CERTIFICATE_2}");
    let (first, more) = X509::from_pem(two.to_bytes()).unwrap();
    assert!(more);
    assert_eq!(*first.to_der().unwrap(), *der);

    assert!(X509::from_pem(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").is_err());
    assert_eq!(X509::from_pem(b"").unwrap_err(), Errno::EBADMSG);

    // The failed parse above drained the queue already
    let e = log_openssl_errors!(LOG_DEBUG, "Draining the error queue of {}", "libcrypto");
    assert_eq!(e, Errno::ENOTRECOVERABLE);
}

#[cfg(not(HAVE_OPENSSL))]
fn test_x509() {
    log_info!("OpenSSL support is disabled, skipping.");
}

fn test_keyring() {
    // SAFETY: plain call into libsystemd-shared.
    let pid = unsafe { sys::getpid_cached() };
    let name = cstr::try_format(format_args!("test-rust-shared-{pid}")).unwrap();

    // A keyring on the thread keyring is private and goes away with the thread.
    // SAFETY: the strings are NUL-terminated, a keyring takes no payload.
    let ring = unsafe {
        sys::add_key_shim(
            c"keyring".as_ptr(),
            name.as_ptr(),
            ptr::null(),
            0,
            sys::KEY_SPEC_THREAD_KEYRING,
        )
    };
    if ring < 0 {
        log_info!("Cannot create a keyring, skipping: {}", Errno::last_os_error());
        return;
    }

    let d = keyring::describe_full(ring).unwrap();
    assert_eq!(d.type_.as_cstr(), c"keyring");
    assert_eq!(d.description.as_cstr(), name.as_cstr());
    let perm = keyring::perm(ring).unwrap();
    assert!(perm & sys::KEY_POS_VIEW != 0);
    assert_eq!(keyring::description(ring).unwrap().as_cstr(), name.as_cstr());
    assert!(keyring::list(ring).unwrap().is_empty());
    assert_eq!(
        keyring::resolve(sys::KEY_SPEC_THREAD_KEYRING).map(|r| r > 0),
        Ok(true)
    );

    // Containers may hide /proc/keys or leave it out with ProcSubset=pid, there is none at all below a root
    // without /proc.
    match keyring::find_by_name_at(BorrowedFd::XAT_FDROOT, &name, sys::UID_INVALID) {
        Ok(serial) => {
            assert_eq!(serial, ring);
            assert_eq!(
                keyring::find_by_name_at(
                    BorrowedFd::XAT_FDROOT,
                    c"test-rust-shared-does-not-exist",
                    sys::UID_INVALID
                )
                .unwrap_err(),
                Errno::ENOKEY
            );
        }
        Err(e) => assert!(
            [Errno::ERFKILL, Errno::EACCES, Errno::EPERM, Errno::ENOENT].contains(&e),
            "{e}"
        ),
    }
    let empty = TempDir::new();
    assert_eq!(
        keyring::find_by_name_at(empty.fd(), &name, sys::UID_INVALID).unwrap_err(),
        Errno::ENOENT
    );

    // SAFETY: as above, with a one byte payload.
    let key = unsafe {
        sys::add_key_shim(
            c"user".as_ptr(),
            c"test-key".as_ptr(),
            c"x".as_ptr().cast(),
            1,
            ring,
        )
    };
    assert!(key > 0);
    assert_eq!(keyring::list(ring).unwrap(), [key]);
    keyring::unlink_key(ring, key).unwrap();
    assert!(keyring::list(ring).unwrap().is_empty());
    // The keyring drops its reference to the key after an RCU grace period, until then the key is still
    // there and just not linked.
    assert!(matches!(
        keyring::unlink_key(ring, key),
        Err(Errno::ENOENT | Errno::ENOKEY)
    ));

    assert_eq!(
        keyring::add_asymmetric(ring, None, &[]).unwrap_err(),
        Errno::EINVAL
    );

    // Only asymmetric keys signed by what the keyring holds may be added from now on, once.
    match keyring::restrict(ring, Some(c"asymmetric"), Some(c"key_or_keyring:0:chain")) {
        Err(e @ (Errno::ENOKEY | Errno::ENOENT)) => {
            log_info!("Kernel lacks asymmetric keys, skipping: {e}");
            keyring::unlink_key(sys::KEY_SPEC_THREAD_KEYRING, ring).unwrap();
            return;
        }
        r => r.unwrap(),
    }
    assert_eq!(keyring::restrict(ring, None, None).unwrap_err(), Errno::EEXIST);

    // Without SetAttr the mask is frozen.
    let frozen = perm & !(sys::KEY_POS_SETATTR | sys::KEY_USR_SETATTR);
    keyring::set_perm(ring, frozen).unwrap();
    assert_eq!(keyring::perm(ring).unwrap(), frozen);
    assert_eq!(keyring::set_perm(ring, perm).unwrap_err(), Errno::EACCES);

    keyring::unlink_key(sys::KEY_SPEC_THREAD_KEYRING, ring).unwrap();
}

fn test_table() {
    // The rendering depends on the environment, pin it like test-format-table.c does. The terminal features
    // are cached once looked at, so the caches have to go too.
    for (name, value) in [(c"SYSTEMD_COLORS", c"0"), (c"COLUMNS", c"200")] {
        // SAFETY: the test is single-threaded, nothing reads the environment concurrently.
        check(unsafe { sys::set_unset_env(name.as_ptr(), value.as_ptr(), true) }).unwrap();
    }
    // SAFETY: plain call into libsystemd-shared.
    unsafe { sys::reset_terminal_feature_caches() };

    let mut t = Table::new(&[c"name", c"set", c"count", c"tristate", c"list"]).unwrap();
    t.set_ersatz_string(TABLE_ERSATZ_DASH);

    let mut l = Strv::new();
    l.push(c"a").unwrap();
    l.push(c"b").unwrap();

    t.add_string(c"one").unwrap();
    t.add_boolean_checkmark(true).unwrap();
    t.add_uint64(7).unwrap();
    t.add_tristate(None).unwrap();
    t.add_strv(&l).unwrap();

    t.add_string(c"two").unwrap();
    t.add_boolean_checkmark(false).unwrap();
    t.add_empty().unwrap();
    t.add_tristate(Some(true)).unwrap();
    t.add_strv(&Strv::new()).unwrap();

    // SAFETY: plain calls on a valid table.
    let size = unsafe {
        (
            sys::table_get_rows(t.as_ptr()),
            sys::table_get_columns(t.as_ptr()),
        )
    };
    assert_eq!(size, (3, 5));

    let mut s: *mut c_char = ptr::null_mut();
    // SAFETY: s receives a malloc()ed string on success.
    check(unsafe { sys::table_format(t.as_ptr(), &mut s) }).unwrap();
    // SAFETY: the string is ours.
    let s = unsafe { OwnedCStr::from_raw(s) }.unwrap();
    log_info!("Table:\n{s}");
    let mut lines = s.to_str().unwrap().lines();
    let [header, one, b, two] = [(); 4].map(|()| lines.next().unwrap());
    assert!(lines.next().is_none());
    assert!(header.starts_with("NAME"));
    assert!(one.starts_with("one"));
    assert!(one.contains('7'));
    assert!(b.trim_start().starts_with('b'));
    assert!(two.starts_with("two"));

    assert_eq!(Table::new(&[]).unwrap_err(), Errno::EINVAL);
}

fn test_files() {
    let dir = TempDir::new();

    let (parent, base) = chase::open_parent_at(dir.fd(), dir.fd(), c"a/b/c", CHASE_MKDIR_0755).unwrap();
    assert_eq!(base.as_cstr(), c"c");
    let f_ok = sys::F_OK as c_int;
    chase::accessat(dir.fd(), dir.fd(), c"a/b", 0, f_ok).unwrap();
    assert_eq!(
        chase::accessat(dir.fd(), dir.fd(), c"a/b/c", 0, f_ok).unwrap_err(),
        Errno::ENOENT
    );
    // Absolute paths stay below the root.
    chase::accessat(dir.fd(), parent.as_fd(), c"/a/b", 0, f_ok).unwrap();
    // What the C helpers assert against is an error.
    assert_eq!(
        chase::accessat(dir.fd(), dir.fd(), c"a", sys::CHASE_NONEXISTENT, f_ok).unwrap_err(),
        Errno::EINVAL
    );
    let autofs = sys::CHASE_NO_AUTOFS | sys::CHASE_TRIGGER_AUTOFS;
    assert_eq!(
        chase::accessat(dir.fd(), dir.fd(), c"a", autofs, f_ok).unwrap_err(),
        Errno::EINVAL
    );
    // A plain open() triggers automounts by itself, only O_PATH|O_CREAT with the flag asserts in C.
    let o_dir = (sys::O_RDONLY | sys::O_DIRECTORY | sys::O_CLOEXEC) as c_int;
    chase::openat(dir.fd(), dir.fd(), c"a/b", sys::CHASE_TRIGGER_AUTOFS, o_dir).unwrap();
    let o_path = (sys::O_PATH | sys::O_DIRECTORY | sys::O_CLOEXEC) as c_int;
    chase::openat(dir.fd(), dir.fd(), c"a/b", sys::CHASE_TRIGGER_AUTOFS, o_path).unwrap();
    let o_creat = o_path | sys::O_CREAT as c_int;
    assert_eq!(
        chase::openat(dir.fd(), dir.fd(), c"a/b", sys::CHASE_TRIGGER_AUTOFS, o_creat).unwrap_err(),
        Errno::EINVAL
    );
    // O_CREAT on the parent reopened for CHASE_PARENT is EISDIR.
    let o_create = (sys::O_RDONLY | sys::O_CREAT | sys::O_CLOEXEC) as c_int;
    assert_eq!(
        chase::openat(dir.fd(), dir.fd(), c"a/b/c", sys::CHASE_PARENT, o_create).unwrap_err(),
        Errno::EISDIR
    );

    // Linked into place it replaces the target.
    dir.write(c"a/b/c", c"old");
    let tmp =
        LinkableTmpfile::open_at(parent.as_fd(), &base, (sys::O_WRONLY | sys::O_CLOEXEC) as c_int).unwrap();
    fd::loop_write(tmp.fd(), b"new contents\n").unwrap();
    fd::fchmod(tmp.fd(), 0o600).unwrap();
    tmp.link(&base, LINK_TMPFILE_REPLACE).unwrap();
    let contents = fileio::read_full_file_full(
        parent.as_fd(),
        Some(&base),
        u64::MAX,
        4096,
        fileio::READ_FULL_FILE_VERIFY_REGULAR | fileio::READ_FULL_FILE_FAIL_WHEN_LARGER,
    )
    .unwrap();
    assert_eq!(&*contents, b"new contents\n");
    assert_eq!(
        format_cstr!("{contents:?}").as_cstr(),
        c"Contents { size: 13, .. }"
    );

    // Dropped before, nothing is left behind. Where O_TMPFILE works there is no name to remove, the unlink
    // of the named fallback is not exercised.
    let tmp =
        LinkableTmpfile::open_at(parent.as_fd(), c"d", (sys::O_WRONLY | sys::O_CLOEXEC) as c_int).unwrap();
    assert_eq!(
        LinkableTmpfile::open_at(parent.as_fd(), c"e/f", sys::O_WRONLY as c_int).unwrap_err(),
        Errno::EINVAL
    );
    assert_eq!(
        LinkableTmpfile::open_at(BorrowedFd::XAT_FDROOT, c"e", sys::O_WRONLY as c_int).unwrap_err(),
        Errno::EBADF
    );
    assert_eq!(
        LinkableTmpfile::open_at(parent.as_fd(), c"e", (sys::O_WRONLY | sys::O_EXCL) as c_int).unwrap_err(),
        Errno::EINVAL
    );
    fd::loop_write(tmp.fd(), b"never seen").unwrap();
    drop(tmp);
    // A placeholder is no open descriptor.
    assert_eq!(
        fd::loop_write(BorrowedFd::XAT_FDROOT, b"x").unwrap_err(),
        Errno::EBADF
    );
    // The parent is an O_PATH descriptor, listing needs a readable one.
    let flags = (sys::O_RDONLY | sys::O_DIRECTORY | sys::O_CLOEXEC) as c_int;
    let listable = chase::openat(dir.fd(), dir.fd(), c"a/b", 0, flags).unwrap();
    let de = recurse_dir::readdir_all(listable.as_fd(), RECURSE_DIR_SORT).unwrap();
    assert!(de.names().eq([c"c"]));
    assert_eq!(
        recurse_dir::readdir_all(BorrowedFd::XAT_FDROOT, 0).unwrap_err(),
        Errno::EBADF
    );

    // Larger than allowed is an error, and so are a limit that cannot be exceeded and one that would truncate.
    assert_eq!(
        fileio::read_full_file_full(
            parent.as_fd(),
            Some(&base),
            u64::MAX,
            4,
            fileio::READ_FULL_FILE_FAIL_WHEN_LARGER
        )
        .unwrap_err(),
        Errno::E2BIG
    );
    assert_eq!(
        fileio::read_full_file_full(
            parent.as_fd(),
            Some(&base),
            u64::MAX,
            usize::MAX,
            fileio::READ_FULL_FILE_FAIL_WHEN_LARGER
        )
        .unwrap_err(),
        Errno::EINVAL
    );
    assert_eq!(
        fileio::read_full_file_full(parent.as_fd(), Some(&base), u64::MAX, 4096, 0).unwrap_err(),
        Errno::EINVAL
    );
    assert_eq!(
        fileio::read_full_file_full(
            parent.as_fd(),
            Some(&base),
            u64::MAX,
            4096,
            sys::READ_FULL_FILE_UNBASE64 | sys::READ_FULL_FILE_UNHEX
        )
        .unwrap_err(),
        Errno::EINVAL
    );

    dir.write(c"bool", c"yes");
    assert_eq!(fileio::read_boolean_file_at(dir.fd(), c"bool"), Ok(true));
    dir.write(c"bool", c"0");
    assert_eq!(fileio::read_boolean_file_at(dir.fd(), c"bool"), Ok(false));
    assert_eq!(
        fileio::read_boolean_file_at(dir.fd(), c"nope").unwrap_err(),
        Errno::ENOENT
    );
    // Only a single component, everything else goes through chase.
    assert_eq!(
        fileio::read_boolean_file_at(dir.fd(), c"a/b/c").unwrap_err(),
        Errno::EINVAL
    );

    log_debug!("Worked in '{}'.", dir.path);
}

fn set_credentials_directory(path: Option<&CStr>) {
    // SAFETY: the test is single-threaded, nothing reads the environment concurrently.
    check(unsafe {
        sys::set_unset_env(
            c"CREDENTIALS_DIRECTORY".as_ptr(),
            path.map_or(ptr::null(), CStr::as_ptr),
            true,
        )
    })
    .unwrap();
}

fn test_creds() {
    set_credentials_directory(None);
    assert_eq!(
        creds::open_credentials_dir_at(BorrowedFd::XAT_FDROOT).unwrap_err(),
        Errno::ENXIO
    );

    // Any directory does as the credentials directory.
    let dir = TempDir::new();
    dir.write(c"keyring-setup.os", c"fedora:43 fedora");
    let c = creds::read_credential_at(dir.fd(), c"keyring-setup.os").unwrap();
    assert_eq!(&*c, b"fedora:43 fedora\n");
    let c = creds::read_credential_string_at(dir.fd(), c"keyring-setup.os").unwrap();
    assert_eq!(c.as_cstr(), c"fedora:43 fedora\n");

    // A NUL byte is fine for binary contents, but not in a string.
    let tmp =
        LinkableTmpfile::open_at(dir.fd(), c"binary", (sys::O_WRONLY | sys::O_CLOEXEC) as c_int).unwrap();
    fd::loop_write(tmp.fd(), b"a\0b").unwrap();
    tmp.link(c"binary", LINK_TMPFILE_REPLACE).unwrap();
    assert_eq!(&*creds::read_credential_at(dir.fd(), c"binary").unwrap(), b"a\0b");
    assert_eq!(
        creds::read_credential_string_at(dir.fd(), c"binary").unwrap_err(),
        Errno::EBADMSG
    );

    // $CREDENTIALS_DIRECTORY names it, resolved below the root.
    set_credentials_directory(Some(&dir.path));
    let opened = creds::open_credentials_dir_at(BorrowedFd::XAT_FDROOT);
    set_credentials_directory(None);
    assert_eq!(
        &*creds::read_credential_at(opened.unwrap().as_fd(), c"keyring-setup.os").unwrap(),
        b"fedora:43 fedora\n"
    );
    assert_eq!(
        creds::read_credential_at(dir.fd(), c"nope").unwrap_err(),
        Errno::ENOENT
    );
    assert_eq!(
        creds::read_credential_at(dir.fd(), c"a/b").unwrap_err(),
        Errno::EINVAL
    );
    assert_eq!(
        creds::read_credential_at(dir.fd(), c"..").unwrap_err(),
        Errno::EINVAL
    );
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
        test_path,
        test_id128,
        test_json,
        test_fd,
        test_alloc,
        test_alloc_erasing,
        test_alloc_zero_sized,
        test_print,
        test_constants,
        test_voa,
        test_x509,
        test_keyring,
        test_table,
        test_files,
        test_creds,
    ]
);
