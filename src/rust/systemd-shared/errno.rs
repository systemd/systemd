// SPDX-License-Identifier: LGPL-2.1-or-later

//! The negative-errno return convention.

use core::ffi::{c_char, c_int, CStr};
use core::fmt;
use core::num::NonZero;

use crate::sys;

/// A positive errno value.
///
/// C code in systemd returns `-errno` on failure and [`check`] turns that into `Err(Errno)`. The value is
/// never zero, so `Result<(), Errno>` is one machine word.
///
/// ```
/// use systemd_shared::{check, Errno};
///
/// assert_eq!(check(-2), Err(Errno::ENOENT));
/// assert_eq!(Errno::ENOENT.negative(), -2);
/// assert_eq!(Errno::ENOENT.name(), Some(c"ENOENT"));
/// assert_eq!(Errno::ENOENT.to_string(), "No such file or directory");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Errno(NonZero<c_int>);

const EINVAL_NZ: NonZero<c_int> = match NonZero::new(sys::EINVAL as c_int) {
    Some(n) => n,
    None => panic!("EINVAL is zero"),
};

macro_rules! declare_errno {
    ($($name:ident),* $(,)?) => {
        impl Errno {
            $(
                #[doc = concat!("`", stringify!($name), "`.")]
                pub const $name: Errno = Errno::from_code(sys::$name as c_int);
            )*
        }
    };
}

declare_errno!(
    E2BIG,
    EACCES,
    EADDRINUSE,
    EADDRNOTAVAIL,
    EADV,
    EAFNOSUPPORT,
    EAGAIN,
    EALREADY,
    EBADE,
    EBADF,
    EBADFD,
    EBADMSG,
    EBADR,
    EBADRQC,
    EBADSLT,
    EBFONT,
    EBUSY,
    ECANCELED,
    ECHILD,
    ECHRNG,
    ECOMM,
    ECONNABORTED,
    ECONNREFUSED,
    ECONNRESET,
    EDEADLK,
    EDEADLOCK,
    EDESTADDRREQ,
    EDOM,
    EDOTDOT,
    EDQUOT,
    EEXIST,
    EFAULT,
    EFBIG,
    EFSBADCRC,
    EFSCORRUPTED,
    EHOSTDOWN,
    EHOSTUNREACH,
    EHWPOISON,
    EIDRM,
    EILSEQ,
    EINPROGRESS,
    EINTR,
    EINVAL,
    EIO,
    EISCONN,
    EISDIR,
    EISNAM,
    EKEYEXPIRED,
    EKEYREJECTED,
    EKEYREVOKED,
    EL2HLT,
    EL2NSYNC,
    EL3HLT,
    EL3RST,
    ELIBACC,
    ELIBBAD,
    ELIBEXEC,
    ELIBMAX,
    ELIBSCN,
    ELNRNG,
    ELOOP,
    EMEDIUMTYPE,
    EMFILE,
    EMLINK,
    EMSGSIZE,
    EMULTIHOP,
    ENAMETOOLONG,
    ENAVAIL,
    ENETDOWN,
    ENETRESET,
    ENETUNREACH,
    ENFILE,
    ENOANO,
    ENOBUFS,
    ENOCSI,
    ENODATA,
    ENODEV,
    ENOENT,
    ENOEXEC,
    ENOKEY,
    ENOLCK,
    ENOLINK,
    ENOMEDIUM,
    ENOMEM,
    ENOMSG,
    ENONET,
    ENOPKG,
    ENOPROTOOPT,
    ENOSPC,
    ENOSR,
    ENOSTR,
    ENOSYS,
    ENOTBLK,
    ENOTCONN,
    ENOTDIR,
    ENOTEMPTY,
    ENOTNAM,
    ENOTRECOVERABLE,
    ENOTSOCK,
    ENOTSUP,
    ENOTTY,
    ENOTUNIQ,
    ENXIO,
    EOPNOTSUPP,
    EOVERFLOW,
    EOWNERDEAD,
    EPERM,
    EPFNOSUPPORT,
    EPIPE,
    EPROTO,
    EPROTONOSUPPORT,
    EPROTOTYPE,
    ERANGE,
    EREMCHG,
    EREMOTE,
    EREMOTEIO,
    ERESTART,
    ERFKILL,
    EROFS,
    ESHUTDOWN,
    ESOCKTNOSUPPORT,
    ESPIPE,
    ESRCH,
    ESRMNT,
    ESTALE,
    ESTRPIPE,
    ETIME,
    ETIMEDOUT,
    ETOOMANYREFS,
    ETXTBSY,
    EUCLEAN,
    EUNATCH,
    EUSERS,
    EWOULDBLOCK,
    EXDEV,
    EXFULL,
);

impl Errno {
    /// Constructs from either sign convention.
    ///
    /// Zero is not an error, and `c_int::MIN` has no positive counterpart: the C helpers assert on both in
    /// developer mode, here they are a `debug_assert!` and map to `EINVAL` otherwise.
    pub const fn from_code(code: c_int) -> Errno {
        debug_assert!(code != 0 && code != c_int::MIN, "not an errno value");
        match NonZero::new(code.wrapping_abs()) {
            Some(n) if code != c_int::MIN => Errno(n),
            _ => Errno(EINVAL_NZ),
        }
    }

    /// The positive errno value.
    pub const fn code(self) -> c_int {
        self.0.get()
    }

    /// The value as C code returns it.
    pub const fn negative(self) -> c_int {
        -self.0.get()
    }

    /// The symbolic name, `errno_name_no_fallback()`; `None` for values the tree does not know.
    pub fn name(self) -> Option<&'static CStr> {
        // SAFETY: errno_name_no_fallback() returns a static string or NULL.
        let p = unsafe { sys::errno_name_no_fallback(self.0.get()) };
        if p.is_null() {
            return None;
        }
        // SAFETY: p is a static NUL-terminated string.
        Some(unsafe { CStr::from_ptr(p) })
    }

    /// The calling thread's current `errno`, like `negative_errno()` in C.
    pub fn last_os_error() -> Errno {
        Errno::from(std::io::Error::last_os_error())
    }
}

impl From<c_int> for Errno {
    fn from(code: c_int) -> Errno {
        Errno::from_code(code)
    }
}

impl From<std::io::Error> for Errno {
    fn from(e: std::io::Error) -> Errno {
        e.raw_os_error().map_or(Errno::EIO, Errno::from_code)
    }
}

impl From<Errno> for std::io::Error {
    fn from(e: Errno) -> std::io::Error {
        std::io::Error::from_raw_os_error(e.code())
    }
}

impl From<core::num::TryFromIntError> for Errno {
    fn from(_: core::num::TryFromIntError) -> Errno {
        Errno::ERANGE
    }
}

impl From<core::str::Utf8Error> for Errno {
    fn from(_: core::str::Utf8Error) -> Errno {
        Errno::EINVAL
    }
}

impl From<std::ffi::NulError> for Errno {
    fn from(_: std::ffi::NulError) -> Errno {
        Errno::EINVAL
    }
}

impl From<core::convert::Infallible> for Errno {
    fn from(e: core::convert::Infallible) -> Errno {
        match e {}
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf: [c_char; 128] = [0; 128];
        // SAFETY: GNU strerror_r() returns either buf or a static string, both NUL-terminated, and never
        // writes past the length it is given.
        let s = unsafe { CStr::from_ptr(sys::strerror_r(self.0.get(), buf.as_mut_ptr(), buf.len())) };
        write!(f, "{}", s.to_string_lossy())
    }
}

impl fmt::Debug for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "Errno({})", name.to_string_lossy()),
            None => write!(f, "Errno({})", self.0),
        }
    }
}

impl std::error::Error for Errno {}

/// The result type of everything that talks to libsystemd-shared.
pub type Result<T = (), E = Errno> = core::result::Result<T, E>;

/// Maps a systemd-style return value (negative errno on failure) to a [`Result`].
pub fn check(r: c_int) -> Result<c_int> {
    if r < 0 {
        Err(Errno::from_code(r))
    } else {
        Ok(r)
    }
}

/// Runs a closure and maps its [`Result`] to the `int` an `extern "C"` callback hands back to C: the value
/// on success, `-errno` on failure.
///
/// ```
/// use core::ffi::c_int;
/// use systemd_shared::{from_result, Errno};
///
/// assert_eq!(from_result(|| Ok(3)), 3);
/// assert_eq!(from_result(|| Err(Errno::EBUSY)), -16);
/// ```
pub fn from_result(f: impl FnOnce() -> Result<c_int>) -> c_int {
    match f() {
        Ok(r) => r,
        Err(e) => e.negative(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_maps_sign() {
        assert_eq!(check(0), Ok(0));
        assert_eq!(check(7), Ok(7));
        assert_eq!(check(-(sys::ENOENT as c_int)), Err(Errno::ENOENT));
    }

    #[test]
    fn errno_is_always_positive() {
        let e = Errno::from_code(-(sys::EINVAL as c_int));
        assert_eq!(e, Errno::EINVAL);
        assert_eq!(e.code(), sys::EINVAL as c_int);
        assert_eq!(e.negative(), -(sys::EINVAL as c_int));
        assert_eq!(Errno::from(sys::EINVAL as c_int), e);
        assert_eq!(std::io::Error::from(e).raw_os_error(), Some(sys::EINVAL as c_int));
        assert_eq!(Errno::from(std::io::Error::from(Errno::EBADF)), Errno::EBADF);
        assert_eq!(core::mem::size_of::<Result<()>>(), core::mem::size_of::<c_int>());
    }

    #[test]
    fn conversions() {
        assert_eq!(Errno::from(u8::try_from(300).unwrap_err()), Errno::ERANGE);
        let invalid = std::hint::black_box([0xffu8]);
        assert_eq!(
            Errno::from(core::str::from_utf8(&invalid).unwrap_err()),
            Errno::EINVAL
        );
        assert_eq!(
            Errno::from(std::ffi::CString::new("a\0b").unwrap_err()),
            Errno::EINVAL
        );
        assert_eq!(from_result(|| Ok(5)), 5);
        assert_eq!(from_result(|| Err(Errno::EAGAIN)), Errno::EAGAIN.negative());
    }

    #[test]
    fn names_and_messages() {
        assert_eq!(Errno::ENOENT.name(), Some(c"ENOENT"));
        assert_eq!(Errno::from_code(-100_000).name(), None);
        assert_eq!(Errno::ENOENT.to_string(), "No such file or directory");
        assert_eq!(format!("{:?}", Errno::EBADF), "Errno(EBADF)");
        assert_eq!(format!("{:?}", Errno::from_code(100_000)), "Errno(100000)");
    }
}
