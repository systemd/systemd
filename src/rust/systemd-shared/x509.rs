// SPDX-License-Identifier: LGPL-2.1-or-later

//! X.509 certificates through the libcrypto that `crypto-util.h` loads with `dlopen()`. [`X509::from_pem()`]
//! loads it, as `openssl_load_x509_certificate_from_pem()` does, and so does [`log_openssl_errors!`].

use core::ffi::{c_char, c_int, c_void, CStr};
use core::fmt;
use core::ptr::{self, NonNull};

use crate::cstr::{self, OwnedCStr};
use crate::errno::{check, Errno, Result};
use crate::log::LOG_DEBUG;
use crate::sys;

/// A function libcrypto exports, as `crypto-util.c` resolved it. Reading the pointer is unsafe: they are
/// written once by `dlopen_libcrypto()`, which has succeeded once an [`X509`] exists.
macro_rules! sym {
    ($name:ident) => {
        sys::$name.expect(concat!(stringify!($name), "() used before dlopen_libcrypto()"))
    };
}

/// `dlopen_libcrypto()`.
pub fn dlopen_libcrypto(log_level: c_int) -> Result<()> {
    // SAFETY: plain call into libsystemd-shared.
    check(unsafe { sys::dlopen_libcrypto(log_level) }).map(|_| ())
}

/// An `ASN1_STRING` owned by something else.
pub struct Asn1String<'a> {
    s: &'a sys::ASN1_STRING,
}

impl<'a> Asn1String<'a> {
    /// `ASN1_STRING_type()`.
    pub fn type_(&self) -> c_int {
        // SAFETY: the string is alive for 'a, and came from an X509, so libcrypto is loaded.
        unsafe { sym!(sym_ASN1_STRING_type)(self.s) }
    }

    /// `ASN1_STRING_get0_data()` and `ASN1_STRING_length()`.
    pub fn data(&self) -> &'a [u8] {
        // SAFETY: the string is alive for 'a, and came from an X509, so libcrypto is loaded.
        let (p, n) = unsafe {
            (
                sym!(sym_ASN1_STRING_get0_data)(self.s),
                sym!(sym_ASN1_STRING_length)(self.s),
            )
        };
        match usize::try_from(n) {
            // SAFETY: the data is n bytes long and lives as long as the string.
            Ok(n) if n > 0 && !p.is_null() => unsafe { core::slice::from_raw_parts(p, n) },
            _ => &[],
        }
    }
}

/// An X.509 certificate, freed with `X509_free()`.
#[derive(Debug)]
pub struct X509(NonNull<sys::X509>);

impl X509 {
    /// `openssl_load_x509_certificate_from_pem()`: the first certificate of a PEM document, and whether more
    /// follow.
    pub fn from_pem(pem: &[u8]) -> Result<(X509, bool)> {
        let iov = sys::iovec {
            iov_base: pem.as_ptr().cast_mut().cast(),
            iov_len: pem.len(),
        };
        let mut x: *mut sys::X509 = ptr::null_mut();
        let mut more = false;
        // SAFETY: the iovec points to pem, which is only read, x and more are valid out-pointers.
        check(unsafe { sys::openssl_load_x509_certificate_from_pem(&iov, &mut x, &mut more) })?;
        Ok((X509(NonNull::new(x).ok_or(Errno::EBADMSG)?), more))
    }

    /// The raw pointer, for passing to C.
    pub fn as_ptr(&self) -> *mut sys::X509 {
        self.0.as_ptr()
    }

    /// `X509_get_extension_flags()`, the `EXFLAG_*` bits.
    pub fn extension_flags(&self) -> u32 {
        // SAFETY: we own a live certificate, so libcrypto is loaded.
        unsafe { sym!(sym_X509_get_extension_flags)(self.as_ptr()) }
    }

    /// `X509_get_key_usage()`, the `KU_*` bits.
    pub fn key_usage(&self) -> u32 {
        // SAFETY: we own a live certificate, so libcrypto is loaded.
        unsafe { sym!(sym_X509_get_key_usage)(self.as_ptr()) }
    }

    /// `X509_get_extended_key_usage()`, the `XKU_*` bits.
    pub fn extended_key_usage(&self) -> u32 {
        // SAFETY: we own a live certificate, so libcrypto is loaded.
        unsafe { sym!(sym_X509_get_extended_key_usage)(self.as_ptr()) }
    }

    /// `X509_get0_subject_key_id()`, `None` without a subject key identifier.
    pub fn subject_key_id(&self) -> Option<Asn1String<'_>> {
        // SAFETY: we own a live certificate, so libcrypto is loaded; the identifier is owned by it.
        let p = unsafe { sym!(sym_X509_get0_subject_key_id)(self.as_ptr()) };
        // SAFETY: NULL or a string that lives as long as the certificate.
        unsafe { p.as_ref() }.map(|s| Asn1String { s })
    }

    /// `X509_get0_serialNumber()`.
    pub fn serial_number(&self) -> Asn1String<'_> {
        // SAFETY: we own a live certificate, so libcrypto is loaded; it always has a serial number owned by it.
        let p = unsafe { sym!(sym_X509_get0_serialNumber)(self.as_ptr()) };
        // SAFETY: as above, the string lives as long as the certificate.
        let s = unsafe { p.as_ref() }.expect("certificate without serial number");
        Asn1String { s }
    }

    /// `i2d_X509()`: the DER encoding, `None` with the reason in the OpenSSL error queue.
    pub fn to_der(&self) -> Option<Der> {
        let mut out: *mut u8 = ptr::null_mut();
        // SAFETY: we own a live certificate, so libcrypto is loaded; out receives a buffer it allocates.
        let n = unsafe { sym!(sym_i2d_X509)(self.as_ptr(), &mut out) };
        let der = Der {
            data: NonNull::new(out)?,
            size: usize::try_from(n).unwrap_or(0),
        };
        // Nothing encoded means failure, a buffer handed out regardless is freed with der.
        (der.size > 0).then_some(der)
    }

    /// The certificate alone as a PEM `CERTIFICATE` block. `-EIO` if it cannot be DER encoded, with the reason
    /// in the OpenSSL error queue.
    pub fn to_pem(&self) -> Result<OwnedCStr> {
        let der = self.to_der().ok_or(Errno::EIO)?;
        let mut p: *mut c_char = ptr::null_mut();
        // SAFETY: der holds der.len() bytes, p receives a malloc()ed string on success.
        let r = unsafe { sys::base64mem_full(der.as_ptr().cast(), der.len(), 64, &mut p) };
        if r < 0 {
            return Err(Errno::from_code(c_int::try_from(r)?));
        }
        // SAFETY: the string is ours.
        let base64 = unsafe { OwnedCStr::from_raw(p) }.ok_or(Errno::ENOMEM)?;
        let base64 = base64.as_cstr().to_str()?;

        cstr::try_format(format_args!(
            "-----BEGIN CERTIFICATE-----\n{base64}\n-----END CERTIFICATE-----\n"
        ))
    }
}

/// A DER encoded certificate in a buffer libcrypto allocated, freed with `OPENSSL_free()`.
pub struct Der {
    data: NonNull<u8>,
    size: usize,
}

impl AsRef<[u8]> for Der {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl core::ops::Deref for Der {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // SAFETY: the buffer holds size bytes for as long as we live.
        unsafe { core::slice::from_raw_parts(self.data.as_ptr(), self.size) }
    }
}

impl fmt::Debug for Der {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Der")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl Drop for Der {
    fn drop(&mut self) {
        let mut p = self.data.as_ptr().cast::<c_void>();
        // SAFETY: the buffer came from libcrypto and is ours.
        unsafe { sys::OPENSSL_freep(&mut p) };
    }
}

impl Drop for X509 {
    fn drop(&mut self) {
        let mut p = self.0.as_ptr();
        // SAFETY: we own the certificate.
        unsafe { sys::X509_freep(&mut p) };
    }
}

/// Backend of [`log_openssl_errors!`].
#[doc(hidden)]
pub fn __log_openssl_errors(
    level: c_int,
    file: &CStr,
    line: u32,
    func: &CStr,
    args: fmt::Arguments<'_>,
) -> Errno {
    // The error queue is read through libcrypto, which nothing might have loaded yet.
    if let Err(e) = dlopen_libcrypto(LOG_DEBUG) {
        crate::log::__log(level, e.code(), file, line, func, args);
        return e;
    }

    // Like vasprintf() failing in C.
    let Ok(message) = cstr::try_format(args) else {
        return crate::log_full_errno!(level, Errno::ENOMEM, "Out of memory.");
    };
    // SAFETY: all strings are NUL-terminated, the format consumes exactly the one argument passed.
    let r = unsafe {
        sys::log_openssl_errors_internal(
            level,
            file.as_ptr(),
            line as c_int,
            func.as_ptr(),
            c"%s".as_ptr(),
            message.as_ptr(),
        )
    };
    Errno::from_code(r)
}

/// `log_openssl_errors()`: logs the message followed by the errors in the OpenSSL error queue and evaluates to
/// the [`Errno`] the last of them maps to.
#[macro_export]
macro_rules! log_openssl_errors {
    ($level:expr, $($arg:tt)*) => {
        $crate::x509::__log_openssl_errors(
            $level,
            const { $crate::log::__cstr(::core::concat!(::core::file!(), "\0")) },
            ::core::line!(),
            const { $crate::log::__cstr(::core::concat!(::core::module_path!(), "\0")) },
            ::core::format_args!($($arg)*),
        )
    };
}
