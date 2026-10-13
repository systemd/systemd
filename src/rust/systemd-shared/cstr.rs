// SPDX-License-Identifier: LGPL-2.1-or-later

//! Strings that C allocated.

use core::ffi::{c_char, c_void, CStr};
use core::fmt::{self, Write};
use core::ptr::{self, NonNull};

use crate::errno::{Errno, Result};
use crate::sys;

/// A NUL-terminated string that was `malloc()`ed by C and is `free()`d on drop, the `_cleanup_free_ char *`
/// of Rust.
pub struct OwnedCStr(NonNull<c_char>);

impl OwnedCStr {
    /// Takes ownership of a string returned by a C helper, `None` for NULL.
    ///
    /// # Safety
    ///
    /// `p` must be NULL or a `malloc()`ed NUL-terminated string that nothing else frees.
    pub unsafe fn from_raw(p: *mut c_char) -> Option<Self> {
        NonNull::new(p).map(OwnedCStr)
    }

    /// Copies `bytes` into a new string, `memdup_suffix0()`. `-ENOMEM` instead of aborting when memory runs
    /// out, `-EINVAL` for embedded NUL bytes.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<OwnedCStr> {
        if bytes.contains(&0) {
            return Err(Errno::EINVAL);
        }
        // SAFETY: bytes is valid for its length, memdup_suffix0() returns a NUL-terminated copy or NULL.
        let p = unsafe { sys::memdup_suffix0(bytes.as_ptr().cast(), bytes.len()) };
        // SAFETY: the copy is ours.
        unsafe { OwnedCStr::from_raw(p.cast()) }.ok_or(Errno::ENOMEM)
    }

    /// Borrows the string.
    pub fn as_cstr(&self) -> &CStr {
        // SAFETY: invariant of from_raw().
        unsafe { CStr::from_ptr(self.0.as_ptr()) }
    }

    /// Gives the string back to C, `TAKE_PTR()`.
    #[must_use = "the string leaks unless it is freed"]
    pub fn into_raw(self) -> *mut c_char {
        let p = self.0.as_ptr();
        core::mem::forget(self);
        p
    }
}

impl TryFrom<&CStr> for OwnedCStr {
    type Error = Errno;

    /// `strdup()`, `-ENOMEM` instead of aborting when memory runs out.
    fn try_from(s: &CStr) -> Result<OwnedCStr> {
        // SAFETY: s is a C string, strdup() returns a copy or NULL.
        unsafe { OwnedCStr::from_raw(sys::strdup(s.as_ptr())) }.ok_or(Errno::ENOMEM)
    }
}

/// Formats into a new string, `-ENOMEM` instead of aborting when memory runs out, `-EINVAL` if formatting
/// an argument fails or the result has a NUL byte. Like the kernel's `CString::try_from_fmt()`, the output is
/// measured first and then formatted into one allocation of exactly that size, without copying.
pub fn try_format(args: fmt::Arguments<'_>) -> Result<OwnedCStr> {
    /// Counts the bytes formatting produces.
    struct Measure(usize);

    impl Write for Measure {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            self.0 = self.0.checked_add(s.len()).ok_or(fmt::Error)?;
            Ok(())
        }
    }

    /// Writes into a buffer of the measured size, never past it.
    struct Buffer {
        p: NonNull<u8>,
        size: usize,
        len: usize,
    }

    impl Write for Buffer {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let end = self
                .len
                .checked_add(s.len())
                .filter(|&end| end <= self.size)
                .ok_or(fmt::Error)?;
            // SAFETY: the bytes up to end are within the buffer, which s does not overlap.
            unsafe { ptr::copy_nonoverlapping(s.as_ptr(), self.p.as_ptr().add(self.len), s.len()) };
            self.len = end;
            Ok(())
        }
    }

    let mut m = Measure(0);
    m.write_fmt(args).map_err(|_| Errno::EINVAL)?;
    let size = m.0.checked_add(1).ok_or(Errno::ENOMEM)?;

    // SAFETY: plain call into libc.
    let p = NonNull::new(unsafe { sys::malloc(size) }.cast::<u8>()).ok_or(Errno::ENOMEM)?;
    let mut b = Buffer {
        p,
        size: size - 1,
        len: 0,
    };
    let r = b.write_fmt(args);
    // SAFETY: the first b.len bytes were written above.
    if r.is_err() || unsafe { core::slice::from_raw_parts(p.as_ptr(), b.len) }.contains(&0) {
        // SAFETY: allocated above and not handed out.
        unsafe { sys::free(p.as_ptr().cast()) };
        return Err(Errno::EINVAL);
    }
    // SAFETY: b.len is below size, the terminator fits.
    unsafe { p.as_ptr().add(b.len).write(0) };
    // SAFETY: a malloc()ed NUL-terminated string that nothing else frees.
    unsafe { OwnedCStr::from_raw(p.as_ptr().cast()) }.ok_or(Errno::ENOMEM)
}

/// `startswith()`: the rest of `s` after `prefix`, a C string as well.
pub fn strip_prefix<'a>(s: &'a CStr, prefix: &[u8]) -> Option<&'a CStr> {
    CStr::from_bytes_with_nul(s.to_bytes_with_nul().strip_prefix(prefix)?).ok()
}

/// Displays a C string, with invalid UTF-8 replaced like `to_string_lossy()` does, but without allocating.
pub fn display(s: &CStr) -> Display<'_> {
    Display(s)
}

/// See [`display()`].
pub struct Display<'a>(&'a CStr);

impl fmt::Display for Display<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(s) = self.0.to_str() {
            return f.pad(s);
        }
        for chunk in self.0.to_bytes().utf8_chunks() {
            f.write_str(chunk.valid())?;
            if !chunk.invalid().is_empty() {
                f.write_str("\u{FFFD}")?;
            }
        }
        Ok(())
    }
}

impl Drop for OwnedCStr {
    fn drop(&mut self) {
        // SAFETY: invariant of from_raw().
        unsafe { sys::free(self.0.as_ptr().cast::<c_void>()) }
    }
}

impl core::ops::Deref for OwnedCStr {
    type Target = CStr;

    fn deref(&self) -> &CStr {
        self.as_cstr()
    }
}

impl AsRef<CStr> for OwnedCStr {
    fn as_ref(&self) -> &CStr {
        self.as_cstr()
    }
}

impl core::borrow::Borrow<CStr> for OwnedCStr {
    fn borrow(&self) -> &CStr {
        self.as_cstr()
    }
}

impl fmt::Display for OwnedCStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&display(self.as_cstr()), f)
    }
}

impl fmt::Debug for OwnedCStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_cstr(), f)
    }
}
