// SPDX-License-Identifier: LGPL-2.1-or-later

//! Kernel keyrings, `keyring-util.h`.

use core::ffi::{c_char, c_void, CStr};
use core::ptr;

use crate::alloc::Vec;

use crate::cstr::OwnedCStr;
use crate::errno::{check, Errno, Result};
use crate::fd::BorrowedFd;
use crate::sys;

/// `key_serial_t`.
pub type KeySerial = sys::key_serial_t;

/// What `KEYCTL_DESCRIBE` reports about a key, `keyring_describe_full()`.
#[derive(Debug)]
pub struct Description {
    /// The key type.
    pub type_: OwnedCStr,
    /// The owner.
    pub uid: sys::uid_t,
    /// The permission mask.
    pub perm: u32,
    /// The type specific description.
    pub description: OwnedCStr,
}

/// `keyring_find_by_name_at()`: the keyring called `name` owned by `owner`, looked up in the `/proc/keys` below
/// `root`. `-ENOKEY` if there is none, `-ENOTUNIQ` if there are several.
pub fn find_by_name_at(root: BorrowedFd<'_>, name: &CStr, owner: sys::uid_t) -> Result<KeySerial> {
    let mut serial: KeySerial = 0;
    // SAFETY: name is a C string, serial a valid out-pointer.
    check(unsafe { sys::keyring_find_by_name_at(root.as_raw(), name.as_ptr(), owner, &mut serial) })?;
    Ok(serial)
}

/// `keyring_resolve()`: the serial of a `KEY_SPEC_*` keyring, without creating it.
pub fn resolve(id: KeySerial) -> Result<KeySerial> {
    let mut serial: KeySerial = 0;
    // SAFETY: serial is a valid out-pointer.
    check(unsafe { sys::keyring_resolve(id, &mut serial) })?;
    Ok(serial)
}

/// `keyring_list()`: the serials of the keys linked into the keyring. `-ENOMEM` instead of aborting when
/// memory runs out.
pub fn list(keyring: KeySerial) -> Result<Vec<KeySerial>> {
    let mut serials: *mut KeySerial = ptr::null_mut();
    let mut n = 0;
    // SAFETY: both are valid out-pointers, serials receives a malloc()ed array of n entries on success.
    check(unsafe { sys::keyring_list(keyring, &mut serials, &mut n) })?;
    if serials.is_null() {
        return Ok(Vec::new());
    }

    let mut v = Vec::new();
    // SAFETY: the array has n entries.
    let r = v.extend_from_slice(unsafe { core::slice::from_raw_parts(serials, n) });
    // SAFETY: the array is ours to free.
    unsafe { sys::free(serials.cast::<c_void>()) };
    r?;
    Ok(v)
}

/// `keyring_describe_full()`.
pub fn describe_full(serial: KeySerial) -> Result<Description> {
    let mut type_: *mut c_char = ptr::null_mut();
    let mut description: *mut c_char = ptr::null_mut();
    let mut uid: sys::uid_t = 0;
    let mut perm = 0;
    // SAFETY: all out-pointers are valid, the strings are malloc()ed on success.
    let r = unsafe { sys::keyring_describe_full(serial, &mut type_, &mut uid, &mut perm, &mut description) };
    // SAFETY: whatever was returned is ours, and freed with the wrappers on the error path too.
    let (type_, description) = unsafe { (OwnedCStr::from_raw(type_), OwnedCStr::from_raw(description)) };
    check(r)?;
    Ok(Description {
        type_: type_.ok_or(Errno::EBADMSG)?,
        uid,
        perm,
        description: description.ok_or(Errno::EBADMSG)?,
    })
}

/// `keyring_perm()`: the permission mask of the key.
pub fn perm(serial: KeySerial) -> Result<u32> {
    let mut perm = 0;
    // SAFETY: perm is a valid out-pointer.
    check(unsafe { sys::keyring_perm(serial, &mut perm) })?;
    Ok(perm)
}

/// `keyring_description()`: the type specific description of the key.
pub fn description(serial: KeySerial) -> Result<OwnedCStr> {
    let mut description: *mut c_char = ptr::null_mut();
    // SAFETY: description is a valid out-pointer that receives a malloc()ed string on success.
    check(unsafe { sys::keyring_description(serial, &mut description) })?;
    // SAFETY: the string is ours.
    unsafe { OwnedCStr::from_raw(description) }.ok_or(Errno::EBADMSG)
}

/// `keyring_add_asymmetric()`: adds a DER encoded X.509 certificate to the keyring. Without a description the
/// kernel derives one from the certificate.
pub fn add_asymmetric(keyring: KeySerial, description: Option<&CStr>, der: &[u8]) -> Result<KeySerial> {
    if der.is_empty() {
        return Err(Errno::EINVAL);
    }
    let iov = sys::iovec {
        iov_base: der.as_ptr().cast_mut().cast(),
        iov_len: der.len(),
    };
    let mut serial: KeySerial = 0;
    // SAFETY: the iovec points to der, which the kernel only reads, serial is a valid out-pointer.
    check(unsafe {
        sys::keyring_add_asymmetric(
            keyring,
            description.map_or(ptr::null(), CStr::as_ptr),
            &iov,
            &mut serial,
        )
    })?;
    Ok(serial)
}

/// `keyring_restrict()`: `KEYCTL_RESTRICT_KEYRING`, a one-way transition.
pub fn restrict(keyring: KeySerial, type_: Option<&CStr>, restriction: Option<&CStr>) -> Result<()> {
    // SAFETY: both are C strings or NULL.
    check(unsafe {
        sys::keyring_restrict(
            keyring,
            type_.map_or(ptr::null(), CStr::as_ptr),
            restriction.map_or(ptr::null(), CStr::as_ptr),
        )
    })
    .map(|_| ())
}

/// `keyring_set_perm()`: `KEYCTL_SETPERM`.
pub fn set_perm(serial: KeySerial, perm: u32) -> Result<()> {
    // SAFETY: plain call into libsystemd-shared.
    check(unsafe { sys::keyring_set_perm(serial, perm) }).map(|_| ())
}

/// `keyring_unlink_key()`: removes the key from the keyring.
pub fn unlink_key(keyring: KeySerial, key: KeySerial) -> Result<()> {
    // SAFETY: plain call into libsystemd-shared.
    check(unsafe { sys::keyring_unlink_key(keyring, key) }).map(|_| ())
}
