// SPDX-License-Identifier: LGPL-2.1-or-later

//! The File Hierarchy for the Verification of OS Artifacts (VOA), `voa-util.h`.

use core::ffi::{c_char, CStr};
use core::ptr;

use crate::conf_files::ConfFiles;
use crate::errno::{check, Result};
use crate::fd::BorrowedFd;
use crate::strv::Strv;
use crate::sys;

pub use sys::{
    VoaFlags, VoaMode, VOA_EPHEMERAL_LOAD_PATH, VOA_MODE_ARTIFACT_VERIFIER, VOA_MODE_TRUST_ANCHOR,
    VOA_TECHNOLOGY_X509, VOA_WARN, VOA_X509_CERTIFICATE_SUFFIX,
};

/// Where to look for verifiers, C's `VoaLookup`.
pub struct Lookup<'a> {
    /// The OS identifiers, all of them are searched.
    pub os: &'a Strv,
    /// The role.
    pub role: &'a CStr,
    /// The context below the role.
    pub context: &'a CStr,
    /// Artifact verifiers or trust anchors.
    pub mode: VoaMode,
    /// The technology, e.g. [`VOA_TECHNOLOGY_X509`].
    pub technology: &'a CStr,
    /// The file name suffix, e.g. [`VOA_X509_CERTIFICATE_SUFFIX`].
    pub suffix: &'a CStr,
}

/// `voa_identifier_is_valid()`.
pub fn identifier_is_valid(s: &CStr, allow_colon: bool) -> bool {
    // SAFETY: s is a C string.
    unsafe { sys::voa_identifier_is_valid(s.as_ptr(), allow_colon) }
}

/// `voa_os_is_valid()`.
pub fn os_is_valid(s: &CStr) -> bool {
    // SAFETY: s is a C string.
    unsafe { sys::voa_os_is_valid(s.as_ptr()) }
}

/// `voa_os_identifiers()`: the identifiers to look up for the OS in `root`, the exact one, then the bare
/// `ID`. The flag is set when only the bare `ID` is usable, because a field contains characters the
/// specification does not permit.
pub fn os_identifiers(root: BorrowedFd<'_>) -> Result<(Strv, bool)> {
    let mut l: *mut *mut c_char = ptr::null_mut();
    // SAFETY: l is a valid out-pointer that receives an strv on success.
    let r = check(unsafe { sys::voa_os_identifiers(root.as_raw(), &mut l) })?;
    // SAFETY: the strv is ours.
    Ok((unsafe { Strv::from_raw(l) }, r > 0))
}

/// `voa_list_verifiers()`: the verifiers in load path order, masked ones dropped.
pub fn list_verifiers(root: BorrowedFd<'_>, lookup: &Lookup<'_>, flags: VoaFlags) -> Result<ConfFiles> {
    let l = sys::VoaLookup {
        os: lookup.os.as_ptr().cast_mut(),
        role: lookup.role.as_ptr(),
        context: lookup.context.as_ptr(),
        mode: lookup.mode,
        technology: lookup.technology.as_ptr(),
        suffix: lookup.suffix.as_ptr(),
    };
    let mut files: *mut *mut sys::ConfFile = ptr::null_mut();
    let mut n = 0;
    // SAFETY: the lookup only borrows strings that outlive the call, the C code does not modify the strv;
    // files and n are valid out-pointers.
    check(unsafe { sys::voa_list_verifiers(root.as_raw(), &l, flags, &mut files, &mut n) })?;
    // SAFETY: the array is ours.
    Ok(unsafe { ConfFiles::from_raw(files, n) })
}
