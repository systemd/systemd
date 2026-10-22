// SPDX-License-Identifier: LGPL-2.1-or-later

//! Loading kernel modules through libkmod, `module-util.h`.

use core::ffi::CStr;
use core::ptr::{self, NonNull};

use crate::errno::{check, Errno, Result};
use crate::sys;

/// A libkmod context, `struct kmod_ctx`. Without libkmod support there never is one.
pub struct Kmod(NonNull<sys::kmod_ctx>);

impl Kmod {
    /// `module_setup_context()`.
    pub fn setup() -> Result<Kmod> {
        let mut ctx: *mut sys::kmod_ctx = ptr::null_mut();
        // SAFETY: ctx is a valid out-pointer that receives a reference on success.
        check(unsafe { sys::module_setup_context(&mut ctx) })?;
        NonNull::new(ctx).map(Kmod).ok_or(Errno::EINVAL)
    }

    /// `module_load_and_warn()`.
    pub fn load_and_warn(&self, module: &CStr, verbose: bool) -> Result<()> {
        // SAFETY: the context is alive, module is a C string.
        check(unsafe { sys::module_load_and_warn(self.0.as_ptr(), module.as_ptr(), verbose) }).map(|_| ())
    }
}

impl Drop for Kmod {
    fn drop(&mut self) {
        #[cfg(HAVE_KMOD)]
        {
            let mut ctx = self.0.as_ptr();
            // SAFETY: we own the reference.
            unsafe { sys::kmod_unrefp(&mut ctx) };
        }
    }
}
