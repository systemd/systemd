// SPDX-License-Identifier: LGPL-2.1-or-later

//! Reference counted objects, `sd_*_ref()`/`sd_*_unref()`.

use core::mem;
use core::ptr::NonNull;

/// A C type that is reference counted.
///
/// # Safety
///
/// `inc_ref()` and `dec_ref()` must call the type's own reference counting functions and nothing else.
pub unsafe trait RefCounted {
    /// Takes an additional reference.
    ///
    /// # Safety
    ///
    /// `this` must point to a live object.
    unsafe fn inc_ref(this: NonNull<Self>);

    /// Drops a reference.
    ///
    /// # Safety
    ///
    /// `this` must point to a live object and the caller must own one of its references.
    unsafe fn dec_ref(this: NonNull<Self>);
}

/// An owned reference to a [`RefCounted`] object: `Clone` takes another one, `Drop` releases it, like
/// `_cleanup_(sd_foo_unrefp)` in C.
pub struct Ref<T: RefCounted>(NonNull<T>);

impl<T: RefCounted> Ref<T> {
    /// Takes ownership of a reference, `None` for NULL.
    ///
    /// # Safety
    ///
    /// `p` must be NULL or point to a live object whose reference the caller owns.
    pub unsafe fn from_raw(p: *mut T) -> Option<Ref<T>> {
        NonNull::new(p).map(Ref)
    }

    /// The raw pointer, for passing to C.
    pub fn as_ptr(&self) -> *mut T {
        self.0.as_ptr()
    }

    /// Gives the reference to C, `TAKE_PTR()`.
    pub fn into_raw(self) -> *mut T {
        let p = self.0.as_ptr();
        mem::forget(self);
        p
    }
}

impl<T: RefCounted> Clone for Ref<T> {
    fn clone(&self) -> Ref<T> {
        // SAFETY: we own a reference, so the object is alive.
        unsafe { T::inc_ref(self.0) };
        Ref(self.0)
    }
}

impl<T: RefCounted> Drop for Ref<T> {
    fn drop(&mut self) {
        // SAFETY: drops the reference we own.
        unsafe { T::dec_ref(self.0) };
    }
}
