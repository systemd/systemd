// SPDX-License-Identifier: LGPL-2.1-or-later

//! sd-event. Callbacks are closures: the closure is boxed, handed to C as the `userdata`, and freed by the
//! source's destroy callback, so it lives exactly as long as the source.

use core::ffi::{c_int, c_void};
use core::mem::ManuallyDrop;
use core::ptr::{self, NonNull};

use crate::errno::{check, from_result, Errno, Result};
use crate::refcount::{Ref, RefCounted};
use crate::sys;

// SAFETY: sd_event_ref()/sd_event_unref() are the type's reference counting functions.
unsafe impl RefCounted for sys::sd_event {
    unsafe fn inc_ref(this: NonNull<Self>) {
        // SAFETY: the caller guarantees a live object.
        unsafe { sys::sd_event_ref(this.as_ptr()) };
    }

    unsafe fn dec_ref(this: NonNull<Self>) {
        // SAFETY: the caller guarantees a live object and an owned reference.
        unsafe { sys::sd_event_unref(this.as_ptr()) };
    }
}

// SAFETY: sd_event_source_ref()/sd_event_source_unref() are the type's reference counting functions.
unsafe impl RefCounted for sys::sd_event_source {
    unsafe fn inc_ref(this: NonNull<Self>) {
        // SAFETY: the caller guarantees a live object.
        unsafe { sys::sd_event_source_ref(this.as_ptr()) };
    }

    unsafe fn dec_ref(this: NonNull<Self>) {
        // SAFETY: the caller guarantees a live object and an owned reference.
        unsafe { sys::sd_event_source_unref(this.as_ptr()) };
    }
}

/// A reference to an `sd_event` loop.
#[derive(Clone)]
pub struct Event(Ref<sys::sd_event>);

/// A reference to an `sd_event_source`. Dropping the last reference disables the source, as in C.
#[derive(Clone)]
pub struct EventSource(Ref<sys::sd_event_source>);

/// What a time event source runs: the source and the time it fired at, `sd_event_time_handler_t`. An error
/// is returned to sd-event as `-errno`, which disables the source (or exits the loop, see
/// `sd_event_source_set_exit_on_failure()`).
pub trait TimeHandler: FnMut(&EventSource, u64) -> Result<()> + 'static {}
impl<F: FnMut(&EventSource, u64) -> Result<()> + 'static> TimeHandler for F {}

impl Event {
    /// `sd_event_default()`.
    pub fn try_default() -> Result<Event> {
        let mut e: *mut sys::sd_event = ptr::null_mut();
        // SAFETY: e receives a new reference on success.
        check(unsafe { sys::sd_event_default(&mut e) })?;
        // SAFETY: we own the reference sd_event_default() handed out.
        unsafe { Ref::from_raw(e) }.map(Event).ok_or(Errno::EINVAL)
    }

    /// `sd_event_new()`.
    pub fn new() -> Result<Event> {
        let mut e: *mut sys::sd_event = ptr::null_mut();
        // SAFETY: e receives a new reference on success.
        check(unsafe { sys::sd_event_new(&mut e) })?;
        // SAFETY: we own the reference sd_event_new() handed out.
        unsafe { Ref::from_raw(e) }.map(Event).ok_or(Errno::EINVAL)
    }

    /// The raw pointer, for passing to C.
    pub fn as_ptr(&self) -> *mut sys::sd_event {
        self.0.as_ptr()
    }

    /// `sd_event_add_time_relative()`.
    ///
    /// ```
    /// use systemd_shared::prelude::*;
    /// use systemd_shared::sys;
    ///
    /// let event = Event::new().unwrap();
    /// let source = event
    ///     .add_time_relative(sys::CLOCK_MONOTONIC as sys::clockid_t, 1000, 0, |source, _usec| {
    ///         source.event().exit(7)
    ///     })
    ///     .unwrap();
    /// assert_eq!(event.run_loop().unwrap(), 7);
    /// ```
    pub fn add_time_relative<F: TimeHandler>(
        &self,
        clock: sys::clockid_t,
        usec: u64,
        accuracy: u64,
        callback: F,
    ) -> Result<EventSource> {
        let userdata = Box::into_raw(Box::new(callback));
        let mut s: *mut sys::sd_event_source = ptr::null_mut();
        // SAFETY: s receives a new reference on success, the trampoline matches the closure type of the box
        // handed over as userdata.
        let r = unsafe {
            sys::sd_event_add_time_relative(
                self.as_ptr(),
                &mut s,
                clock,
                usec,
                accuracy,
                Some(time_trampoline::<F>),
                userdata.cast(),
            )
        };
        if let Err(e) = check(r) {
            // SAFETY: C did not take the box.
            drop(unsafe { Box::from_raw(userdata) });
            return Err(e);
        }
        // SAFETY: we own the reference sd_event_add_time_relative() handed out.
        let source = unsafe { Ref::from_raw(s) }
            .map(EventSource)
            .ok_or(Errno::EINVAL)?;

        // SAFETY: userdata is the box registered above and drop_userdata::<F> is its destructor.
        if let Err(e) = check(unsafe {
            sys::sd_event_source_set_destroy_callback(source.as_ptr(), Some(drop_userdata::<F>))
        }) {
            drop(source);
            // SAFETY: the source is gone without having called a destroy callback, the box is ours again.
            drop(unsafe { Box::from_raw(userdata) });
            return Err(e);
        }
        Ok(source)
    }

    /// `sd_event_loop()`.
    pub fn run_loop(&self) -> Result<c_int> {
        // SAFETY: plain call on a valid event loop.
        check(unsafe { sys::sd_event_loop(self.as_ptr()) })
    }

    /// `sd_event_exit()`.
    pub fn exit(&self, code: c_int) -> Result<()> {
        // SAFETY: plain call on a valid event loop.
        check(unsafe { sys::sd_event_exit(self.as_ptr(), code) }).map(|_| ())
    }
}

impl EventSource {
    /// The raw pointer, for passing to C.
    pub fn as_ptr(&self) -> *mut sys::sd_event_source {
        self.0.as_ptr()
    }

    /// `sd_event_source_set_exit_on_failure()`: an error from the handler ends the loop with that error
    /// instead of only disabling the source.
    pub fn set_exit_on_failure(&self, on: bool) -> Result<()> {
        // SAFETY: plain call on a valid source.
        check(unsafe { sys::sd_event_source_set_exit_on_failure(self.as_ptr(), c_int::from(on)) })
            .map(|_| ())
    }

    /// The event loop the source belongs to, `sd_event_source_get_event()`.
    pub fn event(&self) -> Event {
        // SAFETY: a live source always has an event loop; sd_event_source_get_event() does not take a
        // reference, so take one before wrapping the pointer.
        let e = unsafe { sys::sd_event_ref(sys::sd_event_source_get_event(self.as_ptr())) };
        // SAFETY: we own the reference just taken.
        Event(unsafe { Ref::from_raw(e) }.expect("event source without event loop"))
    }
}

/// The `sd_event_time_handler_t` behind [`Event::add_time_relative`].
///
/// # Safety
///
/// Only sd-event calls this, with the source it was registered for and the `Box<F>` it was given as userdata.
unsafe extern "C" fn time_trampoline<F: TimeHandler>(
    s: *mut sys::sd_event_source,
    usec: u64,
    userdata: *mut c_void,
) -> c_int {
    // SAFETY: userdata is the Box<F> add_time_relative() registered, and sd-event runs one callback at a
    // time, so no other reference to it exists.
    let callback = unsafe { &mut *userdata.cast::<F>() };
    // SAFETY: s is alive for the duration of the callback and the reference stays with sd-event, hence the
    // wrapper must not release it.
    let source = ManuallyDrop::new(EventSource(
        unsafe { Ref::from_raw(s) }.expect("callback without source"),
    ));
    from_result(|| callback(&source, usec).map(|()| 0))
}

/// The `sd_event_destroy_t` behind [`Event::add_time_relative`].
///
/// # Safety
///
/// Only sd-event calls this, once, with the `Box<F>` the source was given as userdata.
unsafe extern "C" fn drop_userdata<F: TimeHandler>(userdata: *mut c_void) {
    // SAFETY: userdata is the Box<F> add_time_relative() registered; sd-event calls the destroy callback once,
    // when the source is freed.
    drop(unsafe { Box::from_raw(userdata.cast::<F>()) });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    #[test]
    fn timer_exits_loop() {
        let e = Event::new().unwrap();
        let fired = Rc::new(Cell::new(0));
        let counter = Rc::clone(&fired);
        let source = e
            .add_time_relative(
                sys::CLOCK_MONOTONIC as sys::clockid_t,
                1000,
                0,
                move |source, _usec| {
                    counter.set(counter.get() + 1);
                    source.event().exit(7)
                },
            )
            .unwrap();
        assert_eq!(e.run_loop().unwrap(), 7);
        assert_eq!(fired.get(), 1);

        // The closure holds a clone of the counter until the source is freed.
        assert_eq!(Rc::strong_count(&fired), 2);
        drop(source);
        drop(e);
        assert_eq!(Rc::strong_count(&fired), 1);
    }

    #[test]
    fn handler_errors_reach_the_loop() {
        let e = Event::new().unwrap();
        let source = e
            .add_time_relative(sys::CLOCK_MONOTONIC as sys::clockid_t, 0, 0, |_source, _usec| {
                Err(Errno::EIO)
            })
            .unwrap();
        source.set_exit_on_failure(true).unwrap();
        assert_eq!(e.run_loop(), Err(Errno::EIO));
    }

    #[test]
    fn events_are_shared_references() {
        let e = Event::new().unwrap();
        let e2 = e.clone();
        assert_eq!(e.as_ptr(), e2.as_ptr());
    }
}
