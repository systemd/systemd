// SPDX-License-Identifier: LGPL-2.1-or-later

//! Memory allocation that never aborts, the way the kernel's Rust support does it.
//!
//! The `alloc` crate is not used: its collections abort the program when an allocation fails. [`Box`] and
//! [`Vec`] have no such paths. Everything that allocates returns a `Result` with [`AllocError`], which converts
//! into `-ENOMEM`, so a failed allocation is handled like it is in C. Memory comes from `malloc()` and friends,
//! as for the C code, so Rust and C allocations share one heap.
//!
//! There is no global allocator either, so a program that pulls in `alloc` regardless does not link.
//!
//! Like the kernel's, [`Box`] and [`Vec`] take their [`Allocator`] as a type parameter: [`Malloc`] unless
//! another one is named. [`Erasing`] erases memory before it is freed or moved, so `Vec<u8, Erasing>` makes a
//! buffer for secrets a type rather than a convention.

use core::alloc::Layout;
use core::ffi::c_void;
use core::fmt;
use core::marker::PhantomData;
use core::mem::{self, ManuallyDrop};
use core::ops::{Deref, DerefMut};
use core::ptr::{self, NonNull};
use core::slice;

use crate::sys;

/// An allocation failed, because memory ran out or the size does not fit the address space. Converts into
/// `-ENOMEM`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocError;

/// What `malloc()` guarantees on every libc the tree builds with: glibc aligns to twice the pointer size (or
/// more), musl to 16 bytes.
const MIN_ALIGN: usize = 2 * mem::size_of::<usize>();

fn malloc_aligns(layout: Layout) -> bool {
    // malloc(n) only guarantees the alignment of an object of n bytes.
    layout.align() <= MIN_ALIGN && layout.align() <= layout.size()
}

/// Where [`Box`] and [`Vec`] get their memory from, the kernel's `Allocator`. Allocators are zero-sized types
/// without instances, so the allocator is a property of the type of a box or vector rather than of its value.
///
/// # Safety
///
/// Memory an allocator hands out satisfies the layout it was requested for and stays valid until it is passed
/// back to [`Allocator::realloc()`] or [`Allocator::free()`].
pub unsafe trait Allocator {
    /// Allocates memory for `layout`.
    ///
    /// # Safety
    ///
    /// `layout` must not be zero-sized.
    unsafe fn alloc(layout: Layout) -> Result<NonNull<u8>, AllocError>;

    /// Moves the allocation `p` from `old` to `new`, which have the same alignment. On failure `p` is untouched.
    ///
    /// # Safety
    ///
    /// `p` must come from this allocator for `old`, and `new` must not be zero-sized.
    unsafe fn realloc(p: NonNull<u8>, old: Layout, new: Layout) -> Result<NonNull<u8>, AllocError>;

    /// Frees the allocation `p`.
    ///
    /// # Safety
    ///
    /// `p` must come from this allocator for `layout` and not have been freed.
    unsafe fn free(p: NonNull<u8>, layout: Layout);
}

/// `malloc()` and friends, as for the C code, so that Rust and C allocations share one heap. The allocator of
/// [`Box`] and [`Vec`] unless another one is named.
pub struct Malloc;

// SAFETY: every path returns memory of at least the requested size and alignment from libc, or an error, and
// frees only what it allocated.
unsafe impl Allocator for Malloc {
    /// `malloc()` or, for alignments it does not guarantee, `posix_memalign()`.
    unsafe fn alloc(layout: Layout) -> Result<NonNull<u8>, AllocError> {
        let p = if malloc_aligns(layout) {
            // SAFETY: plain call into libc.
            unsafe { sys::malloc(layout.size()) }
        } else {
            let mut p: *mut c_void = ptr::null_mut();
            // posix_memalign() wants a multiple of the pointer size.
            let align = layout.align().max(mem::size_of::<usize>());
            // SAFETY: align is a power of two and a multiple of the pointer size, p is a valid out-pointer.
            if unsafe { sys::posix_memalign(&mut p, align, layout.size()) } != 0 {
                return Err(AllocError);
            }
            p
        };
        NonNull::new(p.cast()).ok_or(AllocError)
    }

    unsafe fn realloc(p: NonNull<u8>, old: Layout, new: Layout) -> Result<NonNull<u8>, AllocError> {
        if malloc_aligns(new) {
            // SAFETY: p came from malloc(), posix_memalign() or realloc(), all of which realloc() takes, and it
            // keeps the alignment malloc() guarantees for the new size.
            let n = unsafe { sys::realloc(p.as_ptr().cast(), new.size()) };
            return NonNull::new(n.cast()).ok_or(AllocError);
        }

        // SAFETY: new is not zero-sized, as the caller guarantees.
        let n = unsafe { Self::alloc(new)? };
        // SAFETY: both blocks are valid for the smaller of the two sizes and do not overlap, the old one is ours
        // to free.
        unsafe {
            ptr::copy_nonoverlapping(p.as_ptr(), n.as_ptr(), old.size().min(new.size()));
            Self::free(p, old);
        }
        Ok(n)
    }

    unsafe fn free(p: NonNull<u8>, _layout: Layout) {
        // SAFETY: p came from malloc(), posix_memalign() or realloc(), as the caller guarantees.
        unsafe { sys::free(p.as_ptr().cast()) }
    }
}

/// Like [`Malloc`], but memory is erased before it is freed, also when growing or shrinking moves it, as
/// `erase_and_free()` does in C. For keys, passphrases and other secrets, e.g. `Vec<u8, Erasing>`. Elements a
/// [`Vec`] drops early, with [`Vec::pop()`] or [`Vec::truncate()`], stay in its memory until it is freed.
pub struct Erasing;

// SAFETY: memory comes from Malloc and goes back to libc once it is erased.
unsafe impl Allocator for Erasing {
    unsafe fn alloc(layout: Layout) -> Result<NonNull<u8>, AllocError> {
        // SAFETY: layout is not zero-sized, as the caller guarantees.
        unsafe { Malloc::alloc(layout) }
    }

    unsafe fn realloc(p: NonNull<u8>, old: Layout, new: Layout) -> Result<NonNull<u8>, AllocError> {
        // Never realloc(), which may leave the old contents behind in the memory it frees.
        // SAFETY: new is not zero-sized, as the caller guarantees.
        let n = unsafe { Self::alloc(new)? };
        // SAFETY: both blocks are valid for the smaller of the two sizes and do not overlap, the old one is ours
        // to erase and free.
        unsafe {
            ptr::copy_nonoverlapping(p.as_ptr(), n.as_ptr(), old.size().min(new.size()));
            Self::free(p, old);
        }
        Ok(n)
    }

    unsafe fn free(p: NonNull<u8>, _layout: Layout) {
        // SAFETY: p came from malloc() or posix_memalign(), erase_and_free() erases all of it before freeing it.
        unsafe { sys::erase_and_free(p.as_ptr().cast()) };
    }
}

/// An owned `T` on the heap, like `alloc::boxed::Box` but without the paths that abort when memory runs out:
/// [`Box::new()`] returns an error instead.
pub struct Box<T, A: Allocator = Malloc>(NonNull<T>, PhantomData<(T, A)>);

impl<T, A: Allocator> Box<T, A> {
    /// Moves `x` to the heap.
    pub fn new(x: T) -> Result<Box<T, A>, AllocError> {
        let layout = Layout::new::<T>();
        let p = if layout.size() == 0 {
            NonNull::dangling()
        } else {
            // SAFETY: the layout is not zero-sized.
            unsafe { A::alloc(layout)? }.cast::<T>()
        };
        // SAFETY: p is valid for writes of a T and suitably aligned.
        unsafe { p.as_ptr().write(x) };
        Ok(Box(p, PhantomData))
    }

    /// Hands the value over as a raw pointer, e.g. for C to keep as userdata. [`Box::from_raw()`] takes it back.
    pub fn into_raw(b: Box<T, A>) -> *mut T {
        ManuallyDrop::new(b).0.as_ptr()
    }

    /// Takes back what [`Box::into_raw()`] handed out.
    ///
    /// # Safety
    ///
    /// `p` must come from [`Box::into_raw()`] and not have been taken back before.
    pub unsafe fn from_raw(p: *mut T) -> Box<T, A> {
        // SAFETY: into_raw() never hands out NULL, as the caller guarantees.
        Box(unsafe { NonNull::new_unchecked(p) }, PhantomData)
    }

    /// Moves the value back out of the heap.
    pub fn into_inner(b: Box<T, A>) -> T {
        let b = ManuallyDrop::new(b);
        // SAFETY: the value is initialized and moved out once, the box is not dropped.
        let x = unsafe { b.0.as_ptr().read() };
        // SAFETY: the memory is ours, its value was moved out above.
        unsafe { free_box::<T, A>(b.0) };
        x
    }
}

/// Frees the memory of a box without dropping its value.
///
/// # Safety
///
/// `p` must be the pointer of a box whose memory was not freed yet.
unsafe fn free_box<T, A: Allocator>(p: NonNull<T>) {
    if mem::size_of::<T>() != 0 {
        // SAFETY: a box allocates exactly when T is not zero-sized, with A for the layout of T, as the caller
        // guarantees.
        unsafe { A::free(p.cast(), Layout::new::<T>()) };
    }
}

impl<T, A: Allocator> Drop for Box<T, A> {
    fn drop(&mut self) {
        // SAFETY: the value is initialized and dropped once, then its memory is freed.
        unsafe {
            ptr::drop_in_place(self.0.as_ptr());
            free_box::<T, A>(self.0);
        }
    }
}

impl<T, A: Allocator> Deref for Box<T, A> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the value is initialized and lives as long as the box.
        unsafe { self.0.as_ref() }
    }
}

impl<T, A: Allocator> DerefMut for Box<T, A> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the value is initialized, lives as long as the box and the box is borrowed mutably.
        unsafe { self.0.as_mut() }
    }
}

impl<T: fmt::Debug, A: Allocator> fmt::Debug for Box<T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

// SAFETY: a box owns its value like the value owns itself.
unsafe impl<T: Send, A: Allocator> Send for Box<T, A> {}
// SAFETY: as above.
unsafe impl<T: Sync, A: Allocator> Sync for Box<T, A> {}

/// A growable array on the heap, like `alloc::vec::Vec` but without the paths that abort when memory runs out:
/// whatever may allocate returns an error instead.
pub struct Vec<T, A: Allocator = Malloc> {
    ptr: NonNull<T>,
    cap: usize,
    len: usize,
    _owns: PhantomData<(T, A)>,
}

impl<T, A: Allocator> Vec<T, A> {
    const IS_ZST: bool = mem::size_of::<T>() == 0;

    /// An empty array, without allocating.
    pub const fn new() -> Vec<T, A> {
        Vec {
            ptr: NonNull::dangling(),
            // Zero-sized elements never need memory.
            cap: if Self::IS_ZST { usize::MAX } else { 0 },
            len: 0,
            _owns: PhantomData,
        }
    }

    /// An empty array with room for `capacity` elements.
    pub fn with_capacity(capacity: usize) -> Result<Vec<T, A>, AllocError> {
        let mut v = Vec::new();
        v.reserve_exact(capacity)?;
        Ok(v)
    }

    /// The number of elements.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether there are no elements.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// How many elements fit without allocating.
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Makes room for at least `additional` more elements, growing the allocation geometrically.
    pub fn reserve(&mut self, additional: usize) -> Result<(), AllocError> {
        let needed = self.len.checked_add(additional).ok_or(AllocError)?;
        if needed <= self.cap {
            return Ok(());
        }
        self.grow(needed.max(self.cap.saturating_mul(2)).max(4))
    }

    /// Makes room for exactly `additional` more elements.
    pub fn reserve_exact(&mut self, additional: usize) -> Result<(), AllocError> {
        let needed = self.len.checked_add(additional).ok_or(AllocError)?;
        if needed <= self.cap {
            return Ok(());
        }
        self.grow(needed)
    }

    fn grow(&mut self, cap: usize) -> Result<(), AllocError> {
        // Zero-sized elements never get here, their capacity is usize::MAX.
        let new = Layout::array::<T>(cap).map_err(|_| AllocError)?;
        let p = if self.cap == 0 {
            // SAFETY: T is not zero-sized and cap is not zero, hence neither is the layout.
            unsafe { A::alloc(new)? }
        } else {
            let old = Layout::array::<T>(self.cap).map_err(|_| AllocError)?;
            // SAFETY: the buffer was allocated for old, new is not zero-sized.
            unsafe { A::realloc(self.ptr.cast(), old, new)? }
        };
        self.ptr = p.cast();
        self.cap = cap;
        Ok(())
    }

    /// Appends `v`, allocating if there is no room left.
    pub fn push(&mut self, v: T) -> Result<(), AllocError> {
        self.reserve(1)?;
        // SAFETY: reserve() made room for one more element past len.
        unsafe { self.ptr.as_ptr().add(self.len).write(v) };
        self.len += 1;
        Ok(())
    }

    /// Removes the last element and returns it.
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        // SAFETY: the element at the old last index is initialized and no longer counted, it is read once.
        Some(unsafe { self.ptr.as_ptr().add(self.len).read() })
    }

    /// Drops the elements past `len`, keeping the allocation.
    pub fn truncate(&mut self, len: usize) {
        if len >= self.len {
            return;
        }
        // SAFETY: the elements from len on are initialized and within the allocation.
        let tail = ptr::slice_from_raw_parts_mut(unsafe { self.ptr.as_ptr().add(len) }, self.len - len);
        self.len = len;
        // SAFETY: the tail is no longer counted, so it is dropped exactly once.
        unsafe { ptr::drop_in_place(tail) };
    }

    /// Drops all elements, keeping the allocation.
    pub fn clear(&mut self) {
        self.truncate(0);
    }

    /// The elements.
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: the first len elements are initialized, ptr is non-null and aligned even when nothing is
        // allocated.
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// The elements, mutably.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: as in as_slice(), and the array is borrowed mutably.
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl<T: Clone, A: Allocator> Vec<T, A> {
    /// Appends clones of the elements of `other`.
    pub fn extend_from_slice(&mut self, other: &[T]) -> Result<(), AllocError> {
        self.reserve(other.len())?;
        for x in other {
            // SAFETY: reserve() made room for other.len() more elements past len.
            unsafe { self.ptr.as_ptr().add(self.len).write(x.clone()) };
            self.len += 1;
        }
        Ok(())
    }

    /// An array of `n` clones of `value`.
    pub fn from_elem(value: T, n: usize) -> Result<Vec<T, A>, AllocError> {
        let mut v = Vec::with_capacity(n)?;
        for _ in 0..n {
            v.push(value.clone())?;
        }
        Ok(v)
    }
}

impl<T, A: Allocator> Drop for Vec<T, A> {
    fn drop(&mut self) {
        self.clear();
        if Self::IS_ZST || self.cap == 0 {
            return;
        }
        // The layout was computed the same way when the buffer was allocated
        if let Ok(layout) = Layout::array::<T>(self.cap) {
            // SAFETY: the buffer was allocated by A for this layout and its elements are dropped.
            unsafe { A::free(self.ptr.cast(), layout) };
        }
    }
}

impl<T, A: Allocator> Default for Vec<T, A> {
    fn default() -> Vec<T, A> {
        Vec::new()
    }
}

impl<T, A: Allocator> Deref for Vec<T, A> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T, A: Allocator> DerefMut for Vec<T, A> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<'a, T, A: Allocator> IntoIterator for &'a Vec<T, A> {
    type Item = &'a T;
    type IntoIter = slice::Iter<'a, T>;

    fn into_iter(self) -> slice::Iter<'a, T> {
        self.iter()
    }
}

impl<'a, T, A: Allocator> IntoIterator for &'a mut Vec<T, A> {
    type Item = &'a mut T;
    type IntoIter = slice::IterMut<'a, T>;

    fn into_iter(self) -> slice::IterMut<'a, T> {
        self.iter_mut()
    }
}

impl<T: fmt::Debug, A: Allocator> fmt::Debug for Vec<T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_slice().fmt(f)
    }
}

impl<T: PartialEq<U>, U, A: Allocator> PartialEq<[U]> for Vec<T, A> {
    fn eq(&self, other: &[U]) -> bool {
        self.as_slice() == other
    }
}

impl<T: PartialEq<U>, U, A: Allocator, const N: usize> PartialEq<[U; N]> for Vec<T, A> {
    fn eq(&self, other: &[U; N]) -> bool {
        self.as_slice() == other
    }
}

// SAFETY: a vector owns its elements like the elements own themselves.
unsafe impl<T: Send, A: Allocator> Send for Vec<T, A> {}
// SAFETY: as above.
unsafe impl<T: Sync, A: Allocator> Sync for Vec<T, A> {}
