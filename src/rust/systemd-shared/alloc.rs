// SPDX-License-Identifier: LGPL-2.1-or-later

//! Memory allocation that never aborts.
//!
//! The `alloc` crate is not used: its collections abort the program when an allocation fails. [`Box`] and
//! [`Vec`] have no such paths. Everything that allocates returns a `Result` with [`AllocError`], which converts
//! into `-ENOMEM`, so a failed allocation is handled like it is in C. Memory comes from `malloc()` and friends,
//! as for the C code, so Rust and C allocations share one heap.
//!
//! No global allocator is registered either. If the `alloc` crate sneaks in, the link fails.
//!
//! [`Box`] and [`Vec`] carry their [`Allocator`] like std's do: [`Malloc`] unless another one is handed to
//! [`Box::new_in()`] or [`Vec::new_in()`]. [`Erasing`] erases memory before it is freed or moved, so
//! `Vec<u8, Erasing>` makes a buffer for secrets a type rather than a convention.

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

impl fmt::Display for AllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("memory allocation failed")
    }
}

/// What `malloc()` guarantees at least: twice the pointer size on glibc, 16 bytes on musl. This is the lower
/// bound of the two.
const MIN_ALIGN: usize = 2 * mem::size_of::<usize>();

fn malloc_aligns(layout: Layout) -> bool {
    // malloc(n) only guarantees the alignment of an object of n bytes.
    layout.align() <= MIN_ALIGN && layout.align() <= layout.size()
}

/// The block a zero-sized request gets: nothing behind it, but aligned as asked.
fn dangling(layout: Layout) -> NonNull<[u8]> {
    // SAFETY: an alignment is never zero.
    let p = unsafe { NonNull::new_unchecked(ptr::without_provenance_mut::<u8>(layout.align())) };
    NonNull::slice_from_raw_parts(p, 0)
}

/// Where [`Box`] and [`Vec`] get their memory from. This is `core::alloc::Allocator` as Rust 1.100 stabilizes
/// it, its methods, their contracts and their provided implementations, spelled out because the tree's floor is
/// 1.85. Once the floor moves it becomes a re-export and nothing else changes. std's own boxes and vectors stay
/// out though: they abort when memory runs out.
///
/// # Safety
///
/// A block an allocator hands out satisfies the layout it was requested for and stays valid until it is passed
/// to [`Allocator::deallocate()`], [`Allocator::grow()`] or [`Allocator::shrink()`], also when the allocator is
/// moved, copied or cloned: a copy takes blocks of the original and the other way round.
pub unsafe trait Allocator {
    /// Allocates a block for `layout`, at least as large as it asks for: the length of the result says how
    /// large. A zero-sized layout gets a dangling block that must not be dereferenced.
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError>;

    /// Like [`Allocator::allocate()`], with the block zeroed.
    fn allocate_zeroed(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let p = self.allocate(layout)?;
        // SAFETY: the block is valid for writes of its length.
        unsafe { p.cast::<u8>().as_ptr().write_bytes(0, p.len()) };
        Ok(p)
    }

    /// Frees the block `ptr` points to.
    ///
    /// # Safety
    ///
    /// `ptr` must come from this allocator for `layout` and not have been freed.
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout);

    /// Moves the block `ptr` points to from `old_layout` to the larger `new_layout`, keeping its contents. On
    /// failure the block stays as it was.
    ///
    /// # Safety
    ///
    /// `ptr` must come from this allocator for `old_layout`, and `new_layout` must not be smaller.
    unsafe fn grow(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        debug_assert!(new_layout.size() >= old_layout.size());
        let p = self.allocate(new_layout)?;
        // SAFETY: both blocks are valid for old_layout.size() bytes and do not overlap, the old one is ours to
        // free.
        unsafe {
            ptr::copy_nonoverlapping(ptr.as_ptr(), p.cast::<u8>().as_ptr(), old_layout.size());
            self.deallocate(ptr, old_layout);
        }
        Ok(p)
    }

    /// Like [`Allocator::grow()`], with the added memory zeroed.
    ///
    /// # Safety
    ///
    /// As for [`Allocator::grow()`].
    unsafe fn grow_zeroed(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        debug_assert!(new_layout.size() >= old_layout.size());
        let p = self.allocate_zeroed(new_layout)?;
        // SAFETY: as in grow().
        unsafe {
            ptr::copy_nonoverlapping(ptr.as_ptr(), p.cast::<u8>().as_ptr(), old_layout.size());
            self.deallocate(ptr, old_layout);
        }
        Ok(p)
    }

    /// Moves the block `ptr` points to from `old_layout` to the smaller `new_layout`, keeping what fits. On
    /// failure the block stays as it was.
    ///
    /// # Safety
    ///
    /// `ptr` must come from this allocator for `old_layout`, and `new_layout` must not be larger.
    unsafe fn shrink(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        debug_assert!(new_layout.size() <= old_layout.size());
        let p = self.allocate(new_layout)?;
        // SAFETY: both blocks are valid for new_layout.size() bytes and do not overlap, the old one is ours to
        // free.
        unsafe {
            ptr::copy_nonoverlapping(ptr.as_ptr(), p.cast::<u8>().as_ptr(), new_layout.size());
            self.deallocate(ptr, old_layout);
        }
        Ok(p)
    }
}

/// `malloc()` and friends, as for the C code, so that Rust and C allocations share one heap. The allocator of
/// [`Box`] and [`Vec`] unless another one is named.
#[derive(Clone, Copy, Debug, Default)]
pub struct Malloc;

impl Malloc {
    /// `realloc()` for a block that `malloc()` aligns, a new block and a copy for the rest: `realloc()` keeps
    /// no alignment beyond `malloc()`'s.
    ///
    /// # Safety
    ///
    /// `ptr` must come from this allocator for `old_layout`.
    unsafe fn realloc(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        if old_layout.size() == 0 {
            return self.allocate(new_layout);
        }
        if new_layout.size() == 0 {
            // SAFETY: the block is ours to free, as the caller guarantees.
            unsafe { self.deallocate(ptr, old_layout) };
            return Ok(dangling(new_layout));
        }
        if malloc_aligns(new_layout) {
            // SAFETY: ptr came from malloc(), posix_memalign() or realloc(), all of which realloc() takes, and
            // it keeps the alignment malloc() guarantees for the new size.
            let n = unsafe { sys::realloc(ptr.as_ptr().cast(), new_layout.size()) };
            let n = NonNull::new(n.cast::<u8>()).ok_or(AllocError)?;
            return Ok(NonNull::slice_from_raw_parts(n, new_layout.size()));
        }
        let n = self.allocate(new_layout)?;
        // SAFETY: both blocks are valid for the smaller of the two sizes and do not overlap, the old one is ours
        // to free.
        unsafe {
            ptr::copy_nonoverlapping(
                ptr.as_ptr(),
                n.cast::<u8>().as_ptr(),
                old_layout.size().min(new_layout.size()),
            );
            self.deallocate(ptr, old_layout);
        }
        Ok(n)
    }
}

// SAFETY: every path returns a block of at least the requested size and alignment from libc, a dangling one for
// nothing, or an error, and frees only what it allocated.
unsafe impl Allocator for Malloc {
    /// `malloc()` or, for alignments it does not guarantee, `posix_memalign()`.
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        if layout.size() == 0 {
            return Ok(dangling(layout));
        }
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
        let p = NonNull::new(p.cast::<u8>()).ok_or(AllocError)?;
        Ok(NonNull::slice_from_raw_parts(p, layout.size()))
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        if layout.size() == 0 {
            return;
        }
        // SAFETY: ptr came from malloc(), posix_memalign() or realloc(), as the caller guarantees.
        unsafe { sys::free(ptr.as_ptr().cast()) }
    }

    unsafe fn grow(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        debug_assert!(new_layout.size() >= old_layout.size());
        // SAFETY: the block is ours for old_layout, as the caller guarantees.
        unsafe { self.realloc(ptr, old_layout, new_layout) }
    }

    unsafe fn shrink(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        debug_assert!(new_layout.size() <= old_layout.size());
        // SAFETY: as in grow().
        unsafe { self.realloc(ptr, old_layout, new_layout) }
    }
}

/// Like [`Malloc`], but memory is erased before it is freed, also when growing or shrinking moves it, as
/// `erase_and_free()` does in C. For keys, passphrases and other secrets, e.g. `Vec<u8, Erasing>`. Elements a
/// [`Vec`] drops early, with [`Vec::pop()`] or [`Vec::truncate()`], stay in its memory until it is freed.
#[derive(Clone, Copy, Debug, Default)]
pub struct Erasing;

// SAFETY: blocks come from Malloc and go back to libc once they are erased. Growing and shrinking keep the
// provided implementations: never realloc(), which may leave the old contents behind in the memory it frees,
// but a new block, a copy and deallocate(), which erases.
unsafe impl Allocator for Erasing {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        Malloc.allocate(layout)
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        if layout.size() == 0 {
            return;
        }
        // SAFETY: ptr came from malloc() or posix_memalign(), erase_and_free() erases all of it before freeing
        // it.
        unsafe { sys::erase_and_free(ptr.as_ptr().cast()) };
    }
}

/// An owned `T` on the heap, like `alloc::boxed::Box` but without the paths that abort when memory runs out:
/// [`Box::new()`] returns an error instead. A boxed slice comes from [`Vec::into_boxed_slice()`].
pub struct Box<T: ?Sized, A: Allocator = Malloc>(NonNull<T>, A);

impl<T> Box<T> {
    /// Moves `x` to the heap, allocating with [`Malloc`].
    pub fn new(x: T) -> Result<Box<T>, AllocError> {
        Box::new_in(x, Malloc)
    }
}

impl<T, A: Allocator> Box<T, A> {
    /// Moves `x` to the heap, allocating with `alloc`.
    pub fn new_in(x: T, alloc: A) -> Result<Box<T, A>, AllocError> {
        let layout = Layout::new::<T>();
        // As with std, a zero-sized value takes no block from the allocator.
        let p = if layout.size() == 0 {
            NonNull::dangling()
        } else {
            alloc.allocate(layout)?.cast::<T>()
        };
        // SAFETY: the block is valid for writes of a T and aligned for it, the dangling one of a zero-sized T
        // included.
        unsafe { p.as_ptr().write(x) };
        Ok(Box(p, alloc))
    }

    /// Moves the value back out of the heap.
    pub fn into_inner(b: Box<T, A>) -> T {
        let b = ManuallyDrop::new(b);
        // SAFETY: the value is initialized and moved out once, and so is the allocator; the box is not dropped.
        let (x, alloc) = unsafe { (b.0.as_ptr().read(), ptr::read(&b.1)) };
        let layout = Layout::new::<T>();
        if layout.size() != 0 {
            // SAFETY: the block came from the allocator for the layout of T, its value was moved out above.
            unsafe { alloc.deallocate(b.0.cast(), layout) };
        }
        x
    }
}

impl<T: ?Sized, A: Allocator> Drop for Box<T, A> {
    fn drop(&mut self) {
        // SAFETY: the value is initialized and dropped once, then its block goes back to the allocator for the
        // layout it was allocated with, which is the value's own. A zero-sized value has no block.
        unsafe {
            let layout = Layout::for_value(self.0.as_ref());
            ptr::drop_in_place(self.0.as_ptr());
            if layout.size() != 0 {
                self.1.deallocate(self.0.cast(), layout);
            }
        }
    }
}

impl<T: ?Sized, A: Allocator> Deref for Box<T, A> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the value is initialized and lives as long as the box.
        unsafe { self.0.as_ref() }
    }
}

impl<T: ?Sized, A: Allocator> DerefMut for Box<T, A> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the value is initialized, lives as long as the box and the box is borrowed mutably.
        unsafe { self.0.as_mut() }
    }
}

impl<T: ?Sized + fmt::Debug, A: Allocator> fmt::Debug for Box<T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

// SAFETY: a box owns its value like the value owns itself, and its allocator like any field.
unsafe impl<T: ?Sized + Send, A: Allocator + Send> Send for Box<T, A> {}
// SAFETY: as above.
unsafe impl<T: ?Sized + Sync, A: Allocator + Sync> Sync for Box<T, A> {}

/// A growable array on the heap, like `alloc::vec::Vec` but without the paths that abort when memory runs out:
/// whatever may allocate returns an error instead.
pub struct Vec<T, A: Allocator = Malloc> {
    ptr: NonNull<T>,
    cap: usize,
    len: usize,
    alloc: A,
    _owns: PhantomData<T>,
}

impl<T> Vec<T> {
    /// An empty array, without allocating, with [`Malloc`] for later.
    pub const fn new() -> Vec<T> {
        Vec::new_in(Malloc)
    }

    /// An empty array with room for `capacity` elements, allocated with [`Malloc`].
    pub fn with_capacity(capacity: usize) -> Result<Vec<T>, AllocError> {
        Vec::with_capacity_in(capacity, Malloc)
    }
}

impl<T, A: Allocator> Vec<T, A> {
    const IS_ZST: bool = mem::size_of::<T>() == 0;

    /// An empty array, without allocating, with `alloc` for later.
    pub const fn new_in(alloc: A) -> Vec<T, A> {
        Vec {
            ptr: NonNull::dangling(),
            // Zero-sized elements never need memory.
            cap: if Self::IS_ZST { usize::MAX } else { 0 },
            len: 0,
            alloc,
            _owns: PhantomData,
        }
    }

    /// An empty array with room for `capacity` elements, allocated with `alloc`.
    pub fn with_capacity_in(capacity: usize, alloc: A) -> Result<Vec<T, A>, AllocError> {
        let mut v = Vec::new_in(alloc);
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

    /// Gives the spare capacity back. On failure the allocation stays as it was.
    pub fn shrink_to_fit(&mut self) -> Result<(), AllocError> {
        if Self::IS_ZST || self.cap == self.len {
            return Ok(());
        }
        let old = Layout::array::<T>(self.cap).map_err(|_| AllocError)?;
        if self.len == 0 {
            // SAFETY: the block came from the allocator for old and holds no element.
            unsafe { self.alloc.deallocate(self.ptr.cast(), old) };
            self.ptr = NonNull::dangling();
        } else {
            let new = Layout::array::<T>(self.len).map_err(|_| AllocError)?;
            // SAFETY: the block was allocated for old, and new is smaller.
            self.ptr = unsafe { self.alloc.shrink(self.ptr.cast(), old, new)? }.cast();
        }
        self.cap = self.len;
        Ok(())
    }

    fn grow(&mut self, cap: usize) -> Result<(), AllocError> {
        // Zero-sized elements never get here, their capacity is usize::MAX.
        let new = Layout::array::<T>(cap).map_err(|_| AllocError)?;
        let p = if self.cap == 0 {
            self.alloc.allocate(new)?
        } else {
            let old = Layout::array::<T>(self.cap).map_err(|_| AllocError)?;
            // SAFETY: the block was allocated for old, and new is larger.
            unsafe { self.alloc.grow(self.ptr.cast(), old, new)? }
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

    /// Hands the elements over as a boxed slice, with the spare capacity given back. On failure the elements
    /// are dropped.
    pub fn into_boxed_slice(mut self) -> Result<Box<[T], A>, AllocError> {
        self.shrink_to_fit()?;
        let v = ManuallyDrop::new(self);
        // SAFETY: the allocator is moved out once, the vector is not dropped.
        let alloc = unsafe { ptr::read(&v.alloc) };
        Ok(Box(NonNull::slice_from_raw_parts(v.ptr, v.len), alloc))
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
}

impl<T: Clone> Vec<T> {
    /// An array of `n` clones of `value`, allocated with [`Malloc`].
    pub fn from_elem(value: T, n: usize) -> Result<Vec<T>, AllocError> {
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
        // The layout was computed the same way when the block was allocated
        if let Ok(layout) = Layout::array::<T>(self.cap) {
            // SAFETY: the block came from the allocator for this layout and its elements are dropped.
            unsafe { self.alloc.deallocate(self.ptr.cast(), layout) };
        }
    }
}

impl<T> Default for Vec<T> {
    fn default() -> Vec<T> {
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

// SAFETY: a vector owns its elements like the elements own themselves, and its allocator like any field.
unsafe impl<T: Send, A: Allocator + Send> Send for Vec<T, A> {}
// SAFETY: as above.
unsafe impl<T: Sync, A: Allocator + Sync> Sync for Vec<T, A> {}
