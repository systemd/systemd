/*
 * klibc/sysconfig.h
 *
 * Allows for definitions of some things which may be system-dependent
 */

#ifndef _KLIBC_SYSCONFIG_H
#define _KLIBC_SYSCONFIG_H

/*
 * Define this to obtain memory using sbrk() instead
 * of mmap().  This should make it friendlier on
 * non-MMU architectures.  This should become a
 * per-architecture configurable.
 */
#undef MALLOC_USING_SBRK

/*
 * This is the minimum chunk size we will ask the kernel for using
 * malloc(); this should be a multiple of the page size on all
 * architectures.
 */
#define MALLOC_CHUNK_SIZE	65536
#define MALLOC_CHUNK_MASK       (MALLOC_CHUNK_SIZE-1)

/*
 * This is the minimum alignment for the memory returned by sbrk().
 * It must be a power of 2.  If MALLOC_USING_SBRK is defined it should
 * be no smaller than the size of struct arena_header in malloc.h (4
 * pointers.)
 */
#define SBRK_ALIGNMENT		32

#endif /* _KLIBC_SYSCONFIG_H */
