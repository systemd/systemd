/*
 * sys/mman.h
 */

#ifndef _SYS_MMAN_H
#define _SYS_MMAN_H

#include <klibc/extern.h>
#include <sys/types.h>
#include <asm/mman.h>
#include <asm/page.h>		/* For PAGE_SIZE */

#define MAP_FAILED ((void *)-1)

__extern void *mmap(void *, size_t, int, int, int, off_t);
__extern int munmap(void *, size_t);
__extern void *mremap(void *, size_t, size_t, unsigned long);
__extern int msync(const void *, size_t, int);
__extern int mprotect(const void *, size_t, int);
__extern int mlockall(int);
__extern int munlockall(void);
__extern int mlock(const void *, size_t);
__extern int munlock(const void *, size_t);

#endif /* _SYS_MMAN_H */
