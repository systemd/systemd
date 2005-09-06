/*
 * malloc.h
 *
 * Apparently people haven't caught on to use <stdlib.h>, which is the
 * standard place for this crap since the 1980's...
 */

#ifndef _MALLOC_H
#define _MALLOC_H

#include <klibc/extern.h>
#include <klibc/compiler.h>
#include <stddef.h>

__extern void free(void *);

__extern __mallocfunc void *malloc(size_t);
__extern __mallocfunc void *calloc(size_t, size_t);
__extern __mallocfunc void *realloc(void *, size_t);

#endif /* _MALLOC_H */
