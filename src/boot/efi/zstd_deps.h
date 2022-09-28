/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if !defined(ZSTD_DEPS_COMMON)
#  define ZSTD_DEPS_COMMON
#  define ZSTD_memcpy __builtin_memcpy
#  define ZSTD_memmove __builtin_memmove
#  define ZSTD_memset __builtin_memset
#  define memcpy __builtin_memcpy
#  define memmove __builtin_memmove
#  define memset __builtin_memset
#endif

#if defined(ZSTD_DEPS_NEED_MALLOC) && !defined(ZSTD_DEPS_MALLOC)
#  define ZSTD_DEPS_MALLOC
#  include <efi.h>
#  include <efilib.h>
#  include <stddef.h>

static inline void *ZSTD_malloc(size_t size) {
        void *p = NULL;
        BS->AllocatePool(EfiBootServicesData, size, &p);
        return p;
}

static inline void *ZSTD_calloc(size_t n, size_t size) {
        if (__builtin_mul_overflow(n, size, &size))
                return NULL;

        void *p = ZSTD_malloc(size);
        if (p)
                memset(p, 0, size);
        return p;
}

static inline void ZSTD_free(void *p) {
        if (p)
                BS->FreePool(p);
}
#endif

#if defined(ZSTD_DEPS_NEED_MATH64) && !defined(ZSTD_DEPS_MATH64)
#  define ZSTD_DEPS_MATH64
#  define ZSTD_div64(dividend, divisor) ((dividend) / (divisor))
#endif
