/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <malloc.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

#include "alloc-util.h"
#include "macro.h"

size_t page_size(void) _pure_;
#define PAGE_ALIGN(l) ALIGN_TO((l), page_size())
#define PAGE_ALIGN_DOWN(l) ((l) & ~(page_size() - 1))
#define PAGE_OFFSET(l) ((l) & (page_size() - 1))

/* Normal memcpy() requires src to be nonnull. We do nothing if n is 0. */
static inline void *memcpy_safe(void *dst, const void *src, size_t n) {
        if (n == 0)
                return dst;
        assert(src);
        return memcpy(dst, src, n);
}

/* Normal mempcpy() requires src to be nonnull. We do nothing if n is 0. */
static inline void *mempcpy_safe(void *dst, const void *src, size_t n) {
        if (n == 0)
                return dst;
        assert(src);
        return mempcpy(dst, src, n);
}

/* Normal memcmp() requires s1 and s2 to be nonnull. We do nothing if n is 0. */
static inline int memcmp_safe(const void *s1, const void *s2, size_t n) {
        if (n == 0)
                return 0;
        assert(s1);
        assert(s2);
        return memcmp(s1, s2, n);
}

/* Compare s1 (length n1) with s2 (length n2) in lexicographic order. */
static inline int memcmp_nn(const void *s1, size_t n1, const void *s2, size_t n2) {
        return memcmp_safe(s1, s2, MIN(n1, n2))
            ?: CMP(n1, n2);
}

#define memzero(x,l)                                            \
        ({                                                      \
                size_t _l_ = (l);                               \
                if (_l_ > 0)                                    \
                        memset(x, 0, _l_);                      \
        })

#define zero(x) (memzero(&(x), sizeof(x)))

bool memeqbyte(uint8_t byte, const void *data, size_t length);

#define memeqzero(data, length) memeqbyte(0x00, data, length)

#define eqzero(x) memeqzero(x, sizeof(x))

static inline void *mempset(void *s, int c, size_t n) {
        memset(s, c, n);
        return (uint8_t*)s + n;
}

/* Normal memmem() requires haystack to be nonnull, which is annoying for zero-length buffers */
static inline void *memmem_safe(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {

        if (needlelen <= 0)
                return (void*) haystack;

        if (haystacklen < needlelen)
                return NULL;

        assert(haystack);
        assert(needle);

        return memmem(haystack, haystacklen, needle, needlelen);
}

static inline void *mempmem_safe(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
        const uint8_t *p;

        p = memmem_safe(haystack, haystacklen, needle, needlelen);
        if (!p)
                return NULL;

        return (uint8_t*) p + needlelen;
}

#if HAVE_EXPLICIT_BZERO
static inline void* explicit_bzero_safe(void *p, size_t l) {
        if (l > 0)
                explicit_bzero(p, l);

        return p;
}
#else
void *explicit_bzero_safe(void *p, size_t l);
#endif

static inline void* erase_and_free(void *p) {
        size_t l;

        if (!p)
                return NULL;

        l = MALLOC_SIZEOF_SAFE(p);
        explicit_bzero_safe(p, l);
        return mfree(p);
}

static inline void erase_and_freep(void *p) {
        erase_and_free(*(void**) p);
}

/* Use with _cleanup_ to erase a single 'char' when leaving scope */
static inline void erase_char(char *p) {
        explicit_bzero_safe(p, sizeof(char));
}
