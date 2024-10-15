/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <malloc.h>
#include <stdint.h>
#include <string.h>

#include "alloc-util.h"
#include "macro.h"
#include "memory-util.h"

void* memdup(const void *p, size_t l) {
        void *ret;

        assert(l == 0 || p);

        ret = malloc(l ?: 1);
        if (!ret)
                return NULL;

        return memcpy_safe(ret, p, l);
}

void* memdup_suffix0(const void *p, size_t l) {
        void *ret;

        assert(l == 0 || p);

        /* The same as memdup() but place a safety NUL byte after the allocated memory */

        if (_unlikely_(l == SIZE_MAX)) /* prevent overflow */
                return NULL;

        ret = malloc(l + 1);
        if (!ret)
                return NULL;

        ((uint8_t*) ret)[l] = 0;
        return memcpy_safe(ret, p, l);
}

void* greedy_realloc(
                void **p,
                size_t need,
                size_t size) {

        size_t newalloc;
        void *q;

        assert(p);

        /* We use malloc_usable_size() for determining the current allocated size. On all systems we care
         * about this should be safe to rely on. Should there ever arise the need to avoid relying on this we
         * can instead locally fall back to realloc() on every call, rounded up to the next exponent of 2 or
         * so. */

        if (*p && (size == 0 || (MALLOC_SIZEOF_SAFE(*p) / size >= need)))
                return *p;

        if (_unlikely_(need > SIZE_MAX/2)) /* Overflow check */
                return NULL;
        newalloc = need * 2;

        if (!MUL_ASSIGN_SAFE(&newalloc, size))
                return NULL;

        if (newalloc < 64) /* Allocate at least 64 bytes */
                newalloc = 64;

        q = realloc(*p, newalloc);
        if (!q)
                return NULL;

        return *p = q;
}

void* greedy_realloc0(
                void **p,
                size_t need,
                size_t size) {

        size_t before, after;
        uint8_t *q;

        assert(p);

        before = MALLOC_SIZEOF_SAFE(*p); /* malloc_usable_size() will return 0 on NULL input, as per docs */

        q = greedy_realloc(p, need, size);
        if (!q)
                return NULL;

        after = MALLOC_SIZEOF_SAFE(q);

        if (size == 0) /* avoid division by zero */
                before = 0;
        else
                before = (before / size) * size; /* Round down */

        if (after > before)
                memzero(q + before, after - before);

        return q;
}

void* greedy_realloc_append(
                void **p,
                size_t *n_p,
                const void *from,
                size_t n_from,
                size_t size) {

        uint8_t *q;

        assert(p);
        assert(n_p);
        assert(from || n_from == 0);

        if (n_from > SIZE_MAX - *n_p)
                return NULL;

        q = greedy_realloc(p, *n_p + n_from, size);
        if (!q)
                return NULL;

        memcpy_safe(q + *n_p * size, from, n_from * size);

        *n_p += n_from;

        return q;
}

void *expand_to_usable(void *ptr, size_t newsize _unused_) {
        return ptr;
}
