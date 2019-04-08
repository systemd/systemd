/* SPDX-License-Identifier: LGPL-2.1+ */

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

        memcpy(ret, p, l);
        return ret;
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

        *((uint8_t*) mempcpy(ret, p, l)) = 0;
        return ret;
}

void* greedy_realloc(void **p, size_t *allocated, size_t need, size_t size) {
        size_t a, newalloc;
        void *q;

        assert(p);
        assert(allocated);

        if (*allocated >= need)
                return *p;

        if (_unlikely_(need > SIZE_MAX/2)) /* Overflow check */
                return NULL;

        newalloc = need * 2;
        if (size_multiply_overflow(newalloc, size))
                return NULL;

        a = newalloc * size;
        if (a < 64) /* Allocate at least 64 bytes */
                a = 64;

        q = realloc(*p, a);
        if (!q)
                return NULL;

        *p = q;
        *allocated = _unlikely_(size == 0) ? newalloc : malloc_usable_size(q) / size;
        return q;
}

void* greedy_realloc0(void **p, size_t *allocated, size_t need, size_t size) {
        size_t prev;
        uint8_t *q;

        assert(p);
        assert(allocated);

        prev = *allocated;

        q = greedy_realloc(p, allocated, need, size);
        if (!q)
                return NULL;

        if (*allocated > prev)
                memzero(q + prev * size, (*allocated - prev) * size);

        return q;
}
