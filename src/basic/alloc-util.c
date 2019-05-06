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

        if (size > 0) {
                size_t bn;

                /* Adjust for the 64 byte minimum */
                newalloc = a / size;

                bn = malloc_usable_size(q) / size;
                if (bn > newalloc) {
                        void *qq;

                        /* The actual size allocated is larger than what we asked for. Let's call realloc() again to
                         * take possession of the extra space. This should be cheap, since libc doesn't have to move
                         * the memory for this. */

                        qq = realloc(q, bn * size);
                        if (_likely_(qq)) {
                                *p = qq;
                                *allocated = bn;
                                return qq;
                        }
                }
        }

        *p = q;
        *allocated = newalloc;
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
