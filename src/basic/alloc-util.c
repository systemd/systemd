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
        size_t a, new_need;
        void *q;

        assert(p);
        assert(allocated);

        /* In these 3 following cases return the current pointer and do not update allocated size:
         *  - There is already enough allocated space
         *  - The number of element (need) is 0
         *  - The size of "object" is equal to 0 */
        if (*allocated >= need || size == 0)
                return *p;

        /* Overflow check of: need * size * 2 */
        if (size_multiply_overflow(need, 2))
                return NULL;

        new_need = need * 2;
        if (size_multiply_overflow(size, new_need))
                return NULL;

        /* Allocate at least: 64 bytes or the current usable size of previously allocated buffer */
        a = MAX3(new_need * size, malloc_usable_size(*p), 64u);
        q = realloc(*p, a);
        if (!q)
                return NULL;

        *p = q;
        *allocated = a / size;
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
