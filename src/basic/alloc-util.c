/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdbool.h>
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

        ret = malloc(l + 1);
        if (!ret)
                return NULL;

        *((uint8_t*) mempcpy(ret, p, l)) = 0;
        return ret;
}

static void* greedy_realloc_internal(void **p, size_t *allocated, size_t need, size_t size, bool greedy) {
        size_t a, newalloc;
        void *q;

        assert(p);
        assert(allocated);

        if (*allocated >= need)
                return *p;

        newalloc = MAX(greedy ? need * 2 : need, 64u / size);
        a = newalloc * size;

        /* check for overflows */
        if (a < size * need)
                return NULL;

        q = realloc(*p, a);
        if (!q)
                return NULL;

        *p = q;
        *allocated = newalloc;
        return q;
}

static void* greedy_realloc0_internal(void **p, size_t *allocated, size_t need, size_t size, bool greedy) {
        size_t prev;
        uint8_t *q;

        assert(p);
        assert(allocated);

        prev = *allocated;

        q = greedy_realloc_internal(p, allocated, need, size, greedy);
        if (!q)
                return NULL;

        if (*allocated > prev)
                memzero(q + prev * size, (*allocated - prev) * size);

        return q;
}

void* lazy_realloc(void **p, size_t *allocated, size_t need, size_t size) {
        return greedy_realloc_internal(p, allocated, need, size, false);
}

void* lazy_realloc0(void **p, size_t *allocated, size_t need, size_t size) {
        return greedy_realloc0_internal(p, allocated, need, size, false);
}

void* greedy_realloc(void **p, size_t *allocated, size_t need, size_t size) {
        return greedy_realloc_internal(p, allocated, need, size, true);
}

void* greedy_realloc0(void **p, size_t *allocated, size_t need, size_t size) {
        return greedy_realloc0_internal(p, allocated, need, size, true);
}
