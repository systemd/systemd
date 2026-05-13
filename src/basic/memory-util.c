/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <threads.h>
#include <unistd.h>

#include "alloc-util.h"
#include "memory-util.h"

size_t page_size(void) {
        static thread_local size_t pgsz = 0;
        long r;

        if (_likely_(pgsz > 0))
                return pgsz;

        r = sysconf(_SC_PAGESIZE);
        assert(r > 0);

        pgsz = (size_t) r;
        return pgsz;
}

void* memdup_reverse(const void *mem, size_t size) {
        assert(mem);
        assert(size != 0);

        void *p = malloc(size);
        if (!p)
                return NULL;

        uint8_t *p_dst = p;
        const uint8_t *p_src = mem;
        for (size_t i = 0, k = size; i < size; i++, k--)
                p_dst[i] = p_src[k-1];

        return p;
}

void* erase_and_free(void *p) {
        size_t l;

        if (!p)
                return NULL;

        l = MALLOC_SIZEOF_SAFE(p);
        explicit_bzero_safe(p, l);
        return mfree(p);
}
