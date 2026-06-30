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

void* erase_and_free(void *p) {
        size_t l;

        if (!p)
                return NULL;

        l = MALLOC_SIZEOF_SAFE(p);
        explicit_bzero_safe(p, l);
        return mfree(p);
}
