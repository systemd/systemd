/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

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

bool memeqbyte(uint8_t byte, const void *data, size_t length) {
        /* Does the buffer consist entirely of the same specific byte value?
         * Copied from https://github.com/systemd/casync/, copied in turn from
         * https://github.com/rustyrussell/ccan/blob/master/ccan/mem/mem.c#L92,
         * which is licensed CC-0.
         */

        const uint8_t *p = data;

        /* Check first 16 bytes manually */
        for (size_t i = 0; i < 16; i++, length--) {
                if (length == 0)
                        return true;
                if (p[i] != byte)
                        return false;
        }

        /* Now we know first 16 bytes match, memcmp() with self.  */
        return memcmp(data, p + 16, length) == 0;
}

#if !HAVE_EXPLICIT_BZERO
/*
 * The pointer to memset() is volatile so that compiler must de-reference the pointer and can't assume that
 * it points to any function in particular (such as memset(), which it then might further "optimize"). This
 * approach is inspired by openssl's crypto/mem_clr.c.
 */
typedef void *(*memset_t)(void *,int,size_t);

static volatile memset_t memset_func = memset;

void* explicit_bzero_safe(void *p, size_t l) {
        if (l > 0)
                memset_func(p, '\0', l);

        return p;
}
#endif
