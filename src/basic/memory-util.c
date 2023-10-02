/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "memory-util.h"
#include "missing_threads.h"

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

void *make_swapped(const void *data, size_t size) {
        assert(data);
        assert(size != 0);

        void *p = malloc(size);
        if (!p)
                return NULL;

        uint8_t *p_dst = p;
        const uint8_t *p_src = data;
        for (size_t i = 0, k = size - 1; i < size; i++, k--)
                p_dst[i] = p_src[k];

        return p;
}
