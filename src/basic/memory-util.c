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

bool memeqzero(const void *data, size_t length) {
        /* Does the buffer consist entirely of NULs?
         * Copied from https://github.com/systemd/casync/, copied in turn from
         * https://github.com/rustyrussell/ccan/blob/master/ccan/mem/mem.c#L92,
         * which is licensed CC-0.
         */

        const uint8_t *p = data;
        size_t i;

        /* Check first 16 bytes manually */
        for (i = 0; i < 16; i++, length--) {
                if (length == 0)
                        return true;
                if (p[i])
                        return false;
        }

        /* Now we know first 16 bytes are NUL, memcmp with self.  */
        return memcmp(data, p + i, length) == 0;
}
