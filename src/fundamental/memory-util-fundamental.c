/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "memory-util-fundamental.h"

bool memeqbyte(uint8_t byte, const void *data, size_t length) {
        assert(data || length == 0);

        /* Does the buffer consist entirely of the same specific byte value?
         * Copied from https://github.com/systemd/casync/, copied in turn from
         * https://github.com/rustyrussell/ccan/blob/master/ccan/mem/mem.c#L92,
         * which is licensed CC-0.
         */

        const uint8_t *p = data;

        /* Check first 16 bytes manually */
        for (size_t i = 0; i < 16 && length > 0; i++, length--)
                if (p[i] != byte)
                        return false;

        if (length == 0)
                return true;

        /* Now we know first 16 bytes match, memcmp() with self.  */
        return memcmp(data, p + 16, length) == 0;
}
