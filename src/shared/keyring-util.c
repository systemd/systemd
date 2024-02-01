/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "keyring-util.h"
#include "memory-util.h"
#include "missing_syscall.h"

int keyring_read(key_serial_t serial, void **ret, size_t *ret_size) {
        long bufsize;

        /* Get the size of the key by passing in a NULL buffer */
        bufsize = keyctl(KEYCTL_READ, (unsigned long) serial, (unsigned long) NULL, 0, 0);
        if (bufsize < 0)
                return -errno;

        for (;;) {
                _cleanup_(erase_and_freep) uint8_t *buf = NULL;
                long n;

                buf = new(uint8_t, bufsize + 1);
                if (!buf)
                        return -ENOMEM;

                n = keyctl(KEYCTL_READ, (unsigned long) serial, (unsigned long) buf, (unsigned long) bufsize, 0);
                if (n < 0)
                        return -errno;

                if (n <= bufsize) {
                        p[n] = 0; /* NUL terminate, just in case */

                        if (ret)
                                *ret = TAKE_PTR(p);
                        if (ret_size)
                                *ret_size = n;

                        return 0;
                }

                /* If we reach this point, the key must have gotten bigger between our
                 * initial size query and our actual read. n is holding the new size,
                 * so we should try again with it. */
                bufsize = n;
        }
}
