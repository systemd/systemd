/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "keyring-util.h"
#include "memory-util.h"
#include "missing_syscall.h"

int keyring_read(key_serial_t serial, void **ret, size_t *ret_size) {
        size_t m = 100;

        for (;;) {
                _cleanup_(erase_and_freep) uint8_t *p = NULL;
                long n;

                p = new(uint8_t, m+1);
                if (!p)
                        return -ENOMEM;

                n = keyctl(KEYCTL_READ, (unsigned long) serial, (unsigned long) p, (unsigned long) m, 0);
                if (n < 0)
                        return -errno;

                if ((size_t) n <= m) {
                        p[n] = 0; /* NUL terminate, just in case */

                        if (ret)
                                *ret = TAKE_PTR(p);
                        if (ret_size)
                                *ret_size = n;

                        return 0;
                }

                if (m > (SIZE_MAX-1) / 2) /* overflow check */
                        return -ENOMEM;

                m *= 2;
        }
}
