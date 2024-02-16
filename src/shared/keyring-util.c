/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "keyring-util.h"
#include "memory-util.h"
#include "missing_syscall.h"

int keyring_read(key_serial_t serial, void **ret, size_t *ret_size) {
        size_t bufsize = 100;

        for (;;) {
                _cleanup_(erase_and_freep) uint8_t *buf = NULL;
                long n;

                buf = new(uint8_t, bufsize + 1);
                if (!buf)
                        return -ENOMEM;

                n = keyctl(KEYCTL_READ, (unsigned long) serial, (unsigned long) buf, (unsigned long) bufsize, 0);
                if (n < 0)
                        return -errno;

                if ((size_t) n <= bufsize) {
                        buf[n] = 0; /* NUL terminate, just in case */

                        if (ret)
                                *ret = TAKE_PTR(buf);
                        if (ret_size)
                                *ret_size = n;

                        return 0;
                }

                bufsize = (size_t) n;
        }
}
