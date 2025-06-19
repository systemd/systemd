/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/syscall.h>
#include <unistd.h>

#include "alloc-util.h"
#include "keyctl-util.h"
#include "log.h"

#if !HAVE_KEYCTL
long keyctl(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
        return syscall(__NR_keyctl, cmd, arg2, arg3, arg4, arg5);
}
#endif

#if !HAVE_ADD_KEY
key_serial_t add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t ringid) {
        return syscall(__NR_add_key, type, description, payload, plen, ringid);
}
#endif

#if !HAVE_REQUEST_KEY
key_serial_t request_key(const char *type, const char *description, const char *callout_info, key_serial_t destringid) {
        return syscall(__NR_request_key, type, description, callout_info, destringid);
}
#endif

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

int keyring_describe(key_serial_t serial, char **ret) {
        _cleanup_free_ char *tuple = NULL;
        size_t sz = 64;
        int c = -1; /* Workaround for maybe-uninitialized false positive due to missing_syscall indirection */

        assert(ret);

        for (;;) {
                tuple = new(char, sz);
                if (!tuple)
                        return log_oom_debug();

                c = keyctl(KEYCTL_DESCRIBE, serial, (unsigned long) tuple, c, 0);
                if (c < 0)
                        return log_debug_errno(errno, "Failed to describe key id %d: %m", serial);

                if ((size_t) c <= sz)
                        break;

                sz = c;
                free(tuple);
        }

        /* The kernel returns a final NUL in the string, verify that. */
        assert(tuple[c-1] == 0);

        *ret = TAKE_PTR(tuple);

        return 0;
}
