/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/keyctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef keyctl
extern typeof(keyctl_shim) keyctl __attribute__((weak));
long keyctl_shim(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
        if (keyctl)
                return keyctl(cmd, arg2, arg3, arg4, arg5);
        return syscall(__NR_keyctl, cmd, arg2, arg3, arg4, arg5);
}

#undef add_key
extern typeof(add_key_shim) add_key __attribute__((weak));
key_serial_t add_key_shim(const char *type, const char *description, const void *payload, size_t plen, key_serial_t ringid) {
        if (add_key)
                return add_key(type, description, payload, plen, ringid);
        return syscall(__NR_add_key, type, description, payload, plen, ringid);
}

#undef request_key
extern typeof(request_key_shim) request_key __attribute__((weak));
key_serial_t request_key_shim(const char *type, const char *description, const char *callout_info, key_serial_t destringid) {
        if (request_key)
                return request_key(type, description, callout_info, destringid);
        return syscall(__NR_request_key, type, description, callout_info, destringid);
}
