/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/keyctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !HAVE_KEYCTL
long missing_keyctl(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
        return syscall(__NR_keyctl, cmd, arg2, arg3, arg4, arg5);
}
#endif

#if !HAVE_ADD_KEY
key_serial_t missing_add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t ringid) {
        return syscall(__NR_add_key, type, description, payload, plen, ringid);
}
#endif

#if !HAVE_REQUEST_KEY
key_serial_t missing_request_key(const char *type, const char *description, const char *callout_info, key_serial_t destringid) {
        return syscall(__NR_request_key, type, description, callout_info, destringid);
}
#endif
