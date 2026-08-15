/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/keyctl.h>

#include "libc-shim.h"

DEFINE_SYSCALL_SHIM(keyctl, long,
                    int, cmd,
                    unsigned long, arg2,
                    unsigned long, arg3,
                    unsigned long, arg4,
                    unsigned long, arg5)

DEFINE_SYSCALL_SHIM(add_key, key_serial_t,
                    const char *, type,
                    const char *, description,
                    const void *, payload,
                    size_t, plen,
                    key_serial_t, ringid)

DEFINE_SYSCALL_SHIM(request_key, key_serial_t,
                    const char *, type,
                    const char *, description,
                    const char *, callout_info,
                    key_serial_t, destringid)
