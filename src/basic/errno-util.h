/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "macro.h"

static inline void _reset_errno_(int *saved_errno) {
        if (*saved_errno < 0) /* Invalidated by UNPROTECT_ERRNO? */
                return;

        errno = *saved_errno;
}

#define PROTECT_ERRNO                                                   \
        _cleanup_(_reset_errno_) _unused_ int _saved_errno_ = errno

#define UNPROTECT_ERRNO                         \
        do {                                    \
                errno = _saved_errno_;          \
                _saved_errno_ = -1;             \
        } while (false)

static inline int negative_errno(void) {
        /* This helper should be used to shut up gcc if you know 'errno' is
         * negative. Instead of "return -errno;", use "return negative_errno();"
         * It will suppress bogus gcc warnings in case it assumes 'errno' might
         * be 0 and thus the caller's error-handling might not be triggered. */
        assert_return(errno > 0, -EINVAL);
        return -errno;
}

/* Hint #1: ENETUNREACH happens if we try to connect to "non-existing" special IP addresses, such as ::5.
 *
 * Hint #2: The kernel sends e.g., EHOSTUNREACH or ENONET to userspace in some ICMP error cases.  See the
 *          icmp_err_convert[] in net/ipv4/icmp.c in the kernel sources */
static inline bool ERRNO_IS_DISCONNECT(int r) {
        return IN_SET(abs(r),
                      ECONNABORTED,
                      ECONNREFUSED,
                      ECONNRESET,
                      EHOSTDOWN,
                      EHOSTUNREACH,
                      ENETDOWN,
                      ENETRESET,
                      ENETUNREACH,
                      ENONET,
                      ENOPROTOOPT,
                      ENOTCONN,
                      EPIPE,
                      EPROTO,
                      ESHUTDOWN);
}

/* Transient errors we might get on accept() that we should ignore. As per error handling comment in
 * the accept(2) man page. */
static inline bool ERRNO_IS_ACCEPT_AGAIN(int r) {
        return ERRNO_IS_DISCONNECT(r) ||
                IN_SET(abs(r),
                       EAGAIN,
                       EINTR,
                       EOPNOTSUPP);
}

/* Resource exhaustion, could be our fault or general system trouble */
static inline bool ERRNO_IS_RESOURCE(int r) {
        return IN_SET(abs(r),
                      EMFILE,
                      ENFILE,
                      ENOMEM);
}
