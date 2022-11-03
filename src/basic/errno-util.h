/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdlib.h>
#include <string.h>

#include "macro.h"

/* strerror(3) says that glibc uses a maximum length of 1024 bytes. */
#define ERRNO_BUF_LEN 1024

/* Note: the lifetime of the compound literal is the immediately surrounding block,
 * see C11 §6.5.2.5, and
 * https://stackoverflow.com/questions/34880638/compound-literal-lifetime-and-if-blocks
 *
 * Note that we use the GNU variant of strerror_r() here. */
#define STRERROR(errnum) strerror_r(abs(errnum), (char[ERRNO_BUF_LEN]){}, ERRNO_BUF_LEN)

/* A helper to print an error message or message for functions that return 0 on EOF.
 * Note that we can't use ({ … }) to define a temporary variable, so errnum is
 * evaluated twice. */
#define STRERROR_OR_EOF(errnum) ((errnum) != 0 ? STRERROR(errnum) : "Unexpected EOF")

static inline void _reset_errno_(int *saved_errno) {
        if (*saved_errno < 0) /* Invalidated by UNPROTECT_ERRNO? */
                return;

        errno = *saved_errno;
}

#define PROTECT_ERRNO                           \
        _cleanup_(_reset_errno_) _unused_ int _saved_errno_ = errno

#define UNPROTECT_ERRNO                         \
        do {                                    \
                errno = _saved_errno_;          \
                _saved_errno_ = -1;             \
        } while (false)

#define LOCAL_ERRNO(value)                      \
        PROTECT_ERRNO;                          \
        errno = abs(value)

static inline int negative_errno(void) {
        /* This helper should be used to shut up gcc if you know 'errno' is
         * negative. Instead of "return -errno;", use "return negative_errno();"
         * It will suppress bogus gcc warnings in case it assumes 'errno' might
         * be 0 and thus the caller's error-handling might not be triggered. */
        assert_return(errno > 0, -EINVAL);
        return -errno;
}

static inline int RET_NERRNO(int ret) {

        /* Helper to wrap system calls in to make them return negative errno errors. This brings system call
         * error handling in sync with how we usually handle errors in our own code, i.e. with immediate
         * returning of negative errno. Usage is like this:
         *
         *     …
         *     r = RET_NERRNO(unlink(t));
         *     …
         *
         * or
         *
         *     …
         *     fd = RET_NERRNO(open("/etc/fstab", O_RDONLY|O_CLOEXEC));
         *     …
         */

        if (ret < 0)
                return negative_errno();

        return ret;
}

static inline int errno_or_else(int fallback) {
        /* To be used when invoking library calls where errno handling is not defined clearly: we return
         * errno if it is set, and the specified error otherwise. The idea is that the caller initializes
         * errno to zero before doing an API call, and then uses this helper to retrieve a somewhat useful
         * error code */
        if (errno > 0)
                return -errno;

        return -abs(fallback);
}

/* For send()/recv() or read()/write(). */
static inline bool ERRNO_IS_TRANSIENT(int r) {
        return IN_SET(abs(r),
                      EAGAIN,
                      EINTR);
}

/* Hint #1: ENETUNREACH happens if we try to connect to "non-existing" special IP addresses, such as ::5.
 *
 * Hint #2: The kernel sends e.g., EHOSTUNREACH or ENONET to userspace in some ICMP error cases.  See the
 *          icmp_err_convert[] in net/ipv4/icmp.c in the kernel sources.
 *
 * Hint #3: When asynchronous connect() on TCP fails because the host never acknowledges a single packet,
 *          kernel tells us that with ETIMEDOUT, see tcp(7). */
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
                      ESHUTDOWN,
                      ETIMEDOUT);
}

/* Transient errors we might get on accept() that we should ignore. As per error handling comment in
 * the accept(2) man page. */
static inline bool ERRNO_IS_ACCEPT_AGAIN(int r) {
        return ERRNO_IS_DISCONNECT(r) ||
                ERRNO_IS_TRANSIENT(r) ||
                abs(r) == EOPNOTSUPP;
}

/* Resource exhaustion, could be our fault or general system trouble */
static inline bool ERRNO_IS_RESOURCE(int r) {
        return IN_SET(abs(r),
                      EMFILE,
                      ENFILE,
                      ENOMEM);
}

/* Seven different errors for "operation/system call/ioctl/socket feature not supported" */
static inline bool ERRNO_IS_NOT_SUPPORTED(int r) {
        return IN_SET(abs(r),
                      EOPNOTSUPP,
                      ENOTTY,
                      ENOSYS,
                      EAFNOSUPPORT,
                      EPFNOSUPPORT,
                      EPROTONOSUPPORT,
                      ESOCKTNOSUPPORT);
}

/* Two different errors for access problems */
static inline bool ERRNO_IS_PRIVILEGE(int r) {
        return IN_SET(abs(r),
                      EACCES,
                      EPERM);
}

/* Three different errors for "not enough disk space" */
static inline bool ERRNO_IS_DISK_SPACE(int r) {
        return IN_SET(abs(r),
                      ENOSPC,
                      EDQUOT,
                      EFBIG);
}

/* Three different errors for "this device does not quite exist" */
static inline bool ERRNO_IS_DEVICE_ABSENT(int r) {
        return IN_SET(abs(r),
                      ENODEV,
                      ENXIO,
                      ENOENT);
}

/* Quite often we want to handle cases where the backing FS doesn't support extended attributes at all and
 * where it simply doesn't have the requested xattr the same way */
static inline bool ERRNO_IS_XATTR_ABSENT(int r) {
        return abs(r) == ENODATA ||
                ERRNO_IS_NOT_SUPPORTED(r);
}
