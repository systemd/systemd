/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "strxcpyx.h"

char* strerror_r_gnu(int errnum, char *buf, size_t buflen) {
#ifdef __GLIBC__
        return strerror_r(errnum, buf, buflen);
#else
        /* The XSI-compliant strerror_r() function returns 0 on success.  On error, a (positive) error number
         * is returned (since glibc 2.13), or -1 is returned and errno is set to indicate the error (before
         * glibc 2.13).
         *
         * We always define _GNU_SOURCE, hence the code below is mostly for musl, but let's anyway assume
         * nonzero return value indicates an error. */
        if (strerror_r(errnum, buf, buflen) == 0)
                return buf;

        char *p = buf;
        strpcpyf(&p, buflen, "unknown error: %i", errnum);
        return buf;
#endif
}
