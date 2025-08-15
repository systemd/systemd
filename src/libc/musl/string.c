/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <string.h>

/* The header errno.h overrides strerror_r with strerror_r_gnu, hence we need to undef it here. */
#undef strerror_r

char* strerror_r_gnu(int errnum, char *buf, size_t buflen) {
        /* The XSI-compliant strerror_r() function returns 0 on success. On error, a (positive) error number
         * is returned (since glibc 2.13), or -1 is returned and errno is set to indicate the error (before
         * glibc 2.13).
         *
         * We always define _GNU_SOURCE, hence the code below is for musl, but let's anyway assume nonzero
         * return value indicates an error. */
        if (strerror_r(errnum, buf, buflen) != 0)
                snprintf(buf, buflen, "unknown error: %i", errnum);

        return buf;
}
