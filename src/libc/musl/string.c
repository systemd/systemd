/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* MAX_ERRNO is defined as 4095 in linux/err.h. We use the same value here. */
#define ERRNO_MAX               4095

/* strerror(3) says that glibc uses a maximum length of 1024 bytes. */
#define ERRNO_BUF_LEN           1024

/* The header string.h overrides strerror_r with strerror_r_gnu, hence we need to undef it here. */
#undef strerror_r

char* strerror_r_gnu(int errnum, char *buf, size_t buflen) {
        /* musl provides spurious catchall error message "No error information" for unknown errno
         * (including errno == 0). Let's patch it to glibc style. */

        if (errnum == 0)
                return (char*) "Success";

        if (buflen == 0)
                return (char*) "Unknown error";

        if (errnum < 0 || errnum > ERRNO_MAX)
                goto fallback;

        if (strerror_r(errnum, buf, buflen) != 0)
                goto fallback;

        char buf_0[ERRNO_BUF_LEN];
        if (strerror_r(0, buf_0, sizeof buf_0) != 0) /* Wut?? */
                goto fallback;

        /* strerror_r() may truncate the result. In that case, let's not compare the trailing NUL. */
        size_t n = (buflen < ERRNO_BUF_LEN ? buflen : ERRNO_BUF_LEN) - 1;
        if (strncmp(buf, buf_0, n) != 0)
                return buf;

fallback:
        snprintf(buf, buflen, "Unknown error %i", errnum);
        return buf;
}
