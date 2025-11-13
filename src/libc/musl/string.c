/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* The header string.h overrides strerror_r with strerror_r_gnu, hence we need to undef it here. */
#undef strerror_r

/* See errno-util.h */
#define ERRNO_BUF_LEN           1024U
/* See basic-forward.h */
#define ERRNO_MAX               4095

char* strerror_r_gnu(int errnum, char *buf, size_t buflen) {
        int saved_errno = errno;
        char *ret = buf, buf_0[ERRNO_BUF_LEN];

        /* musl provides spurious catchall error message "No error information" for unknown errno
         * (including errno == 0). Let's patch it to glibc style. */

        if (errnum <= 0 || errnum > ERRNO_MAX)
                goto override;

        if (strerror_r(errnum, buf, buflen) != 0)
                goto override;

        /* Get (possibly localized version of) "No error information" */
        if (strerror_r(0, buf_0, ERRNO_BUF_LEN) != 0)
                goto override;

        if (strncmp(buf, buf_0, buflen < ERRNO_BUF_LEN ? buflen : ERRNO_BUF_LEN) != 0)
                goto finalize; /* We got something unique. */

override:
        if (errnum == 0)
                ret = (char*) "Success";
        else
                snprintf(buf, buflen, "Unknown error %i", errnum);

finalize:
        errno = saved_errno;
        return ret;
}
