/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* The header errno.h overrides strerror_r with strerror_r_gnu, hence we need to undef it here. */
#undef strerror_r

char* strerror_r_gnu(int errnum, char *buf, size_t buflen) {
        int saved_errno = errno;
        const char *msg = strerror(errnum);
        size_t l = strlen(msg);
        if (l >= buflen) {
                if (buflen > 0) {
                        if (buflen > 1)
                                memcpy(buf, msg, buflen - 1);
                        buf[buflen - 1] = '\0';
                }
                errno = ERANGE;
        } else {
                memcpy(buf, msg, l + 1);
                errno = saved_errno;
        }
        return buf;
}
