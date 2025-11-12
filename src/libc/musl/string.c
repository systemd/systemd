/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* The header string.h overrides strerror_r with strerror_r_gnu, hence we need to undef it here. */
#undef strerror_r

char* strerror_r_gnu(int errnum, char *buf, size_t buflen) {
        static const char *strerror_unknown = NULL;
        int saved_errno = errno;

        /* musl provides spurious catchall error message "No error information" for unknown errno
         * (including errno == 0). Let's patch it to glibc style. */
        if (!strerror_unknown)
                strerror_unknown = strerror(0);

        const char *s = strerror(errnum);
        if (s == strerror_unknown) {
                if (errnum == 0)
                        snprintf(buf, buflen, "Success");
                else
                        snprintf(buf, buflen, "Unknown error %i", errnum);
                s = buf;
        }

        errno = saved_errno;
        return (char*) s;
}
