/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* The header string.h overrides strerror_r with strerror_r_gnu, hence we need to undef it here. */
#undef strerror_r

char* strerror_r_gnu(int errnum, char *buf, size_t buflen) {
        int saved_errno = errno;
        const char *ret;

        /* musl provides spurious catchall error message "No error information" for unknown errno
         * (including errno == 0). Let's patch it to glibc style. */

        if (errnum == 0) {
                ret = "Success";
                goto finalize;
        }

        ret = strerror(errnum);
        if (ret != strerror(0)) /* Yay, we got something unique. */
                goto finalize;

        char numbuf[32];
        snprintf(numbuf, sizeof numbuf, "%i", errnum);
        size_t numlen = strlen(numbuf);

        const char *prefix = "Unknown error";
        size_t prefixlen = strlen(prefix);

        if (buflen < numlen + 1) {
                /* Too small buffer and we cannot even store the error number. */
                ret = prefix;
                goto finalize;
        }

        /* Otherwise, use the provided buffer. */

        char *p;
        if (buflen <= numlen + 2)
                /* We can only store the number. Note, let's not make the string start with space. */
                p = buf;

        else if (buflen < numlen + 2 + prefixlen) {
                /* Truncate prefix. E.g. "Unk 123" */
                p = mempcpy(buf, prefix, buflen - numlen - 2);
                *p++ = ' ';

        } else {
                /* We can store whole message. E.g. "Unknown error 123" */
                p = mempcpy(buf, prefix, prefixlen);
                *p++ = ' ';
        }

        memcpy(p, numbuf, numlen + 1);
        ret = buf;

finalize:
        errno = saved_errno;
        return (char*) ret;
}
