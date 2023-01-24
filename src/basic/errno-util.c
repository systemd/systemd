/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "strxcpyx.h"

char* strerror_r_gnu(int errnum, char *buf, size_t buflen) {
#ifdef __GLIBC__
        return strerror_r(errnum, buf, buflen);
#else
        if (strerror_r(errnum, buf, buflen) == 0)
                return buf;

        strscpy(buf, buflen, "unknown error");
        return buf;
#endif
}
