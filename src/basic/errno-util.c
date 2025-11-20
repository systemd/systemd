/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"

const char* strerror_or_eof(int errnum, char *buf, size_t buflen) {
        if (errnum != 0)
                return strerror_r(ABS(errnum), buf, buflen);

        return "Unexpected EOF";
}
