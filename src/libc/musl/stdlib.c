/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

/* The header stdlib.h overrides strtoll with strtoll_fallback, hence we need to undef it here. */
#undef strtoll

long long strtoll_fallback(const char *nptr, char **endptr, int base) {
        /* glibc returns 0 if the first character is '.' without error, but musl returns as an error.
         * As our code assumes the glibc behavior, let's accept string starts with '.'. */
        if (nptr && *nptr == '.') {
                if (endptr)
                        *endptr = (char*) nptr;
                return 0;
        }

        /* Otherwise, use the native strtoll(). */
        return strtoll(nptr, endptr, base);
}
