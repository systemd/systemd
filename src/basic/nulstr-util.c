/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nulstr-util.h"
#include "string-util.h"

const char* nulstr_get(const char *nulstr, const char *needle) {
        const char *i;

        if (!nulstr)
                return NULL;

        NULSTR_FOREACH(i, nulstr)
                if (streq(i, needle))
                        return i;

        return NULL;
}
