/* SPDX-License-Identifier: LGPL-2.1+ */

#include "nulstr-util.h"
#include "string-util.h"

bool nulstr_contains(const char *nulstr, const char *needle) {
        const char *i;

        if (!nulstr)
                return false;

        NULSTR_FOREACH(i, nulstr)
                if (streq(i, needle))
                        return true;

        return false;
}
