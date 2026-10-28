/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "strv.h"

sd_char* strv_find(sd_char * const *l, const sd_char *name) {
        assert(name);

        STRV_FOREACH(i, l)
                if (streq(*i, name))
                        return *i;

        return NULL;
}
