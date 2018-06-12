/* SPDX-License-Identifier: LGPL-2.1+ */

#include "ordered-set.h"
#include "strv.h"

int ordered_set_consume(OrderedSet *s, void *p) {
        int r;

        r = ordered_set_put(s, p);
        if (r <= 0)
                free(p);

        return r;
}

int ordered_set_put_strdup(OrderedSet *s, const char *p) {
        char *c;
        int r;

        assert(s);
        assert(p);

        c = strdup(p);
        if (!c)
                return -ENOMEM;

        r = ordered_set_consume(s, c);
        if (r == -EEXIST)
                return 0;

        return r;
}

int ordered_set_put_strdupv(OrderedSet *s, char **l) {
        int n = 0, r;
        char **i;

        STRV_FOREACH(i, l) {
                r = ordered_set_put_strdup(s, *i);
                if (r < 0)
                        return r;

                n += r;
        }

        return n;
}
