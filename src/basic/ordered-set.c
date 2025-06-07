/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fileio.h"
#include "ordered-set.h"
#include "strv.h"

int ordered_set_ensure_allocated(OrderedSet **s, const struct hash_ops *ops) {
        if (*s)
                return 0;

        *s = ordered_set_new(ops);
        if (!*s)
                return -ENOMEM;

        return 0;
}

int ordered_set_ensure_put(OrderedSet **s, const struct hash_ops *ops, void *p) {
        int r;

        r = ordered_set_ensure_allocated(s, ops);
        if (r < 0)
                return r;

        return ordered_set_put(*s, p);
}

int ordered_set_consume(OrderedSet *s, void *p) {
        int r;

        r = ordered_set_put(s, p);
        if (r <= 0)
                free(p);

        return r;
}

int ordered_set_put_strdup(OrderedSet **s, const char *p) {
        char *c;
        int r;

        assert(s);
        assert(p);

        r = ordered_set_ensure_allocated(s, &string_hash_ops_free);
        if (r < 0)
                return r;

        if (ordered_set_contains(*s, p))
                return 0;

        c = strdup(p);
        if (!c)
                return -ENOMEM;

        return ordered_set_consume(*s, c);
}

int ordered_set_put_strdupv(OrderedSet **s, char **l) {
        int n = 0, r;

        STRV_FOREACH(i, l) {
                r = ordered_set_put_strdup(s, *i);
                if (r < 0)
                        return r;

                n += r;
        }

        return n;
}

int ordered_set_put_string_set(OrderedSet **s, OrderedSet *l) {
        int n = 0, r;
        char *p;

        /* Like ordered_set_put_strv, but for an OrderedSet of strings */

        ORDERED_SET_FOREACH(p, l) {
                r = ordered_set_put_strdup(s, p);
                if (r < 0)
                        return r;

                n += r;
        }

        return n;
}

void ordered_set_print(FILE *f, const char *field, OrderedSet *s) {
        bool space = false;
        char *p;

        assert(f);
        assert(field);

        if (ordered_set_isempty(s))
                return;

        fputs(field, f);

        ORDERED_SET_FOREACH(p, s)
                fputs_with_separator(f, p, NULL, &space);

        fputc('\n', f);
}
