/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <string.h>

#include "macro.h"
#include "util.h"
#include "replace-var.h"
#include "def.h"

/*
 * Generic infrastructure for replacing @FOO@ style variables in
 * strings. Will call a callback for each replacement.
 */

static int get_variable(const char *b, char **r) {
        size_t k;
        char *t;

        assert(b);
        assert(r);

        if (*b != '@')
                return 0;

        k = strspn(b + 1, UPPERCASE_LETTERS "_");
        if (k <= 0 || b[k+1] != '@')
                return 0;

        t = strndup(b + 1, k);
        if (!t)
                return -ENOMEM;

        *r = t;
        return 1;
}

char *replace_var(const char *text, char *(*lookup)(const char *variable, void*userdata), void *userdata) {
        char *r, *t;
        const char *f;
        size_t l;

        assert(text);
        assert(lookup);

        l = strlen(text);
        r = new(char, l+1);
        if (!r)
                return NULL;

        f = text;
        t = r;
        while (*f) {
                _cleanup_free_ char *v = NULL, *n = NULL;
                char *a;
                int k;
                size_t skip, d, nl;

                k = get_variable(f, &v);
                if (k < 0)
                        goto oom;
                if (k == 0) {
                        *(t++) = *(f++);
                        continue;
                }

                n = lookup(v, userdata);
                if (!n)
                        goto oom;

                skip = strlen(v) + 2;

                d = t - r;
                nl = l - skip + strlen(n);
                a = realloc(r, nl + 1);
                if (!a)
                        goto oom;

                l = nl;
                r = a;
                t = r + d;

                t = stpcpy(t, n);
                f += skip;
        }

        *t = 0;
        return r;

oom:
        free(r);
        return NULL;
}
