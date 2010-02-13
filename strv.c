/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "util.h"
#include "strv.h"

char *strv_find(char **l, const char *name) {
        char **i;

        assert(l);
        assert(name);

        STRV_FOREACH(i, l)
                if (streq(*i, name))
                        return *i;

        return NULL;
}

void strv_free(char **l) {
        char **k;

        if (!l)
                return;

        for (k = l; *k; k++)
                free(*k);

        free(l);
}

char **strv_copy(char **l) {
        char **r, **k;

        if (!(r = new(char*, strv_length(l)+1)))
                return NULL;

        for (k = r; *l; k++, l++)
                if (!(*k = strdup(*l)))
                        goto fail;

        *k = NULL;
        return r;

fail:
        for (k--, l--; k >= r; k--, l--)
                free(*k);

        return NULL;
}

unsigned strv_length(char **l) {
        unsigned n = 0;

        if (!l)
                return 0;

        for (; *l; l++)
                n++;

        return n;
}

char **strv_new(const char *x, ...) {
        const char *s;
        char **a;
        unsigned n = 0, i = 0;
        va_list ap;

        if (x) {
                n = 1;

                va_start(ap, x);

                while (va_arg(ap, const char*))
                        n++;

                va_end(ap);
        }

        if (!(a = new(char*, n+1)))
                return NULL;

        if (x) {
                if (!(a[i] = strdup(x))) {
                        free(a);
                        return NULL;
                }

                i++;

                va_start(ap, x);

                while ((s = va_arg(ap, const char*))) {
                        if (!(a[i] = strdup(s)))
                                goto fail;

                        i++;
                }

                va_end(ap);
        }

        a[i] = NULL;
        return a;

fail:

        for (; i > 0; i--)
                if (a[i-1])
                        free(a[i-1]);

        free(a);
        return NULL;
}

char **strv_merge(char **a, char **b) {
        char **r, **k;

        if (!a)
                return strv_copy(b);

        if (!b)
                return strv_copy(a);

        if (!(r = new(char*, strv_length(a)+strv_length(b)+1)))
                return NULL;

        for (k = r; *a; k++, a++)
                if (!(*k = strdup(*a)))
                        goto fail;
        for (; *b; k++, b++)
                if (!(*k = strdup(*b)))
                        goto fail;

        *k = NULL;
        return r;

fail:
        for (k--; k >= r; k--)
                free(*k);

        return NULL;
}

char **strv_merge_concat(char **a, char **b, const char *suffix) {
        char **r, **k;

        /* Like strv_merge(), but appends suffix to all strings in b, before adding */

        if (!b)
                return strv_copy(a);

        if (!(r = new(char*, strv_length(a)+strv_length(b)+1)))
                return NULL;

        for (k = r; *a; k++, a++)
                if (!(*k = strdup(*a)))
                        goto fail;
        for (; *b; k++, b++)
                if (!(*k = strappend(*b, suffix)))
                        goto fail;

        *k = NULL;
        return r;

fail:
        for (k--; k >= r; k--)
                free(*k);

        return NULL;

}

char **strv_split(const char *s, const char *separator) {
        char *state;
        char *w;
        size_t l;
        unsigned n, i;
        char **r;

        assert(s);

        n = 0;
        FOREACH_WORD_SEPARATOR(w, l, s, separator, state)
                n++;

        if (!(r = new(char*, n+1)))
                return NULL;

        i = 0;
        FOREACH_WORD_SEPARATOR(w, l, s, separator, state)
                if (!(r[i++] = strndup(w, l))) {
                        strv_free(r);
                        return NULL;
                }

        r[i] = NULL;
        return r;
}

char **strv_split_quoted(const char *s) {
        char *state;
        char *w;
        size_t l;
        unsigned n, i;
        char **r;

        assert(s);

        n = 0;
        FOREACH_WORD_QUOTED(w, l, s, state)
                n++;

        if (!(r = new(char*, n+1)))
                return NULL;

        i = 0;
        FOREACH_WORD_QUOTED(w, l, s, state)
                if (!(r[i++] = strndup(w, l))) {
                        strv_free(r);
                        return NULL;
                }

        r[i] = NULL;
        return r;
}

char *strv_join(char **l, const char *separator) {
        char *r, *e;
        char **s;
        size_t n, k;

        if (!separator)
                separator = " ";

        k = strlen(separator);

        n = 0;
        STRV_FOREACH(s, l) {
                if (n != 0)
                        n += k;
                n += strlen(*s);
        }

        if (!(r = new(char, n+1)))
                return NULL;

        e = r;
        STRV_FOREACH(s, l) {
                if (e != r)
                        e = stpcpy(e, separator);

                e = stpcpy(e, *s);
        }

        return r;
}

char **strv_append(char **l, const char *s) {
        char **r, **k;

        if (!l)
                return strv_new(s, NULL);

        if (!s)
                return strv_copy(l);

        if (!(r = new(char*, strv_length(l)+2)))
                return NULL;

        for (k = r; *l; k++, l++)
                if (!(*k = strdup(*l)))
                        goto fail;
        if (!(*(k++) = strdup(s)))
                goto fail;

        *k = NULL;
        return r;

fail:
        for (k--; k >= r; k--)
                free(*k);

        return NULL;
}

char **strv_uniq(char **l) {
        char **i;

        /* Drops duplicate entries. The first identical string will be
         * kept, the others dropped */

        STRV_FOREACH(i, l)
                strv_remove(i+1, *i);

        return l;
}

char **strv_remove(char **l, const char *s) {
        char **f, **t;

        if (!l)
                return NULL;

        /* Drops every occurence of s in the string list */

        for (f = t = l; *f; f++) {

                if (streq(*f, s)) {
                        free(*f);
                        continue;
                }

                *(t++) = *f;
        }

        *t = NULL;
        return l;
}
