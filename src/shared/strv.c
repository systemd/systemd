/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include "util.h"
#include "strv.h"

char *strv_find(char **l, const char *name) {
        char **i;

        assert(name);

        STRV_FOREACH(i, l)
                if (streq(*i, name))
                        return *i;

        return NULL;
}

char *strv_find_prefix(char **l, const char *name) {
        char **i;

        assert(name);

        STRV_FOREACH(i, l)
                if (startswith(*i, name))
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

char **strv_copy(char * const *l) {
        char **r, **k;

        k = r = new(char*, strv_length(l) + 1);
        if (!r)
                return NULL;

        if (l)
                for (; *l; k++, l++) {
                        *k = strdup(*l);
                        if (!*k) {
                                strv_free(r);
                                return NULL;
                        }
                }

        *k = NULL;
        return r;
}

unsigned strv_length(char * const *l) {
        unsigned n = 0;

        if (!l)
                return 0;

        for (; *l; l++)
                n++;

        return n;
}

char **strv_new_ap(const char *x, va_list ap) {
        const char *s;
        char **a;
        unsigned n = 0, i = 0;
        va_list aq;

        /* As a special trick we ignore all listed strings that equal
         * (const char*) -1. This is supposed to be used with the
         * STRV_IFNOTNULL() macro to include possibly NULL strings in
         * the string list. */

        if (x) {
                n = x == (const char*) -1 ? 0 : 1;

                va_copy(aq, ap);
                while ((s = va_arg(aq, const char*))) {
                        if (s == (const char*) -1)
                                continue;

                        n++;
                }

                va_end(aq);
        }

        a = new(char*, n+1);
        if (!a)
                return NULL;

        if (x) {
                if (x != (const char*) -1) {
                        a[i] = strdup(x);
                        if (!a[i])
                                goto fail;
                        i++;
                }

                while ((s = va_arg(ap, const char*))) {

                        if (s == (const char*) -1)
                                continue;

                        a[i] = strdup(s);
                        if (!a[i])
                                goto fail;

                        i++;
                }
        }

        a[i] = NULL;

        return a;

fail:
        strv_free(a);
        return NULL;
}

char **strv_new(const char *x, ...) {
        char **r;
        va_list ap;

        va_start(ap, x);
        r = strv_new_ap(x, ap);
        va_end(ap);

        return r;
}

int strv_extend_strv(char ***a, char **b) {
        int r;
        char **s;

        STRV_FOREACH(s, b) {
                r = strv_extend(a, *s);
                if (r < 0)
                        return r;
        }

        return 0;
}

int strv_extend_strv_concat(char ***a, char **b, const char *suffix) {
        int r;
        char **s;

        STRV_FOREACH(s, b) {
                char *v;

                v = strappend(*s, suffix);
                if (!v)
                        return -ENOMEM;

                r = strv_push(a, v);
                if (r < 0) {
                        free(v);
                        return r;
                }
        }

        return 0;
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

        r = new(char*, n+1);
        if (!r)
                return NULL;

        i = 0;
        FOREACH_WORD_SEPARATOR(w, l, s, separator, state) {
                r[i] = strndup(w, l);
                if (!r[i]) {
                        strv_free(r);
                        return NULL;
                }

                i++;
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

        r = new(char*, n+1);
        if (!r)
                return NULL;

        i = 0;
        FOREACH_WORD_QUOTED(w, l, s, state) {
                r[i] = cunescape_length(w, l);
                if (!r[i]) {
                        strv_free(r);
                        return NULL;
                }
                i++;
        }

        r[i] = NULL;
        return r;
}

char **strv_split_newlines(const char *s) {
        char **l;
        unsigned n;

        assert(s);

        /* Special version of strv_split() that splits on newlines and
         * suppresses an empty string at the end */

        l = strv_split(s, NEWLINE);
        if (!l)
                return NULL;

        n = strv_length(l);
        if (n <= 0)
                return l;

        if (isempty(l[n-1])) {
                free(l[n-1]);
                l[n-1] = NULL;
        }

        return l;
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

        r = new(char, n+1);
        if (!r)
                return NULL;

        e = r;
        STRV_FOREACH(s, l) {
                if (e != r)
                        e = stpcpy(e, separator);

                e = stpcpy(e, *s);
        }

        *e = 0;

        return r;
}

char *strv_join_quoted(char **l) {
        char *buf = NULL;
        char **s;
        size_t allocated = 0, len = 0;

        STRV_FOREACH(s, l) {
                /* assuming here that escaped string cannot be more
                 * than twice as long, and reserving space for the
                 * separator and quotes.
                 */
                _cleanup_free_ char *esc = NULL;
                size_t needed;

                if (!GREEDY_REALLOC(buf, allocated,
                                    len + strlen(*s) * 2 + 3))
                        goto oom;

                esc = cescape(*s);
                if (!esc)
                        goto oom;

                needed = snprintf(buf + len, allocated - len, "%s\"%s\"",
                                  len > 0 ? " " : "", esc);
                assert(needed < allocated - len);
                len += needed;
        }

        if (!buf)
                buf = malloc0(1);

        return buf;

 oom:
        free(buf);
        return NULL;
}

int strv_push(char ***l, char *value) {
        char **c;
        unsigned n;

        if (!value)
                return 0;

        n = strv_length(*l);
        c = realloc(*l, sizeof(char*) * (n + 2));
        if (!c)
                return -ENOMEM;

        c[n] = value;
        c[n+1] = NULL;

        *l = c;
        return 0;
}

int strv_push_prepend(char ***l, char *value) {
        char **c;
        unsigned n, i;

        if (!value)
                return 0;

        n = strv_length(*l);
        c = new(char*, n + 2);
        if (!c)
                return -ENOMEM;

        for (i = 0; i < n; i++)
                c[i+1] = (*l)[i];

        c[0] = value;
        c[n+1] = NULL;

        free(*l);
        *l = c;

        return 0;
}

int strv_consume(char ***l, char *value) {
        int r;

        r = strv_push(l, value);
        if (r < 0)
                free(value);

        return r;
}

int strv_consume_prepend(char ***l, char *value) {
        int r;

        r = strv_push_prepend(l, value);
        if (r < 0)
                free(value);

        return r;
}

int strv_extend(char ***l, const char *value) {
        char *v;

        if (!value)
                return 0;

        v = strdup(value);
        if (!v)
                return -ENOMEM;

        return strv_consume(l, v);
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

        assert(s);

        /* Drops every occurrence of s in the string list, edits
         * in-place. */

        for (f = t = l; *f; f++)
                if (streq(*f, s))
                        free(*f);
                else
                        *(t++) = *f;

        *t = NULL;
        return l;
}

char **strv_parse_nulstr(const char *s, size_t l) {
        const char *p;
        unsigned c = 0, i = 0;
        char **v;

        assert(s || l <= 0);

        if (l <= 0)
                return new0(char*, 1);

        for (p = s; p < s + l; p++)
                if (*p == 0)
                        c++;

        if (s[l-1] != 0)
                c++;

        v = new0(char*, c+1);
        if (!v)
                return NULL;

        p = s;
        while (p < s + l) {
                const char *e;

                e = memchr(p, 0, s + l - p);

                v[i] = strndup(p, e ? e - p : s + l - p);
                if (!v[i]) {
                        strv_free(v);
                        return NULL;
                }

                i++;

                if (!e)
                        break;

                p = e + 1;
        }

        assert(i == c);

        return v;
}

char **strv_split_nulstr(const char *s) {
        const char *i;
        char **r = NULL;

        NULSTR_FOREACH(i, s)
                if (strv_extend(&r, i) < 0) {
                        strv_free(r);
                        return NULL;
                }

        if (!r)
                return strv_new(NULL, NULL);

        return r;
}

bool strv_overlap(char **a, char **b) {
        char **i;

        STRV_FOREACH(i, a)
                if (strv_contains(b, *i))
                        return true;

        return false;
}

static int str_compare(const void *_a, const void *_b) {
        const char **a = (const char**) _a, **b = (const char**) _b;

        return strcmp(*a, *b);
}

char **strv_sort(char **l) {

        if (strv_isempty(l))
                return l;

        qsort(l, strv_length(l), sizeof(char*), str_compare);
        return l;
}

void strv_print(char **l) {
        char **s;

        STRV_FOREACH(s, l)
                puts(*s);
}

int strv_extendf(char ***l, const char *format, ...) {
        va_list ap;
        char *x;
        int r;

        va_start(ap, format);
        r = vasprintf(&x, format, ap);
        va_end(ap);

        if (r < 0)
                return -ENOMEM;

        return strv_consume(l, x);
}
