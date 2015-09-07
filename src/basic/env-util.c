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

#include <limits.h>
#include <unistd.h>

#include "alloc-util.h"
#include "def.h"
#include "env-util.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"
#include "util.h"

#define VALID_CHARS_ENV_NAME                    \
        DIGITS LETTERS                          \
        "_"

#ifndef ARG_MAX
#define ARG_MAX ((size_t) sysconf(_SC_ARG_MAX))
#endif

static bool env_name_is_valid_n(const char *e, size_t n) {
        const char *p;

        if (!e)
                return false;

        if (n <= 0)
                return false;

        if (e[0] >= '0' && e[0] <= '9')
                return false;

        /* POSIX says the overall size of the environment block cannot
         * be > ARG_MAX, an individual assignment hence cannot be
         * either. Discounting the equal sign and trailing NUL this
         * hence leaves ARG_MAX-2 as longest possible variable
         * name. */
        if (n > ARG_MAX - 2)
                return false;

        for (p = e; p < e + n; p++)
                if (!strchr(VALID_CHARS_ENV_NAME, *p))
                        return false;

        return true;
}

bool env_name_is_valid(const char *e) {
        if (!e)
                return false;

        return env_name_is_valid_n(e, strlen(e));
}

bool env_value_is_valid(const char *e) {
        if (!e)
                return false;

        if (!utf8_is_valid(e))
                return false;

        /* bash allows tabs in environment variables, and so should
         * we */
        if (string_has_cc(e, "\t"))
                return false;

        /* POSIX says the overall size of the environment block cannot
         * be > ARG_MAX, an individual assignment hence cannot be
         * either. Discounting the shortest possible variable name of
         * length 1, the equal sign and trailing NUL this hence leaves
         * ARG_MAX-3 as longest possible variable value. */
        if (strlen(e) > ARG_MAX - 3)
                return false;

        return true;
}

bool env_assignment_is_valid(const char *e) {
        const char *eq;

        eq = strchr(e, '=');
        if (!eq)
                return false;

        if (!env_name_is_valid_n(e, eq - e))
                return false;

        if (!env_value_is_valid(eq + 1))
                return false;

        /* POSIX says the overall size of the environment block cannot
         * be > ARG_MAX, hence the individual variable assignments
         * cannot be either, but let's leave room for one trailing NUL
         * byte. */
        if (strlen(e) > ARG_MAX - 1)
                return false;

        return true;
}

bool strv_env_is_valid(char **e) {
        char **p, **q;

        STRV_FOREACH(p, e) {
                size_t k;

                if (!env_assignment_is_valid(*p))
                        return false;

                /* Check if there are duplicate assginments */
                k = strcspn(*p, "=");
                STRV_FOREACH(q, p + 1)
                        if (strneq(*p, *q, k) && (*q)[k] == '=')
                                return false;
        }

        return true;
}

bool strv_env_name_is_valid(char **l) {
        char **p, **q;

        STRV_FOREACH(p, l) {
                if (!env_name_is_valid(*p))
                        return false;

                STRV_FOREACH(q, p + 1)
                        if (streq(*p, *q))
                                return false;
        }

        return true;
}

bool strv_env_name_or_assignment_is_valid(char **l) {
        char **p, **q;

        STRV_FOREACH(p, l) {
                if (!env_assignment_is_valid(*p) && !env_name_is_valid(*p))
                        return false;

                STRV_FOREACH(q, p + 1)
                        if (streq(*p, *q))
                                return false;
        }

        return true;
}

static int env_append(char **r, char ***k, char **a) {
        assert(r);
        assert(k);

        if (!a)
                return 0;

        /* Add the entries of a to *k unless they already exist in *r
         * in which case they are overridden instead. This assumes
         * there is enough space in the r array. */

        for (; *a; a++) {
                char **j;
                size_t n;

                n = strcspn(*a, "=");

                if ((*a)[n] == '=')
                        n++;

                for (j = r; j < *k; j++)
                        if (strneq(*j, *a, n))
                                break;

                if (j >= *k)
                        (*k)++;
                else
                        free(*j);

                *j = strdup(*a);
                if (!*j)
                        return -ENOMEM;
        }

        return 0;
}

char **strv_env_merge(unsigned n_lists, ...) {
        size_t n = 0;
        char **l, **k, **r;
        va_list ap;
        unsigned i;

        /* Merges an arbitrary number of environment sets */

        va_start(ap, n_lists);
        for (i = 0; i < n_lists; i++) {
                l = va_arg(ap, char**);
                n += strv_length(l);
        }
        va_end(ap);

        r = new(char*, n+1);
        if (!r)
                return NULL;

        k = r;

        va_start(ap, n_lists);
        for (i = 0; i < n_lists; i++) {
                l = va_arg(ap, char**);
                if (env_append(r, &k, l) < 0)
                        goto fail;
        }
        va_end(ap);

        *k = NULL;

        return r;

fail:
        va_end(ap);
        strv_free(r);

        return NULL;
}

_pure_ static bool env_match(const char *t, const char *pattern) {
        assert(t);
        assert(pattern);

        /* pattern a matches string a
         *         a matches a=
         *         a matches a=b
         *         a= matches a=
         *         a=b matches a=b
         *         a= does not match a
         *         a=b does not match a=
         *         a=b does not match a
         *         a=b does not match a=c */

        if (streq(t, pattern))
                return true;

        if (!strchr(pattern, '=')) {
                size_t l = strlen(pattern);

                return strneq(t, pattern, l) && t[l] == '=';
        }

        return false;
}

char **strv_env_delete(char **x, unsigned n_lists, ...) {
        size_t n, i = 0;
        char **k, **r;
        va_list ap;

        /* Deletes every entry from x that is mentioned in the other
         * string lists */

        n = strv_length(x);

        r = new(char*, n+1);
        if (!r)
                return NULL;

        STRV_FOREACH(k, x) {
                unsigned v;

                va_start(ap, n_lists);
                for (v = 0; v < n_lists; v++) {
                        char **l, **j;

                        l = va_arg(ap, char**);
                        STRV_FOREACH(j, l)
                                if (env_match(*k, *j))
                                        goto skip;
                }
                va_end(ap);

                r[i] = strdup(*k);
                if (!r[i]) {
                        strv_free(r);
                        return NULL;
                }

                i++;
                continue;

        skip:
                va_end(ap);
        }

        r[i] = NULL;

        assert(i <= n);

        return r;
}

char **strv_env_unset(char **l, const char *p) {

        char **f, **t;

        if (!l)
                return NULL;

        assert(p);

        /* Drops every occurrence of the env var setting p in the
         * string list. Edits in-place. */

        for (f = t = l; *f; f++) {

                if (env_match(*f, p)) {
                        free(*f);
                        continue;
                }

                *(t++) = *f;
        }

        *t = NULL;
        return l;
}

char **strv_env_unset_many(char **l, ...) {

        char **f, **t;

        if (!l)
                return NULL;

        /* Like strv_env_unset() but applies many at once. Edits in-place. */

        for (f = t = l; *f; f++) {
                bool found = false;
                const char *p;
                va_list ap;

                va_start(ap, l);

                while ((p = va_arg(ap, const char*))) {
                        if (env_match(*f, p)) {
                                found = true;
                                break;
                        }
                }

                va_end(ap);

                if (found) {
                        free(*f);
                        continue;
                }

                *(t++) = *f;
        }

        *t = NULL;
        return l;
}

char **strv_env_set(char **x, const char *p) {

        char **k, **r;
        char* m[2] = { (char*) p, NULL };

        /* Overrides the env var setting of p, returns a new copy */

        r = new(char*, strv_length(x)+2);
        if (!r)
                return NULL;

        k = r;
        if (env_append(r, &k, x) < 0)
                goto fail;

        if (env_append(r, &k, m) < 0)
                goto fail;

        *k = NULL;

        return r;

fail:
        strv_free(r);
        return NULL;
}

char *strv_env_get_n(char **l, const char *name, size_t k) {
        char **i;

        assert(name);

        if (k <= 0)
                return NULL;

        STRV_FOREACH(i, l)
                if (strneq(*i, name, k) &&
                    (*i)[k] == '=')
                        return *i + k + 1;

        return NULL;
}

char *strv_env_get(char **l, const char *name) {
        assert(name);

        return strv_env_get_n(l, name, strlen(name));
}

char **strv_env_clean_with_callback(char **e, void (*invalid_callback)(const char *p, void *userdata), void *userdata) {
        char **p, **q;
        int k = 0;

        STRV_FOREACH(p, e) {
                size_t n;
                bool duplicate = false;

                if (!env_assignment_is_valid(*p)) {
                        if (invalid_callback)
                                invalid_callback(*p, userdata);
                        free(*p);
                        continue;
                }

                n = strcspn(*p, "=");
                STRV_FOREACH(q, p + 1)
                        if (strneq(*p, *q, n) && (*q)[n] == '=') {
                                duplicate = true;
                                break;
                        }

                if (duplicate) {
                        free(*p);
                        continue;
                }

                e[k++] = *p;
        }

        if (e)
                e[k] = NULL;

        return e;
}

char *replace_env(const char *format, char **env) {
        enum {
                WORD,
                CURLY,
                VARIABLE
        } state = WORD;

        const char *e, *word = format;
        char *r = NULL, *k;

        assert(format);

        for (e = format; *e; e ++) {

                switch (state) {

                case WORD:
                        if (*e == '$')
                                state = CURLY;
                        break;

                case CURLY:
                        if (*e == '{') {
                                k = strnappend(r, word, e-word-1);
                                if (!k)
                                        goto fail;

                                free(r);
                                r = k;

                                word = e-1;
                                state = VARIABLE;

                        } else if (*e == '$') {
                                k = strnappend(r, word, e-word);
                                if (!k)
                                        goto fail;

                                free(r);
                                r = k;

                                word = e+1;
                                state = WORD;
                        } else
                                state = WORD;
                        break;

                case VARIABLE:
                        if (*e == '}') {
                                const char *t;

                                t = strempty(strv_env_get_n(env, word+2, e-word-2));

                                k = strappend(r, t);
                                if (!k)
                                        goto fail;

                                free(r);
                                r = k;

                                word = e+1;
                                state = WORD;
                        }
                        break;
                }
        }

        k = strnappend(r, word, e-word);
        if (!k)
                goto fail;

        free(r);
        return k;

fail:
        free(r);
        return NULL;
}

char **replace_env_argv(char **argv, char **env) {
        char **ret, **i;
        unsigned k = 0, l = 0;

        l = strv_length(argv);

        ret = new(char*, l+1);
        if (!ret)
                return NULL;

        STRV_FOREACH(i, argv) {

                /* If $FOO appears as single word, replace it by the split up variable */
                if ((*i)[0] == '$' && (*i)[1] != '{' && (*i)[1] != '$') {
                        char *e;
                        char **w, **m = NULL;
                        unsigned q;

                        e = strv_env_get(env, *i+1);
                        if (e) {
                                int r;

                                r = strv_split_extract(&m, e, WHITESPACE, EXTRACT_RELAX|EXTRACT_QUOTES);
                                if (r < 0) {
                                        ret[k] = NULL;
                                        strv_free(ret);
                                        return NULL;
                                }
                        } else
                                m = NULL;

                        q = strv_length(m);
                        l = l + q - 1;

                        w = realloc(ret, sizeof(char*) * (l+1));
                        if (!w) {
                                ret[k] = NULL;
                                strv_free(ret);
                                strv_free(m);
                                return NULL;
                        }

                        ret = w;
                        if (m) {
                                memcpy(ret + k, m, q * sizeof(char*));
                                free(m);
                        }

                        k += q;
                        continue;
                }

                /* If ${FOO} appears as part of a word, replace it by the variable as-is */
                ret[k] = replace_env(*i, env);
                if (!ret[k]) {
                        strv_free(ret);
                        return NULL;
                }
                k++;
        }

        ret[k] = NULL;
        return ret;
}

int getenv_bool(const char *p) {
        const char *e;

        e = getenv(p);
        if (!e)
                return -ENXIO;

        return parse_boolean(e);
}
