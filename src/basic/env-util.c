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

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "alloc-util.h"
#include "env-util.h"
#include "escape.h"
#include "extract-word.h"
#include "macro.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

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

static bool env_match(const char *t, const char *pattern) {
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

static bool env_entry_has_name(const char *entry, const char *name) {
        const char *t;

        assert(entry);
        assert(name);

        t = startswith(entry, name);
        if (!t)
                return false;

        return *t == '=';
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

int strv_env_replace(char ***l, char *p) {
        char **f;
        const char *t, *name;

        assert(p);

        /* Replace first occurrence of the env var or add a new one in the
         * string list. Drop other occurences. Edits in-place. Does not copy p.
         * p must be a valid key=value assignment.
         */

        t = strchr(p, '=');
        assert(t);

        name = strndupa(p, t - p);

        for (f = *l; f && *f; f++)
                if (env_entry_has_name(*f, name)) {
                        free_and_replace(*f, p);
                        strv_env_unset(f + 1, *f);
                        return 0;
                }

        /* We didn't find a match, we need to append p or create a new strv */
        if (strv_push(l, p) < 0)
                return -ENOMEM;
        return 1;
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

char *strv_env_get_n(char **l, const char *name, size_t k, unsigned flags) {
        char **i;

        assert(name);

        if (k <= 0)
                return NULL;

        STRV_FOREACH_BACKWARDS(i, l)
                if (strneq(*i, name, k) &&
                    (*i)[k] == '=')
                        return *i + k + 1;

        if (flags & REPLACE_ENV_USE_ENVIRONMENT) {
                const char *t;

                t = strndupa(name, k);
                return getenv(t);
        };

        return NULL;
}

char *strv_env_get(char **l, const char *name) {
        assert(name);

        return strv_env_get_n(l, name, strlen(name), 0);
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

char *replace_env_n(const char *format, size_t n, char **env, unsigned flags) {
        enum {
                WORD,
                CURLY,
                VARIABLE,
                VARIABLE_RAW,
                TEST,
                DEFAULT_VALUE,
                ALTERNATE_VALUE,
        } state = WORD;

        const char *e, *word = format, *test_value;
        char *k;
        _cleanup_free_ char *r = NULL;
        size_t i, len;
        int nest = 0;

        assert(format);

        for (e = format, i = 0; *e && i < n; e ++, i ++) {

                switch (state) {

                case WORD:
                        if (*e == '$')
                                state = CURLY;
                        break;

                case CURLY:
                        if (*e == '{') {
                                k = strnappend(r, word, e-word-1);
                                if (!k)
                                        return NULL;

                                free(r);
                                r = k;

                                word = e-1;
                                state = VARIABLE;
                                nest++;
                        } else if (*e == '$') {
                                k = strnappend(r, word, e-word);
                                if (!k)
                                        return NULL;

                                free(r);
                                r = k;

                                word = e+1;
                                state = WORD;

                        } else if (flags & REPLACE_ENV_ALLOW_BRACELESS && strchr(VALID_CHARS_ENV_NAME, *e)) {
                                k = strnappend(r, word, e-word-1);
                                if (!k)
                                        return NULL;

                                free(r);
                                r = k;

                                word = e-1;
                                state = VARIABLE_RAW;

                        } else
                                state = WORD;
                        break;

                case VARIABLE:
                        if (*e == '}') {
                                const char *t;

                                t = strv_env_get_n(env, word+2, e-word-2, flags);

                                k = strappend(r, t);
                                if (!k)
                                        return NULL;

                                free(r);
                                r = k;

                                word = e+1;
                                state = WORD;
                        } else if (*e == ':') {
                                if (!(flags & REPLACE_ENV_ALLOW_EXTENDED))
                                        /* Treat this as unsupported syntax, i.e. do no replacement */
                                        state = WORD;
                                else {
                                        len = e-word-2;
                                        state = TEST;
                                }
                        }
                        break;

                case TEST:
                        if (*e == '-')
                                state = DEFAULT_VALUE;
                        else if (*e == '+')
                                state = ALTERNATE_VALUE;
                        else {
                                state = WORD;
                                break;
                        }

                        test_value = e+1;
                        break;

                case DEFAULT_VALUE: /* fall through */
                case ALTERNATE_VALUE:
                        assert(flags & REPLACE_ENV_ALLOW_EXTENDED);

                        if (*e == '{') {
                                nest++;
                                break;
                        }

                        if (*e != '}')
                                break;

                        nest--;
                        if (nest == 0) {
                                const char *t;
                                _cleanup_free_ char *v = NULL;

                                t = strv_env_get_n(env, word+2, len, flags);

                                if (t && state == ALTERNATE_VALUE)
                                        t = v = replace_env_n(test_value, e-test_value, env, flags);
                                else if (!t && state == DEFAULT_VALUE)
                                        t = v = replace_env_n(test_value, e-test_value, env, flags);

                                k = strappend(r, t);
                                if (!k)
                                        return NULL;

                                free(r);
                                r = k;

                                word = e+1;
                                state = WORD;
                        }
                        break;

                case VARIABLE_RAW:
                        assert(flags & REPLACE_ENV_ALLOW_BRACELESS);

                        if (!strchr(VALID_CHARS_ENV_NAME, *e)) {
                                const char *t;

                                t = strv_env_get_n(env, word+1, e-word-1, flags);

                                k = strappend(r, t);
                                if (!k)
                                        return NULL;

                                free(r);
                                r = k;

                                word = e--;
                                i--;
                                state = WORD;
                        }
                        break;
                }
        }

        if (state == VARIABLE_RAW) {
                const char *t;

                assert(flags & REPLACE_ENV_ALLOW_BRACELESS);

                t = strv_env_get_n(env, word+1, e-word-1, flags);
                return strappend(r, t);
        } else
                return strnappend(r, word, e-word);
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
                ret[k] = replace_env(*i, env, 0);
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

int serialize_environment(FILE *f, char **environment) {
        char **e;

        STRV_FOREACH(e, environment) {
                _cleanup_free_ char *ce;

                ce = cescape(*e);
                if (!ce)
                        return -ENOMEM;

                fprintf(f, "env=%s\n", ce);
        }

        /* caller should call ferror() */

        return 0;
}

int deserialize_environment(char ***environment, const char *line) {
        char *uce;
        int r;

        assert(line);
        assert(environment);

        assert(startswith(line, "env="));
        r = cunescape(line + 4, UNESCAPE_RELAX, &uce);
        if (r < 0)
                return r;

        if (!env_assignment_is_valid(uce)) {
                free(uce);
                return -EINVAL;
        }

        return strv_env_replace(environment, uce);
}
