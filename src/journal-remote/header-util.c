/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "header-util.h"
#include "strv.h"

/* HTTP header name can contains:
- Alphanumeric characters: a-z, A-Z, and 0-9
- The following special characters: - and _ */
#define VALID_HEADER_NAME_CHARS \
        DIGITS LETTERS "_"      \
                       "-"

#define VALID_HEADER_NAME_LENGTH 40

#define VALID_HEADER_VALUE_CHARS \
        DIGITS LETTERS "_"       \
                       " "       \
                       ":"       \
                       ";"       \
                       "."       \
                       ","       \
                       "\\"      \
                       "/"       \
                       "'"       \
                       "\""      \
                       "?"       \
                       "!"       \
                       "("       \
                       ")"       \
                       "{"       \
                       "}"       \
                       "["       \
                       "]"       \
                       "@"       \
                       "<"       \
                       ">"       \
                       "="       \
                       "-"       \
                       "+"       \
                       "*"       \
                       "#"       \
                       "$"       \
                       "&"       \
                       "`"       \
                       "|"       \
                       "~"       \
                       "^"       \
                       "%"

static bool header_name_is_valid(const char *e, size_t n) {
        if (!e)
                return false;

        if (n > VALID_HEADER_NAME_LENGTH)
                return false;

        for (const char *p = e; p < e + n; p++)
                if (!strchr(VALID_HEADER_NAME_CHARS, *p))
                        return false;

        return true;
}

static bool header_value_is_valid(const char *e) {
        if (!e)
                return false;

        int n = strlen_ptr(e);

        if (n < 0)
                return false;

        for (const char *p = e; p < e + n; p++)
                if (!strchr(VALID_HEADER_VALUE_CHARS, *p))
                        return false;

        return true;
}

bool header_is_valid(const char *e) {
        const char *eq;

        eq = strchr(e, ':');
        if (!eq)
                return false;

        if (!header_name_is_valid(e, eq - e))
                return false;

        if (!header_value_is_valid(skip_leading_chars(eq + 1, WHITESPACE)))
                return false;

        return true;
}

static bool header_entry_has_name(const char *entry, const char *name) {
        const char *t;

        assert(entry);
        assert(name);

        t = startswith(entry, name);
        if (!t)
                return false;

        return *t == ':';
}

static char **strv_header_unset(char **l, const char *name) {
        assert(name);

        if (!l)
                return NULL;

        /* Drops every occurrence of the header var setting p in the
         * string list. Edits in-place. */

        char **f, **t;
        for (f = t = l; *f; f++) {
                if (header_entry_has_name(*f, name)) {
                        free(*f);
                        continue;
                }

                *(t++) = *f;
        }

        *t = NULL;
        return l;
}

int strv_header_replace_consume(char ***l, char *p) {
        const char *t, *name;
        int r;

        assert(p);

        /* p must be a valid "key: value" assignment. */

        t = strchr(p, ':');
        if (!t) {
                free(p);
                return -EINVAL;
        }

        if (!header_is_valid(p)) {
                free(p);
                return -EINVAL;
        }

        name = strndupa(p, t - p);
        if (!name) {
                free(p);
                return -ENOMEM;
        }

        STRV_FOREACH(f, *l)
                if (header_entry_has_name(*f, name)) {
                        free_and_replace(*f, p);
                        strv_header_unset(f + 1, name);
                        return 0;
                }

        /* We didn't find a match, we need to append p or create a new strv */
        r = strv_consume(l, p);
        if (r < 0)
                return r;

        return 1;
}
