/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "escape.h"
#include "extract-word.h"
#include "headers-util.h"
#include "macro.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "syslog-util.h"
#include "utf8.h"

/* We follow bash for the character set. Different shells have different rules. */
#define VALID_HEADER_NAME_CHARS \
        DIGITS LETTERS "_"      \
                       "-"

static bool headers_name_is_valid_n(const char *e, size_t n) {

        if (n == SIZE_MAX)
                n = strlen_ptr(e);

        if (n <= 0)
                return false;

        assert(e);

        /* POSIX says the overall size of the environment block cannot be > ARG_MAX, an individual assignment
         * hence cannot be either. Discounting the equal sign and trailing NUL this hence leaves ARG_MAX-2 as
         * longest possible variable name. */
        if (n > (size_t) sysconf(_SC_ARG_MAX) - 2)
                return false;

        for (const char *p = e; p < e + n; p++)
                if (!strchr(VALID_HEADER_NAME_CHARS, *p))
                        return false;

        return true;
}

bool headers_name_is_valid(const char *e) {
        return headers_name_is_valid_n(e, strlen_ptr(e));
}

bool headers_value_is_valid(const char *e) {
        if (!e)
                return false;

        if (!utf8_is_valid(e))
                return false;

        return true;
}

bool headers_assignment_is_valid(const char *e) {
        const char *eq;

        eq = strchr(e, ':');
        if (!eq)
                return false;

        if (!headers_name_is_valid_n(e, eq - e))
                return false;

        if (!headers_value_is_valid(skip_leading_chars(eq + 1, WHITESPACE)))
                return false;

        return true;
}

bool strv_headers_is_valid(char **e) {
        STRV_FOREACH(p, e) {
                size_t k;

                if (!headers_assignment_is_valid(*p))
                        return false;

                /* Check if there are duplicate assignments */
                k = strcspn(*p, ":");
                STRV_FOREACH(q, p + 1)
                        if (strneq(*p, *q, k) && (*q)[k] == ':')
                                return false;
        }

        return true;
}

bool strv_headers_name_is_valid(char **l) {
        STRV_FOREACH(p, l) {
                if (!headers_name_is_valid(*p))
                        return false;

                if (strv_contains(p + 1, *p))
                        return false;
        }

        return true;
}

bool strv_headers_name_or_assignment_is_valid(char **l) {
        STRV_FOREACH(p, l) {
                if (!headers_assignment_is_valid(*p) && !headers_name_is_valid(*p))
                        return false;

                if (strv_contains(p + 1, *p))
                        return false;
        }

        return true;
}

static bool headers_match(const char *t, const char *pattern) {
        assert(t);
        assert(pattern);

        if (streq(t, pattern))
                return true;

        if (!strchr(pattern, ':')) {
                t = startswith(t, pattern);

                return t && *t == ':';
        }

        return false;
}

static bool headers_entry_has_name(const char *entry, const char *name) {
        const char *t;

        assert(entry);
        assert(name);

        t = startswith(entry, name);
        if (!t)
                return false;

        return *t == ':';
}

char **strv_headers_unset(char **l, const char *p) {
        assert(p);

        if (!l)
                return NULL;

        /* Drops every occurrence of the heaer var setting p in the
         * string list. Edits in-place. */

        char **f, **t;
        for (f = t = l; *f; f++) {
                if (headers_match(*f, p)) {
                        free(*f);
                        continue;
                }

                *(t++) = *f;
        }

        *t = NULL;
        return l;
}

int strv_headers_replace_consume(char ***l, char *p) {
        const char *t, *name;
        int r;

        assert(p);

        /* Replace first occurrence of the headers var or add a new one in the string list. Drop other
         * occurrences. Edits in-place. Does not copy p and CONSUMES p EVEN ON FAILURE.
         *
         * p must be a valid "key: value" assignment. */

        t = strchr(p, ':');
        if (!t) {
                free(p);
                return -EINVAL;
        }

        name = strndupa_safe(p, t - p);

        STRV_FOREACH(f, *l)
                if (headers_entry_has_name(*f, name)) {
                        free_and_replace(*f, p);
                        strv_headers_unset(f + 1, *f);
                        return 0;
                }

        /* We didn't find a match, we need to append p or create a new strv */
        r = strv_consume(l, p);
        if (r < 0)
                return r;

        return 1;
}
