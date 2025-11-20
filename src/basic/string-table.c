/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "parse-util.h"
#include "string-table.h"
#include "string-util.h"

const char* string_table_lookup_to_string(const char * const *table, size_t len, ssize_t i) {
        if (i < 0 || i >= (ssize_t) len)
                return NULL;

        return table[i];
}

ssize_t string_table_lookup_from_string(const char * const *table, size_t len, const char *key) {
        if (!key)
                return -EINVAL;

        for (size_t i = 0; i < len; ++i)
                if (streq_ptr(table[i], key))
                        return (ssize_t) i;

        return -EINVAL;
}

ssize_t string_table_lookup_from_string_with_boolean(const char * const *table, size_t len, const char *key, ssize_t yes) {
        if (!key)
                return -EINVAL;

        int b = parse_boolean(key);
        if (b == 0)
                return 0;
        if (b > 0)
                return yes;

        return string_table_lookup_from_string(table, len, key);
}

int string_table_lookup_to_string_fallback(const char * const *table, size_t len, ssize_t i, size_t max, char **ret) {
        char *s;

        if (i < 0 || i > (ssize_t) max)
                return -ERANGE;

        if (i < (ssize_t) len && table[i]) {
                s = strdup(table[i]);
                if (!s)
                        return -ENOMEM;
        } else if (asprintf(&s, "%zd", i) < 0)
                return -ENOMEM;

        *ret = s;
        return 0;
}

ssize_t string_table_lookup_from_string_fallback(const char * const *table, size_t len, const char *s, size_t max) {
        if (!s)
                return -EINVAL;

        ssize_t i = string_table_lookup_from_string(table, len, s);
        if (i >= 0)
                return i;

        unsigned u;
        if (safe_atou(s, &u) < 0)
                return -EINVAL;
        if (u > max)
                return -EINVAL;

        return u;
}
