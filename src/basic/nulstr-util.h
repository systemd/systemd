/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#define NULSTR_FOREACH(i, l)                                    \
        for (typeof(*(l)) *(i) = (l); (i) && *(i); (i) = strchr((i), 0)+1)

#define NULSTR_FOREACH_PAIR(i, j, l)                             \
        for (typeof(*(l)) *(i) = (l), *(j) = strchr((i), 0)+1; (i) && *(i); (i) = strchr((j), 0)+1, (j) = *(i) ? strchr((i), 0)+1 : (i))

const char* nulstr_get(const char *nulstr, const char *needle);

static inline bool nulstr_contains(const char *nulstr, const char *needle) {
        return nulstr_get(nulstr, needle);
}

char** strv_parse_nulstr(const char *s, size_t l);
char** strv_split_nulstr(const char *s);
int strv_make_nulstr(char * const *l, char **p, size_t *n);

static inline int strv_from_nulstr(char ***a, const char *nulstr) {
        char **t;

        t = strv_split_nulstr(nulstr);
        if (!t)
                return -ENOMEM;
        *a = t;
        return 0;
}
