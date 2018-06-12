/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "macro.h"
#include "parse-util.h"
#include "string-util.h"

ssize_t string_table_lookup(const char * const *table, size_t len, const char *key);

/* For basic lookup tables with strictly enumerated entries */
#define _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,scope)          \
        scope const char *name##_to_string(type i) {                    \
                if (i < 0 || i >= (type) ELEMENTSOF(name##_table))      \
                        return NULL;                                    \
                return name##_table[i];                                 \
        }

#define _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name,type,scope)        \
        scope type name##_from_string(const char *s) {                  \
                return (type) string_table_lookup(name##_table, ELEMENTSOF(name##_table), s); \
        }

#define _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(name,type,yes,scope) \
        scope type name##_from_string(const char *s) {                  \
                int b;                                                  \
                if (!s)                                                 \
                        return -1;                                      \
                b = parse_boolean(s);                                   \
                if (b == 0)                                             \
                        return (type) 0;                                \
                else if (b > 0)                                         \
                        return yes;                                     \
                return (type) string_table_lookup(name##_table, ELEMENTSOF(name##_table), s); \
        }

#define _DEFINE_STRING_TABLE_LOOKUP_TO_STRING_FALLBACK(name,type,max,scope) \
        scope int name##_to_string_alloc(type i, char **str) {          \
                char *s;                                                \
                if (i < 0 || i > max)                                   \
                        return -ERANGE;                                 \
                if (i < (type) ELEMENTSOF(name##_table)) {              \
                        s = strdup(name##_table[i]);                    \
                        if (!s)                                         \
                                return -ENOMEM;                         \
                } else {                                                \
                        if (asprintf(&s, "%i", i) < 0)                  \
                                return -ENOMEM;                         \
                }                                                       \
                *str = s;                                               \
                return 0;                                               \
        }

#define _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING_FALLBACK(name,type,max,scope) \
        type name##_from_string(const char *s) {                        \
                type i;                                                 \
                unsigned u = 0;                                         \
                if (!s)                                                 \
                        return (type) -1;                               \
                for (i = 0; i < (type) ELEMENTSOF(name##_table); i++)   \
                        if (streq_ptr(name##_table[i], s))              \
                                return i;                               \
                if (safe_atou(s, &u) >= 0 && u <= max)                  \
                        return (type) u;                                \
                return (type) -1;                                       \
        }                                                               \

#define _DEFINE_STRING_TABLE_LOOKUP(name,type,scope)                    \
        _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,scope)          \
        _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name,type,scope)

#define _DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(name,type,yes,scope)   \
        _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,scope)          \
        _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(name,type,yes,scope)

#define DEFINE_STRING_TABLE_LOOKUP(name,type) _DEFINE_STRING_TABLE_LOOKUP(name,type,)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP(name,type) _DEFINE_STRING_TABLE_LOOKUP(name,type,static)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(name,type) _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,static)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(name,type) _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name,type,static)

#define DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(name,type,yes) _DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(name,type,yes,)

/* For string conversions where numbers are also acceptable */
#define DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(name,type,max)         \
        _DEFINE_STRING_TABLE_LOOKUP_TO_STRING_FALLBACK(name,type,max,)  \
        _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING_FALLBACK(name,type,max,)

#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING_FALLBACK(name,type,max) \
        _DEFINE_STRING_TABLE_LOOKUP_TO_STRING_FALLBACK(name,type,max,static)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_FALLBACK(name,type,max) \
        _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING_FALLBACK(name,type,max,static)

#define DUMP_STRING_TABLE(name,type,max)                                \
        do {                                                            \
                type _k;                                                \
                flockfile(stdout);                                      \
                for (_k = 0; _k < (max); _k++) {                        \
                        const char *_t;                                 \
                        _t = name##_to_string(_k);                      \
                        if (!_t)                                        \
                                continue;                               \
                        fputs_unlocked(_t, stdout);                     \
                        fputc_unlocked('\n', stdout);                   \
                }                                                       \
                funlockfile(stdout);                                    \
        } while(false)
