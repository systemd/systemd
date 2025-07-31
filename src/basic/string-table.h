/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "forward.h"

const char* string_table_lookup_to_string(const char * const *table, size_t len, ssize_t i) _const_;

ssize_t string_table_lookup_from_string(const char * const *table, size_t len, const char *key) _pure_;
ssize_t string_table_lookup_from_string_with_boolean(const char * const *table, size_t len, const char *key, ssize_t yes) _pure_;

int string_table_lookup_to_string_fallback(const char * const *table, size_t len, ssize_t i, size_t max, char **ret);
ssize_t string_table_lookup_from_string_fallback(const char * const *table, size_t len, const char *s, size_t max);

/* For basic lookup tables with strictly enumerated entries */
#define _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name, type, scope) \
        scope const char* name##_to_string(type i) {             \
                return string_table_lookup_to_string(name##_table, ELEMENTSOF(name##_table), i); \
        }

#define _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name, type, scope) \
        scope type name##_from_string(const char *s) {             \
                return (type) string_table_lookup_from_string(name##_table, ELEMENTSOF(name##_table), s); \
        }

#define _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(name, type, yes, scope) \
        scope type name##_from_string(const char *s) {                               \
                return (type) string_table_lookup_from_string_with_boolean(name##_table, ELEMENTSOF(name##_table), s, yes); \
        }

#define _DEFINE_STRING_TABLE_LOOKUP_TO_STRING_FALLBACK(name, type, max, scope) \
        scope int name##_to_string_alloc(type i, char **ret) {                 \
                return string_table_lookup_to_string_fallback(name##_table, ELEMENTSOF(name##_table), i, max, ret); \
        }

#define _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING_FALLBACK(name, type, max, scope) \
        scope type name##_from_string(const char *s) {                           \
                return (type) string_table_lookup_from_string_fallback(name##_table, ELEMENTSOF(name##_table), s, max); \
        }

#define _DEFINE_STRING_TABLE_LOOKUP(name, type, scope)                    \
        _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name, type, scope)          \
        _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name, type, scope)

#define _DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(name, type, yes, scope)  \
        _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name, type, scope)          \
        _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(name, type, yes, scope)

#define DEFINE_STRING_TABLE_LOOKUP(name, type) _DEFINE_STRING_TABLE_LOOKUP(name, type,)
#define DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name, type) _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name, type,)
#define DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name, type) _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name, type,)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP(name, type) _DEFINE_STRING_TABLE_LOOKUP(name, type, static)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(name, type) _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name, type, static)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(name, type) _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name, type, static)

#define DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(name, type, yes) _DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(name, type, yes,)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(name, type, yes) _DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(name, type, yes, static)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(name, type, yes) \
        _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(name, type, yes, static)

/* For string conversions where numbers are also acceptable */
#define DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(name, type, max)         \
        _DEFINE_STRING_TABLE_LOOKUP_TO_STRING_FALLBACK(name, type, max,)  \
        _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING_FALLBACK(name, type, max,)
#define DEFINE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_FALLBACK(name, type, max) _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING_FALLBACK(name, type, max,)

#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING_FALLBACK(name, type, max) \
        _DEFINE_STRING_TABLE_LOOKUP_TO_STRING_FALLBACK(name, type, max, static)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_FALLBACK(name, type, max) \
        _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING_FALLBACK(name, type, max, static)

#define DUMP_STRING_TABLE(name, type, max)                              \
        ({                                                              \
                flockfile(stdout);                                      \
                for (type _k = 0; _k < (max); _k++) {                   \
                        const char *_t;                                 \
                        _t = name##_to_string(_k);                      \
                        if (!_t)                                        \
                                continue;                               \
                        fputs_unlocked(_t, stdout);                     \
                        fputc_unlocked('\n', stdout);                   \
                }                                                       \
                funlockfile(stdout);                                    \
                0;                                                      \
        })
