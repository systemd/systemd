
#pragma once

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
                b = parse_boolean(s);                                   \
                if (b == 0)                                             \
                        return (type) 0;                                \
                else if (b > 0)                                         \
                        return yes;                                     \
                return (type) string_table_lookup(name##_table, ELEMENTSOF(name##_table), s); \
        }

#define _DEFINE_STRING_TABLE_LOOKUP(name,type,scope)                    \
        _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,scope)          \
        _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name,type,scope)        \
        struct __useless_struct_to_allow_trailing_semicolon__

#define _DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(name,type,yes,scope)   \
        _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,scope)          \
        _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(name,type,yes,scope) \
        struct __useless_struct_to_allow_trailing_semicolon__

#define DEFINE_STRING_TABLE_LOOKUP(name,type) _DEFINE_STRING_TABLE_LOOKUP(name,type,)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP(name,type) _DEFINE_STRING_TABLE_LOOKUP(name,type,static)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(name,type) _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,static)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(name,type) _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name,type,static)

#define DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(name,type,yes) _DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(name,type,yes,)

/* For string conversions where numbers are also acceptable */
#define DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(name,type,max)         \
        int name##_to_string_alloc(type i, char **str) {                \
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
        }                                                               \
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
        struct __useless_struct_to_allow_trailing_semicolon__
