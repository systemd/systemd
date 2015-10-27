
/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#define _DEFINE_STRING_TABLE_LOOKUP(name,type,scope)                    \
        _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,scope)          \
        _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name,type,scope)        \
        struct __useless_struct_to_allow_trailing_semicolon__

#define DEFINE_STRING_TABLE_LOOKUP(name,type) _DEFINE_STRING_TABLE_LOOKUP(name,type,)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP(name,type) _DEFINE_STRING_TABLE_LOOKUP(name,type,static)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(name,type) _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,static)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(name,type) _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name,type,static)

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
