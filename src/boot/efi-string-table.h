/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi-string.h"
#include "macro-fundamental.h"

#define _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,scope)                          \
        scope const char* name##_to_string(type i) {                                    \
                assert(i >= 0 && i < (type) ELEMENTSOF(name##_table));                  \
                return name##_table[i];                                                 \
        }

#define _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name, type, scope)    \
        scope type name##_from_string(const char *s) {                \
                if (!s)                                               \
                        return (type) -1;                             \
                for (size_t i = 0; i < ELEMENTSOF(name##_table); ++i) \
                        if (streq8(name##_table[i], s))               \
                                return (type) i;                      \
                return (type) -1;                                     \
        }

#define _DEFINE_STRING_TABLE_LOOKUP(name, type, scope)             \
        _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name, type, scope)   \
        _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name, type, scope)

#define DEFINE_STRING_TABLE_LOOKUP(name, type) _DEFINE_STRING_TABLE_LOOKUP(name, type,)
#define DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type) _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,)
#define DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name, type) _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name, type,)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP(name, type) _DEFINE_STRING_TABLE_LOOKUP(name, type, static)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(name,type) _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,static)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(name, type) _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name, type, static)
