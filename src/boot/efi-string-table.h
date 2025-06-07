/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro-fundamental.h"

#define _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,scope)          \
        scope const char* name##_to_string(type i) {                    \
                assert(i >= 0 && i < (type) ELEMENTSOF(name##_table));  \
                return name##_table[i];                                 \
        }

#define DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type) _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(name,type) _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,static)
