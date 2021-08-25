/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"
#include "netlink-types.h"

struct NLType {
        uint16_t type;
        size_t size;
        const NLTypeSystem *type_system;
        const NLTypeSystemUnion *type_system_union;
};

struct NLTypeSystem {
        uint16_t count;
        const NLType *types;
};

#define TYPE_SYSTEM_FROM_TYPE(name)                                     \
        { .count = ELEMENTSOF(name##_types), .types = name##_types }
#define DEFINE_TYPE_SYSTEM(name)                                        \
        static const NLTypeSystem name##_type_system = TYPE_SYSTEM_FROM_TYPE(name);

typedef struct NLTypeSystemUnionElement {
        union {
                int protocol;
                const char *name;
        };
        NLTypeSystem type_system;
} NLTypeSystemUnionElement;

struct NLTypeSystemUnion {
        size_t count;
        const NLTypeSystemUnionElement *elements;
        NLMatchType match_type;
        uint16_t match_attribute;
};
