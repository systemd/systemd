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
