/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"
#include "netlink-types.h"

/* C.f. see 'struct nla_policy' at include/net/netlink.h. */
struct NLAPolicy {
        NLAType type;
        size_t size;
        union {
                const NLAPolicySet *policy_set;
                const NLAPolicySetUnion *policy_set_union;
        };
};

struct NLAPolicySet {
        uint16_t count;
        const NLAPolicy *policies;
};

typedef struct NLAPolicySetUnionElement {
        union {
                int family;          /* used by NETLINK_TYPE_NESTED_UNION_BY_FAMILY */
                const char *string;  /* used by NETLINK_TYPE_NESTED_UNION_BY_STRING */
        };
        NLAPolicySet policy_set;
} NLAPolicySetUnionElement;

struct NLAPolicySetUnion {
        size_t count;
        const NLAPolicySetUnionElement *elements;
        uint16_t match_attribute; /* used by NETLINK_TYPE_NESTED_UNION_BY_STRING */
};

#define BUILD_POLICY_WITH_SIZE(t, n)            \
        { .type = NETLINK_TYPE_##t, .size = n }
#define BUILD_POLICY(t)                         \
        BUILD_POLICY_WITH_SIZE(t, 0)
#define BUILD_POLICY_NESTED_WITH_SIZE(name, n)                          \
        { .type = NETLINK_TYPE_NESTED, .size = n, .policy_set = &name##_policy_set }
#define BUILD_POLICY_NESTED(name)               \
        BUILD_POLICY_NESTED_WITH_SIZE(name, 0)
#define _BUILD_POLICY_NESTED_UNION(name, by)                            \
        { .type = NETLINK_TYPE_NESTED_UNION_BY_##by, .policy_set_union = &name##_policy_set_union }
#define BUILD_POLICY_NESTED_UNION_BY_STRING(name)       \
        _BUILD_POLICY_NESTED_UNION(name, STRING)
#define BUILD_POLICY_NESTED_UNION_BY_FAMILY(name)       \
        _BUILD_POLICY_NESTED_UNION(name, FAMILY)

#define _BUILD_POLICY_SET(name)                                         \
        { .count = ELEMENTSOF(name##_policies), .policies = name##_policies }
#define DEFINE_POLICY_SET(name)                                         \
        static const NLAPolicySet name##_policy_set = _BUILD_POLICY_SET(name)

# define BUILD_UNION_ELEMENT_BY_STRING(s, name)                 \
        { .string = s, .policy_set = _BUILD_POLICY_SET(name) }
# define BUILD_UNION_ELEMENT_BY_FAMILY(f, name)                 \
        { .family = f, .policy_set = _BUILD_POLICY_SET(name) }

#define DEFINE_POLICY_SET_UNION(name, attr)                             \
        static const NLAPolicySetUnion name##_policy_set_union = {      \
                .count = ELEMENTSOF(name##_policy_set_union_elements),  \
                .elements = name##_policy_set_union_elements,           \
                .match_attribute = attr,                                \
        }
