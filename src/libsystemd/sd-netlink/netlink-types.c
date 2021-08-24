/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/netlink.h>

#include "netlink-internal.h"
#include "netlink-types-internal.h"

static const NLType empty_types[1] = {
        /* fake array to avoid .types==NULL, which denotes invalid type-systems */
};

static const NLTypeSystem empty_type_system = {
        .count = 0,
        .types = empty_types,
};

static const NLType error_types[] = {
        [NLMSGERR_ATTR_MSG]  = { .type = NETLINK_TYPE_STRING },
        [NLMSGERR_ATTR_OFFS] = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem error_type_system = {
        .count = ELEMENTSOF(error_types),
        .types = error_types,
};

static const NLType basic_types[] = {
        [NLMSG_DONE]  = { .type = NETLINK_TYPE_NESTED, .type_system = &empty_type_system },
        [NLMSG_ERROR] = { .type = NETLINK_TYPE_NESTED, .type_system = &error_type_system, .size = sizeof(struct nlmsgerr) },
};

const NLTypeSystem basic_type_system = {
        .count = ELEMENTSOF(basic_types),
        .types = basic_types,
};

uint16_t type_get_type(const NLType *type) {
        assert(type);
        return type->type;
}

size_t type_get_size(const NLType *type) {
        assert(type);
        return type->size;
}

const NLTypeSystem *type_get_type_system(const NLType *nl_type) {
        assert(nl_type);
        assert(nl_type->type == NETLINK_TYPE_NESTED);
        assert(nl_type->type_system);
        return nl_type->type_system;
}

const NLTypeSystemUnion *type_get_type_system_union(const NLType *nl_type) {
        assert(nl_type);
        assert(nl_type->type == NETLINK_TYPE_UNION);
        assert(nl_type->type_system_union);
        return nl_type->type_system_union;
}

uint16_t type_system_get_count(const NLTypeSystem *type_system) {
        assert(type_system);
        return type_system->count;
}

int type_system_root_get_type(sd_netlink *nl, const NLType **ret, uint16_t type) {
        if (!nl || IN_SET(type, NLMSG_DONE, NLMSG_ERROR))
                return type_system_get_type(&basic_type_system, ret, type);

        switch(nl->protocol) {
        case NETLINK_ROUTE:
                return rtnl_get_type(type, ret);
        case NETLINK_NETFILTER:
                return nfnl_get_type(type, ret);
        case NETLINK_GENERIC:
                return genl_get_type(nl, type, ret);
        default:
                return -EOPNOTSUPP;
        }
}

int type_system_get_type(const NLTypeSystem *type_system, const NLType **ret, uint16_t type) {
        const NLType *nl_type;

        assert(ret);
        assert(type_system);
        assert(type_system->types);

        if (type >= type_system->count)
                return -EOPNOTSUPP;

        nl_type = &type_system->types[type];

        if (nl_type->type == NETLINK_TYPE_UNSPEC)
                return -EOPNOTSUPP;

        *ret = nl_type;
        return 0;
}

int type_system_get_type_system(const NLTypeSystem *type_system, const NLTypeSystem **ret, uint16_t type) {
        const NLType *nl_type;
        int r;

        assert(ret);

        r = type_system_get_type(type_system, &nl_type, type);
        if (r < 0)
                return r;

        *ret = type_get_type_system(nl_type);
        return 0;
}

int type_system_get_type_system_union(const NLTypeSystem *type_system, const NLTypeSystemUnion **ret, uint16_t type) {
        const NLType *nl_type;
        int r;

        assert(ret);

        r = type_system_get_type(type_system, &nl_type, type);
        if (r < 0)
                return r;

        *ret = type_get_type_system_union(nl_type);
        return 0;
}

NLMatchType type_system_union_get_match_type(const NLTypeSystemUnion *type_system_union) {
        assert(type_system_union);
        return type_system_union->match_type;
}

uint16_t type_system_union_get_match_attribute(const NLTypeSystemUnion *type_system_union) {
        assert(type_system_union);
        assert(type_system_union->match_type == NL_MATCH_SIBLING);
        return type_system_union->match_attribute;
}

int type_system_union_get_type_system_by_string(const NLTypeSystemUnion *type_system_union, const NLTypeSystem **ret, const char *key) {
        assert(type_system_union);
        assert(type_system_union->elements);
        assert(type_system_union->match_type == NL_MATCH_SIBLING);
        assert(ret);
        assert(key);

        for (size_t i = 0; i < type_system_union->count; i++)
                if (streq(type_system_union->elements[i].name, key)) {
                        *ret = &type_system_union->elements[i].type_system;
                        return 0;
                }

        return -EOPNOTSUPP;
}

int type_system_union_get_type_system_by_protocol(const NLTypeSystemUnion *type_system_union, const NLTypeSystem **ret, uint16_t protocol) {
        assert(type_system_union);
        assert(type_system_union->elements);
        assert(type_system_union->match_type == NL_MATCH_PROTOCOL);
        assert(ret);

        for (size_t i = 0; i < type_system_union->count; i++)
                if (type_system_union->elements[i].protocol == protocol) {
                        *ret = &type_system_union->elements[i].type_system;
                        return 0;
                }

        return -EOPNOTSUPP;
}
