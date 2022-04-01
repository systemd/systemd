/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/netlink.h>

#include "netlink-genl.h"
#include "netlink-internal.h"
#include "netlink-types-internal.h"

static const NLType empty_types[1] = {
        /* fake array to avoid .types==NULL, which denotes invalid type-systems */
};

DEFINE_TYPE_SYSTEM(empty);

static const NLType error_types[] = {
        [NLMSGERR_ATTR_MSG]  = { .type = NETLINK_TYPE_STRING },
        [NLMSGERR_ATTR_OFFS] = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(error);

static const NLType basic_types[] = {
        [NLMSG_DONE]  = { .type = NETLINK_TYPE_NESTED, .type_system = &empty_type_system },
        [NLMSG_ERROR] = { .type = NETLINK_TYPE_NESTED, .type_system = &error_type_system, .size = sizeof(struct nlmsgerr) },
};

DEFINE_TYPE_SYSTEM(basic);

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

int type_system_root_get_type_system_and_header_size(
                sd_netlink *nl,
                uint16_t type,
                const NLTypeSystem **ret_type_system,
                size_t *ret_header_size) {

        const NLType *nl_type;

        assert(nl);

        if (IN_SET(type, NLMSG_DONE, NLMSG_ERROR))
                nl_type = type_system_get_type(&basic_type_system, type);
        else
                switch (nl->protocol) {
                case NETLINK_ROUTE:
                        nl_type = rtnl_get_type(type);
                        break;
                case NETLINK_NETFILTER:
                        nl_type = nfnl_get_type(type);
                        break;
                case NETLINK_GENERIC:
                        return genl_get_type_system_and_header_size(nl, type, ret_type_system, ret_header_size);
                default:
                        return -EOPNOTSUPP;
                }
        if (!nl_type)
                return -EOPNOTSUPP;

        if (type_get_type(nl_type) != NETLINK_TYPE_NESTED)
                return -EOPNOTSUPP;

        if (ret_type_system)
                *ret_type_system = type_get_type_system(nl_type);
        if (ret_header_size)
                *ret_header_size = type_get_size(nl_type);
        return 0;
}

const NLType *type_system_get_type(const NLTypeSystem *type_system, uint16_t type) {
        const NLType *nl_type;

        assert(type_system);
        assert(type_system->types);

        if (type >= type_system->count)
                return NULL;

        nl_type = &type_system->types[type];

        if (nl_type->type == NETLINK_TYPE_UNSPEC)
                return NULL;

        return nl_type;
}

const NLTypeSystem *type_system_get_type_system(const NLTypeSystem *type_system, uint16_t type) {
        const NLType *nl_type;

        nl_type = type_system_get_type(type_system, type);
        if (!nl_type)
                return NULL;

        return type_get_type_system(nl_type);
}

const NLTypeSystemUnion *type_system_get_type_system_union(const NLTypeSystem *type_system, uint16_t type) {
        const NLType *nl_type;

        nl_type = type_system_get_type(type_system, type);
        if (!nl_type)
                return NULL;

        return type_get_type_system_union(nl_type);
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

const NLTypeSystem *type_system_union_get_type_system_by_string(const NLTypeSystemUnion *type_system_union, const char *key) {
        assert(type_system_union);
        assert(type_system_union->elements);
        assert(type_system_union->match_type == NL_MATCH_SIBLING);
        assert(key);

        for (size_t i = 0; i < type_system_union->count; i++)
                if (streq(type_system_union->elements[i].name, key))
                        return &type_system_union->elements[i].type_system;

        return NULL;
}

const NLTypeSystem *type_system_union_get_type_system_by_protocol(const NLTypeSystemUnion *type_system_union, uint16_t protocol) {
        assert(type_system_union);
        assert(type_system_union->elements);
        assert(type_system_union->match_type == NL_MATCH_PROTOCOL);

        for (size_t i = 0; i < type_system_union->count; i++)
                if (type_system_union->elements[i].protocol == protocol)
                        return &type_system_union->elements[i].type_system;

        return NULL;
}
