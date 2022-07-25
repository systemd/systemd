/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/netlink.h>

#include "netlink-genl.h"
#include "netlink-internal.h"
#include "netlink-types-internal.h"

static const NLAPolicy empty_policies[1] = {
        /* fake array to avoid .types==NULL, which denotes invalid type-systems */
};

DEFINE_POLICY_SET(empty);

static const NLAPolicy error_policies[] = {
        [NLMSGERR_ATTR_MSG]  = BUILD_POLICY(STRING),
        [NLMSGERR_ATTR_OFFS] = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(error);

static const NLAPolicy basic_policies[] = {
        [NLMSG_DONE]  = BUILD_POLICY_NESTED(empty),
        [NLMSG_ERROR] = BUILD_POLICY_NESTED_WITH_SIZE(error, sizeof(struct nlmsgerr)),
};

DEFINE_POLICY_SET(basic);

NLAType policy_get_type(const NLAPolicy *policy) {
        return ASSERT_PTR(policy)->type;
}

size_t policy_get_size(const NLAPolicy *policy) {
        return ASSERT_PTR(policy)->size;
}

const NLAPolicySet *policy_get_policy_set(const NLAPolicy *policy) {
        assert(policy);
        assert(policy->type == NETLINK_TYPE_NESTED);

        return ASSERT_PTR(policy->policy_set);
}

const NLAPolicySetUnion *policy_get_policy_set_union(const NLAPolicy *policy) {
        assert(policy);
        assert(IN_SET(policy->type, NETLINK_TYPE_NESTED_UNION_BY_STRING, NETLINK_TYPE_NESTED_UNION_BY_FAMILY));

        return ASSERT_PTR(policy->policy_set_union);
}

int netlink_get_policy_set_and_header_size(
                sd_netlink *nl,
                uint16_t type,
                const NLAPolicySet **ret_policy_set,
                size_t *ret_header_size) {

        const NLAPolicy *policy;

        assert(nl);

        if (IN_SET(type, NLMSG_DONE, NLMSG_ERROR))
                policy = policy_set_get_policy(&basic_policy_set, type);
        else
                switch (nl->protocol) {
                case NETLINK_ROUTE:
                        policy = rtnl_get_policy(type);
                        break;
                case NETLINK_NETFILTER:
                        policy = nfnl_get_policy(type);
                        break;
                case NETLINK_GENERIC:
                        return genl_get_policy_set_and_header_size(nl, type, ret_policy_set, ret_header_size);
                default:
                        return -EOPNOTSUPP;
                }
        if (!policy)
                return -EOPNOTSUPP;

        if (policy_get_type(policy) != NETLINK_TYPE_NESTED)
                return -EOPNOTSUPP;

        if (ret_policy_set)
                *ret_policy_set = policy_get_policy_set(policy);
        if (ret_header_size)
                *ret_header_size = policy_get_size(policy);
        return 0;
}

const NLAPolicy *policy_set_get_policy(const NLAPolicySet *policy_set, uint16_t attr_type) {
        const NLAPolicy *policy;

        assert(policy_set);
        assert(policy_set->policies);

        if (attr_type >= policy_set->count)
                return NULL;

        policy = &policy_set->policies[attr_type];

        if (policy->type == NETLINK_TYPE_UNSPEC)
                return NULL;

        return policy;
}

const NLAPolicySet *policy_set_get_policy_set(const NLAPolicySet *policy_set, uint16_t attr_type) {
        const NLAPolicy *policy;

        policy = policy_set_get_policy(policy_set, attr_type);
        if (!policy)
                return NULL;

        return policy_get_policy_set(policy);
}

const NLAPolicySetUnion *policy_set_get_policy_set_union(const NLAPolicySet *policy_set, uint16_t attr_type) {
        const NLAPolicy *policy;

        policy = policy_set_get_policy(policy_set, attr_type);
        if (!policy)
                return NULL;

        return policy_get_policy_set_union(policy);
}

uint16_t policy_set_union_get_match_attribute(const NLAPolicySetUnion *policy_set_union) {
        assert(policy_set_union->match_attribute != 0);

        return policy_set_union->match_attribute;
}

const NLAPolicySet *policy_set_union_get_policy_set_by_string(const NLAPolicySetUnion *policy_set_union, const char *string) {
        assert(policy_set_union);
        assert(policy_set_union->elements);
        assert(string);

        for (size_t i = 0; i < policy_set_union->count; i++)
                if (streq(policy_set_union->elements[i].string, string))
                        return &policy_set_union->elements[i].policy_set;

        return NULL;
}

const NLAPolicySet *policy_set_union_get_policy_set_by_family(const NLAPolicySetUnion *policy_set_union, int family) {
        assert(policy_set_union);
        assert(policy_set_union->elements);

        for (size_t i = 0; i < policy_set_union->count; i++)
                if (policy_set_union->elements[i].family == family)
                        return &policy_set_union->elements[i].policy_set;

        return NULL;
}
