/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>

#include "sd-netlink.h"

typedef enum NLAType {
        NETLINK_TYPE_UNSPEC,                    /* NLA_UNSPEC */
        NETLINK_TYPE_BINARY,                    /* NLA_BINARY */
        NETLINK_TYPE_FLAG,                      /* NLA_FLAG */
        NETLINK_TYPE_U8,                        /* NLA_U8 */
        NETLINK_TYPE_U16,                       /* NLA_U16 */
        NETLINK_TYPE_U32,                       /* NLA_U32 */
        NETLINK_TYPE_U64,                       /* NLA_U64 */
        NETLINK_TYPE_S8,                        /* NLA_S8 */
        NETLINK_TYPE_S16,                       /* NLA_S16 */
        NETLINK_TYPE_S32,                       /* NLA_S32 */
        NETLINK_TYPE_S64,                       /* NLA_S64 */
        NETLINK_TYPE_STRING,                    /* NLA_STRING */
        NETLINK_TYPE_BITFIELD32,                /* NLA_BITFIELD32 */
        NETLINK_TYPE_REJECT,                    /* NLA_REJECT */
        NETLINK_TYPE_IN_ADDR,
        NETLINK_TYPE_ETHER_ADDR,
        NETLINK_TYPE_CACHE_INFO,
        NETLINK_TYPE_SOCKADDR,
        NETLINK_TYPE_NESTED,                    /* NLA_NESTED */
        NETLINK_TYPE_NESTED_UNION_BY_STRING,
        NETLINK_TYPE_NESTED_UNION_BY_FAMILY,
        _NETLINK_TYPE_MAX,
        _NETLINK_TYPE_INVALID = -EINVAL,
} NLAType;

typedef struct NLAPolicy NLAPolicy;
typedef struct NLAPolicySet NLAPolicySet;
typedef struct NLAPolicySetUnion NLAPolicySetUnion;

const NLAPolicy *rtnl_get_policy(uint16_t nlmsg_type);
const NLAPolicy *nfnl_get_policy(uint16_t nlmsg_type);
const NLAPolicySet *genl_get_policy_set_by_name(const char *name);
int genl_get_policy_set_and_header_size(
                sd_netlink *nl,
                uint16_t id,
                const NLAPolicySet **ret_policy_set,
                size_t *ret_header_size);

NLAType policy_get_type(const NLAPolicy *policy);
size_t policy_get_size(const NLAPolicy *policy);
const NLAPolicySet *policy_get_policy_set(const NLAPolicy *policy);
const NLAPolicySetUnion *policy_get_policy_set_union(const NLAPolicy *policy);

int netlink_get_policy_set_and_header_size(
                sd_netlink *nl,
                uint16_t type,
                const NLAPolicySet **ret_policy_set,
                size_t *ret_header_size);

const NLAPolicy *policy_set_get_policy(const NLAPolicySet *policy_set, uint16_t attr_type);
const NLAPolicySet *policy_set_get_policy_set(const NLAPolicySet *type_system, uint16_t attr_type);
const NLAPolicySetUnion *policy_set_get_policy_set_union(const NLAPolicySet *type_system, uint16_t attr_type);
uint16_t policy_set_union_get_match_attribute(const NLAPolicySetUnion *policy_set_union);
const NLAPolicySet *policy_set_union_get_policy_set_by_string(const NLAPolicySetUnion *type_system_union, const char *string);
const NLAPolicySet *policy_set_union_get_policy_set_by_family(const NLAPolicySetUnion *type_system_union, int family);
