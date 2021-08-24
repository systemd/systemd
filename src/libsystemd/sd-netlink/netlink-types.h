/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

enum {
        NETLINK_TYPE_UNSPEC,
        NETLINK_TYPE_U8,                        /* NLA_U8 */
        NETLINK_TYPE_U16,                       /* NLA_U16 */
        NETLINK_TYPE_U32,                       /* NLA_U32 */
        NETLINK_TYPE_U64,                       /* NLA_U64 */
        NETLINK_TYPE_S8,                        /* NLA_S8 */
        NETLINK_TYPE_S16,                       /* NLA_S16 */
        NETLINK_TYPE_S32,                       /* NLA_S32 */
        NETLINK_TYPE_S64,                       /* NLA_S64 */
        NETLINK_TYPE_STRING,                    /* NLA_STRING */
        NETLINK_TYPE_FLAG,                      /* NLA_FLAG */
        NETLINK_TYPE_IN_ADDR,
        NETLINK_TYPE_ETHER_ADDR,
        NETLINK_TYPE_CACHE_INFO,
        NETLINK_TYPE_NESTED,                    /* NLA_NESTED */
        NETLINK_TYPE_UNION,
        NETLINK_TYPE_SOCKADDR,
        NETLINK_TYPE_BINARY,
        NETLINK_TYPE_BITFIELD32,                /* NLA_BITFIELD32 */
        NETLINK_TYPE_REJECT,                    /* NLA_REJECT */
};

typedef enum NLMatchType {
        NL_MATCH_SIBLING,
        NL_MATCH_PROTOCOL,
} NLMatchType;

typedef struct NLTypeSystemUnion NLTypeSystemUnion;
typedef struct NLTypeSystem NLTypeSystem;
typedef struct NLType NLType;

extern const NLTypeSystem genl_family_type_system;

int rtnl_get_type(uint16_t nlmsg_type, const NLType **ret);
int nfnl_get_type(uint16_t nlmsg_type, const NLType **ret);
int genl_get_type(sd_netlink *genl, uint16_t nlmsg_type, const NLType **ret);

uint16_t type_get_type(const NLType *type);
size_t type_get_size(const NLType *type);
const NLTypeSystem *type_get_type_system(const NLType *type);
const NLTypeSystemUnion *type_get_type_system_union(const NLType *type);

uint16_t type_system_get_count(const NLTypeSystem *type_system);
int type_system_root_get_type(sd_netlink *nl, const NLType **ret, uint16_t type);
int type_system_get_type(const NLTypeSystem *type_system, const NLType **ret, uint16_t type);
int type_system_get_type_system(const NLTypeSystem *type_system, const NLTypeSystem **ret, uint16_t type);
int type_system_get_type_system_union(const NLTypeSystem *type_system, const NLTypeSystemUnion **ret, uint16_t type);
NLMatchType type_system_union_get_match_type(const NLTypeSystemUnion *type_system_union);
uint16_t type_system_union_get_match_attribute(const NLTypeSystemUnion *type_system_union);
int type_system_union_get_type_system_by_string(const NLTypeSystemUnion *type_system_union, const NLTypeSystem **ret, const char *key);
int type_system_union_get_type_system_by_protocol(const NLTypeSystemUnion *type_system_union, const NLTypeSystem **ret, uint16_t protocol);
