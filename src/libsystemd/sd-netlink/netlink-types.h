/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "macro.h"

enum {
        NETLINK_TYPE_UNSPEC,
        NETLINK_TYPE_U8,                        /* NLA_U8 */
        NETLINK_TYPE_U16,                       /* NLA_U16 */
        NETLINK_TYPE_U32,                       /* NLA_U32 */
        NETLINK_TYPE_U64,                       /* NLA_U64 */
        NETLINK_TYPE_STRING,                    /* NLA_STRING */
        NETLINK_TYPE_FLAG,                      /* NLA_FLAG */
        NETLINK_TYPE_IN_ADDR,
        NETLINK_TYPE_ETHER_ADDR,
        NETLINK_TYPE_CACHE_INFO,
        NETLINK_TYPE_NESTED,                    /* NLA_NESTED */
        NETLINK_TYPE_UNION,
};

typedef enum NLMatchType {
        NL_MATCH_SIBLING,
        NL_MATCH_PROTOCOL,
} NLMatchType;

typedef struct NLTypeSystemUnion NLTypeSystemUnion;
typedef struct NLTypeSystem NLTypeSystem;
typedef struct NLType NLType;

struct NLTypeSystemUnion {
        int num;
        NLMatchType match_type;
        uint16_t match;
        int (*lookup)(const char *);
        const NLTypeSystem *type_systems;
};

extern const NLTypeSystem rtnl_type_system_root;
extern const NLTypeSystem genl_type_system_root;
extern const NLTypeSystem genl_family_type_system_root;

uint16_t type_get_type(const NLType *type);
size_t type_get_size(const NLType *type);
void type_get_type_system(const NLType *type, const NLTypeSystem **ret);
void type_get_type_system_union(const NLType *type, const NLTypeSystemUnion **ret);

const NLTypeSystem* type_system_get_root(int protocol);
uint16_t type_system_get_count(const NLTypeSystem *type_system);
int type_system_get_type(const NLTypeSystem *type_system, const NLType **ret, uint16_t type);
int type_system_get_type_system(const NLTypeSystem *type_system, const NLTypeSystem **ret, uint16_t type);
int type_system_get_type_system_union(const NLTypeSystem *type_system, const NLTypeSystemUnion **ret, uint16_t type);
int type_system_union_get_type_system(const NLTypeSystemUnion *type_system_union, const NLTypeSystem **ret, const char *key);
int type_system_union_protocol_get_type_system(const NLTypeSystemUnion *type_system_union, const NLTypeSystem **ret, uint16_t protocol);

typedef enum NLUnionLinkInfoData {
        NL_UNION_LINK_INFO_DATA_BOND,
        NL_UNION_LINK_INFO_DATA_BRIDGE,
        NL_UNION_LINK_INFO_DATA_VLAN,
        NL_UNION_LINK_INFO_DATA_VETH,
        NL_UNION_LINK_INFO_DATA_DUMMY,
        NL_UNION_LINK_INFO_DATA_MACVLAN,
        NL_UNION_LINK_INFO_DATA_MACVTAP,
        NL_UNION_LINK_INFO_DATA_IPVLAN,
        NL_UNION_LINK_INFO_DATA_VXLAN,
        NL_UNION_LINK_INFO_DATA_IPIP_TUNNEL,
        NL_UNION_LINK_INFO_DATA_IPGRE_TUNNEL,
        NL_UNION_LINK_INFO_DATA_IPGRETAP_TUNNEL,
        NL_UNION_LINK_INFO_DATA_IP6GRE_TUNNEL,
        NL_UNION_LINK_INFO_DATA_IP6GRETAP_TUNNEL,
        NL_UNION_LINK_INFO_DATA_SIT_TUNNEL,
        NL_UNION_LINK_INFO_DATA_VTI_TUNNEL,
        NL_UNION_LINK_INFO_DATA_VTI6_TUNNEL,
        NL_UNION_LINK_INFO_DATA_IP6TNL_TUNNEL,
        NL_UNION_LINK_INFO_DATA_VRF,
        NL_UNION_LINK_INFO_DATA_VCAN,
        NL_UNION_LINK_INFO_DATA_GENEVE,
        NL_UNION_LINK_INFO_DATA_VXCAN,
        NL_UNION_LINK_INFO_DATA_WIREGUARD,
        NL_UNION_LINK_INFO_DATA_NETDEVSIM,
        NL_UNION_LINK_INFO_DATA_CAN,
        _NL_UNION_LINK_INFO_DATA_MAX,
        _NL_UNION_LINK_INFO_DATA_INVALID = -1
} NLUnionLinkInfoData;

const char *nl_union_link_info_data_to_string(NLUnionLinkInfoData p) _const_;
NLUnionLinkInfoData nl_union_link_info_data_from_string(const char *p) _pure_;
