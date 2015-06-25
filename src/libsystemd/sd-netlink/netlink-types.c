/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Tom Gundersen <teg@jklm.no>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdint.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/in6.h>
#include <linux/veth.h>
#include <linux/if_bridge.h>
#include <linux/if_addr.h>
#include <linux/if.h>

#include <linux/ip.h>
#include <linux/if_link.h>
#include <linux/if_tunnel.h>

#include "macro.h"
#include "util.h"

#include "netlink-types.h"
#include "missing.h"

/* Maximum ARP IP target defined in kernel */
#define BOND_MAX_ARP_TARGETS    16

typedef enum {
        BOND_ARP_TARGETS_0,
        BOND_ARP_TARGETS_1,
        BOND_ARP_TARGETS_2,
        BOND_ARP_TARGETS_3,
        BOND_ARP_TARGETS_4,
        BOND_ARP_TARGETS_5,
        BOND_ARP_TARGETS_6,
        BOND_ARP_TARGETS_7,
        BOND_ARP_TARGETS_8,
        BOND_ARP_TARGETS_9,
        BOND_ARP_TARGETS_10,
        BOND_ARP_TARGETS_11,
        BOND_ARP_TARGETS_12,
        BOND_ARP_TARGETS_13,
        BOND_ARP_TARGETS_14,
        BOND_ARP_TARGETS_MAX = BOND_MAX_ARP_TARGETS,
} BondArpTargets;

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

static const NLTypeSystem rtnl_link_type_system;

static const NLType empty_types[1] = {
        /* fake array to avoid .types==NULL, which denotes invalid type-systems */
};

static const NLTypeSystem empty_type_system = {
        .count = 0,
        .types = empty_types,
};

static const NLType rtnl_link_info_data_veth_types[VETH_INFO_MAX + 1] = {
        [VETH_INFO_PEER]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
};

static const NLType rtnl_link_info_data_ipvlan_types[IFLA_IPVLAN_MAX + 1] = {
        [IFLA_IPVLAN_MODE]  = { .type = NETLINK_TYPE_U16 },
};

static const NLType rtnl_link_info_data_macvlan_types[IFLA_MACVLAN_MAX + 1] = {
        [IFLA_MACVLAN_MODE]  = { .type = NETLINK_TYPE_U32 },
        [IFLA_MACVLAN_FLAGS] = { .type = NETLINK_TYPE_U16 },
};

static const NLType rtnl_link_info_data_bridge_types[IFLA_BRIDGE_MAX + 1] = {
        [IFLA_BRIDGE_FLAGS]     = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRIDGE_MODE]      = { .type = NETLINK_TYPE_U16 },
/*
        [IFLA_BRIDGE_VLAN_INFO] = { .type = NETLINK_TYPE_BINARY,
                                    .len = sizeof(struct bridge_vlan_info), },
*/
};

static const NLType rtnl_link_info_data_vlan_types[IFLA_VLAN_MAX + 1] = {
        [IFLA_VLAN_ID]          = { .type = NETLINK_TYPE_U16 },
/*
        [IFLA_VLAN_FLAGS]       = { .len = sizeof(struct ifla_vlan_flags) },
        [IFLA_VLAN_EGRESS_QOS]  = { .type = NETLINK_TYPE_NESTED },
        [IFLA_VLAN_INGRESS_QOS] = { .type = NETLINK_TYPE_NESTED },
*/
        [IFLA_VLAN_PROTOCOL]    = { .type = NETLINK_TYPE_U16 },
};

static const NLType rtnl_link_info_data_vxlan_types[IFLA_VXLAN_MAX+1] = {
        [IFLA_VXLAN_ID]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_VXLAN_GROUP]      = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_VXLAN_LINK]       = { .type = NETLINK_TYPE_U32 },
        [IFLA_VXLAN_LOCAL]      = { .type = NETLINK_TYPE_U32},
        [IFLA_VXLAN_TTL]        = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_TOS]        = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_LEARNING]   = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_AGEING]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_VXLAN_LIMIT]      = { .type = NETLINK_TYPE_U32 },
        [IFLA_VXLAN_PORT_RANGE] = { .type = NETLINK_TYPE_U32},
        [IFLA_VXLAN_PROXY]      = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_RSC]        = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_L2MISS]     = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_L3MISS]     = { .type = NETLINK_TYPE_U8 },
};

static const NLType rtnl_bond_arp_target_types[BOND_ARP_TARGETS_MAX + 1] = {
        [BOND_ARP_TARGETS_0]        = { .type = NETLINK_TYPE_U32 },
        [BOND_ARP_TARGETS_1]        = { .type = NETLINK_TYPE_U32 },
        [BOND_ARP_TARGETS_2]        = { .type = NETLINK_TYPE_U32 },
        [BOND_ARP_TARGETS_3]        = { .type = NETLINK_TYPE_U32 },
        [BOND_ARP_TARGETS_4]        = { .type = NETLINK_TYPE_U32 },
        [BOND_ARP_TARGETS_5]        = { .type = NETLINK_TYPE_U32 },
        [BOND_ARP_TARGETS_6]        = { .type = NETLINK_TYPE_U32 },
        [BOND_ARP_TARGETS_7]        = { .type = NETLINK_TYPE_U32 },
        [BOND_ARP_TARGETS_8]        = { .type = NETLINK_TYPE_U32 },
        [BOND_ARP_TARGETS_9]        = { .type = NETLINK_TYPE_U32 },
        [BOND_ARP_TARGETS_10]       = { .type = NETLINK_TYPE_U32 },
        [BOND_ARP_TARGETS_11]       = { .type = NETLINK_TYPE_U32 },
        [BOND_ARP_TARGETS_12]       = { .type = NETLINK_TYPE_U32 },
        [BOND_ARP_TARGETS_13]       = { .type = NETLINK_TYPE_U32 },
        [BOND_ARP_TARGETS_14]       = { .type = NETLINK_TYPE_U32 },
        [BOND_ARP_TARGETS_MAX]      = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem rtnl_bond_arp_type_system = {
        .count = ELEMENTSOF(rtnl_bond_arp_target_types),
        .types = rtnl_bond_arp_target_types,
};

static const NLType rtnl_link_info_data_bond_types[IFLA_BOND_MAX + 1] = {
        [IFLA_BOND_MODE]                = { .type = NETLINK_TYPE_U8 },
        [IFLA_BOND_ACTIVE_SLAVE]        = { .type = NETLINK_TYPE_U32 },
        [IFLA_BOND_MIIMON]              = { .type = NETLINK_TYPE_U32 },
        [IFLA_BOND_UPDELAY]             = { .type = NETLINK_TYPE_U32 },
        [IFLA_BOND_DOWNDELAY]           = { .type = NETLINK_TYPE_U32 },
        [IFLA_BOND_USE_CARRIER]         = { .type = NETLINK_TYPE_U8 },
        [IFLA_BOND_ARP_INTERVAL]        = { .type = NETLINK_TYPE_U32 },
        [IFLA_BOND_ARP_IP_TARGET]       = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bond_arp_type_system },
        [IFLA_BOND_ARP_VALIDATE]        = { .type = NETLINK_TYPE_U32 },
        [IFLA_BOND_ARP_ALL_TARGETS]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_BOND_PRIMARY]             = { .type = NETLINK_TYPE_U32 },
        [IFLA_BOND_PRIMARY_RESELECT]    = { .type = NETLINK_TYPE_U8 },
        [IFLA_BOND_FAIL_OVER_MAC]       = { .type = NETLINK_TYPE_U8 },
        [IFLA_BOND_XMIT_HASH_POLICY]    = { .type = NETLINK_TYPE_U8 },
        [IFLA_BOND_RESEND_IGMP]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_BOND_NUM_PEER_NOTIF]      = { .type = NETLINK_TYPE_U8 },
        [IFLA_BOND_ALL_SLAVES_ACTIVE]   = { .type = NETLINK_TYPE_U8 },
        [IFLA_BOND_MIN_LINKS]           = { .type = NETLINK_TYPE_U32 },
        [IFLA_BOND_LP_INTERVAL]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_BOND_PACKETS_PER_SLAVE]   = { .type = NETLINK_TYPE_U32 },
        [IFLA_BOND_AD_LACP_RATE]        = { .type = NETLINK_TYPE_U8 },
        [IFLA_BOND_AD_SELECT]           = { .type = NETLINK_TYPE_U8 },
        [IFLA_BOND_AD_INFO]             = { .type = NETLINK_TYPE_NESTED },
};

static const NLType rtnl_link_info_data_iptun_types[IFLA_IPTUN_MAX + 1] = {
        [IFLA_IPTUN_LINK]                = { .type = NETLINK_TYPE_U32 },
        [IFLA_IPTUN_LOCAL]               = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_IPTUN_REMOTE]              = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_IPTUN_TTL]                 = { .type = NETLINK_TYPE_U8 },
        [IFLA_IPTUN_TOS]                 = { .type = NETLINK_TYPE_U8 },
        [IFLA_IPTUN_PMTUDISC]            = { .type = NETLINK_TYPE_U8 },
        [IFLA_IPTUN_FLAGS]               = { .type = NETLINK_TYPE_U16 },
        [IFLA_IPTUN_PROTO]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_IPTUN_6RD_PREFIX]          = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_IPTUN_6RD_RELAY_PREFIX]    = { .type = NETLINK_TYPE_U32 },
        [IFLA_IPTUN_6RD_PREFIXLEN]       = { .type = NETLINK_TYPE_U16 },
        [IFLA_IPTUN_6RD_RELAY_PREFIXLEN] = { .type = NETLINK_TYPE_U16 },
};

static  const NLType rtnl_link_info_data_ipgre_types[IFLA_GRE_MAX + 1] = {
        [IFLA_GRE_LINK]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_GRE_IFLAGS]   = { .type = NETLINK_TYPE_U16 },
        [IFLA_GRE_OFLAGS]   = { .type = NETLINK_TYPE_U16 },
        [IFLA_GRE_IKEY]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_GRE_OKEY]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_GRE_LOCAL]    = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_GRE_REMOTE]   = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_GRE_TTL]      = { .type = NETLINK_TYPE_U8 },
        [IFLA_GRE_TOS]      = { .type = NETLINK_TYPE_U8 },
        [IFLA_GRE_PMTUDISC] = { .type = NETLINK_TYPE_U8 },
};

static const NLType rtnl_link_info_data_ipvti_types[IFLA_VTI_MAX + 1] = {
        [IFLA_VTI_LINK]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_VTI_IKEY]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_VTI_OKEY]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_VTI_LOCAL]        = { .type = NETLINK_TYPE_IN_ADDR  },
        [IFLA_VTI_REMOTE]       = { .type = NETLINK_TYPE_IN_ADDR  },
};

static const NLType rtnl_link_info_data_ip6tnl_types[IFLA_IPTUN_MAX + 1] = {
        [IFLA_IPTUN_LINK]                = { .type = NETLINK_TYPE_U32 },
        [IFLA_IPTUN_LOCAL]               = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_IPTUN_REMOTE]              = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_IPTUN_TTL]                 = { .type = NETLINK_TYPE_U8 },
        [IFLA_IPTUN_FLAGS]               = { .type = NETLINK_TYPE_U32 },
        [IFLA_IPTUN_PROTO]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_IPTUN_ENCAP_LIMIT]         = { .type = NETLINK_TYPE_U8 },
        [IFLA_IPTUN_FLOWINFO]            = { .type = NETLINK_TYPE_U32},
};

/* these strings must match the .kind entries in the kernel */
static const char* const nl_union_link_info_data_table[_NL_UNION_LINK_INFO_DATA_MAX] = {
        [NL_UNION_LINK_INFO_DATA_BOND] = "bond",
        [NL_UNION_LINK_INFO_DATA_BRIDGE] = "bridge",
        [NL_UNION_LINK_INFO_DATA_VLAN] = "vlan",
        [NL_UNION_LINK_INFO_DATA_VETH] = "veth",
        [NL_UNION_LINK_INFO_DATA_DUMMY] = "dummy",
        [NL_UNION_LINK_INFO_DATA_MACVLAN] = "macvlan",
        [NL_UNION_LINK_INFO_DATA_IPVLAN] = "ipvlan",
        [NL_UNION_LINK_INFO_DATA_VXLAN] = "vxlan",
        [NL_UNION_LINK_INFO_DATA_IPIP_TUNNEL] = "ipip",
        [NL_UNION_LINK_INFO_DATA_IPGRE_TUNNEL] = "gre",
        [NL_UNION_LINK_INFO_DATA_IPGRETAP_TUNNEL] = "gretap",
        [NL_UNION_LINK_INFO_DATA_IP6GRE_TUNNEL] = "ip6gre",
        [NL_UNION_LINK_INFO_DATA_IP6GRETAP_TUNNEL] = "ip6gretap",
        [NL_UNION_LINK_INFO_DATA_SIT_TUNNEL] = "sit",
        [NL_UNION_LINK_INFO_DATA_VTI_TUNNEL] = "vti",
        [NL_UNION_LINK_INFO_DATA_VTI6_TUNNEL] = "vti6",
        [NL_UNION_LINK_INFO_DATA_IP6TNL_TUNNEL] = "ip6tnl",
};

DEFINE_STRING_TABLE_LOOKUP(nl_union_link_info_data, NLUnionLinkInfoData);

static const NLTypeSystem rtnl_link_info_data_type_systems[_NL_UNION_LINK_INFO_DATA_MAX] = {
        [NL_UNION_LINK_INFO_DATA_BOND] =        { .count = ELEMENTSOF(rtnl_link_info_data_bond_types),
                                                  .types = rtnl_link_info_data_bond_types },
        [NL_UNION_LINK_INFO_DATA_BRIDGE] =      { .count = ELEMENTSOF(rtnl_link_info_data_bridge_types),
                                                  .types = rtnl_link_info_data_bridge_types },
        [NL_UNION_LINK_INFO_DATA_VLAN] =        { .count = ELEMENTSOF(rtnl_link_info_data_vlan_types),
                                                  .types = rtnl_link_info_data_vlan_types },
        [NL_UNION_LINK_INFO_DATA_VETH] =        { .count = ELEMENTSOF(rtnl_link_info_data_veth_types),
                                                  .types = rtnl_link_info_data_veth_types },
        [NL_UNION_LINK_INFO_DATA_MACVLAN] =     { .count = ELEMENTSOF(rtnl_link_info_data_macvlan_types),
                                                  .types = rtnl_link_info_data_macvlan_types },
        [NL_UNION_LINK_INFO_DATA_IPVLAN] =      { .count = ELEMENTSOF(rtnl_link_info_data_ipvlan_types),
                                                  .types = rtnl_link_info_data_ipvlan_types },
        [NL_UNION_LINK_INFO_DATA_VXLAN] =       { .count = ELEMENTSOF(rtnl_link_info_data_vxlan_types),
                                                  .types = rtnl_link_info_data_vxlan_types },
        [NL_UNION_LINK_INFO_DATA_IPIP_TUNNEL] = { .count = ELEMENTSOF(rtnl_link_info_data_iptun_types),
                                                  .types = rtnl_link_info_data_iptun_types },
        [NL_UNION_LINK_INFO_DATA_IPGRE_TUNNEL] =  { .count = ELEMENTSOF(rtnl_link_info_data_ipgre_types),
                                                    .types = rtnl_link_info_data_ipgre_types },
        [NL_UNION_LINK_INFO_DATA_IPGRETAP_TUNNEL] =  { .count = ELEMENTSOF(rtnl_link_info_data_ipgre_types),
                                                    .types = rtnl_link_info_data_ipgre_types },
        [NL_UNION_LINK_INFO_DATA_IP6GRE_TUNNEL] =  { .count = ELEMENTSOF(rtnl_link_info_data_ipgre_types),
                                                    .types = rtnl_link_info_data_ipgre_types },
        [NL_UNION_LINK_INFO_DATA_IP6GRETAP_TUNNEL] =  { .count = ELEMENTSOF(rtnl_link_info_data_ipgre_types),
                                                    .types = rtnl_link_info_data_ipgre_types },
        [NL_UNION_LINK_INFO_DATA_SIT_TUNNEL] =  { .count = ELEMENTSOF(rtnl_link_info_data_iptun_types),
                                                  .types = rtnl_link_info_data_iptun_types },
        [NL_UNION_LINK_INFO_DATA_VTI_TUNNEL] =  { .count = ELEMENTSOF(rtnl_link_info_data_ipvti_types),
                                                  .types = rtnl_link_info_data_ipvti_types },
        [NL_UNION_LINK_INFO_DATA_VTI6_TUNNEL] =  { .count = ELEMENTSOF(rtnl_link_info_data_ipvti_types),
                                                  .types = rtnl_link_info_data_ipvti_types },
        [NL_UNION_LINK_INFO_DATA_IP6TNL_TUNNEL] =  { .count = ELEMENTSOF(rtnl_link_info_data_ip6tnl_types),
                                                     .types = rtnl_link_info_data_ip6tnl_types },

};

static const NLTypeSystemUnion rtnl_link_info_data_type_system_union = {
        .num = _NL_UNION_LINK_INFO_DATA_MAX,
        .lookup = nl_union_link_info_data_from_string,
        .type_systems = rtnl_link_info_data_type_systems,
        .match_type = NL_MATCH_SIBLING,
        .match = IFLA_INFO_KIND,
};

static const NLType rtnl_link_info_types[IFLA_INFO_MAX + 1] = {
        [IFLA_INFO_KIND]        = { .type = NETLINK_TYPE_STRING },
        [IFLA_INFO_DATA]        = { .type = NETLINK_TYPE_UNION, .type_system_union = &rtnl_link_info_data_type_system_union},
/*
        [IFLA_INFO_XSTATS],
        [IFLA_INFO_SLAVE_KIND]  = { .type = NETLINK_TYPE_STRING },
        [IFLA_INFO_SLAVE_DATA]  = { .type = NETLINK_TYPE_NESTED },
*/
};

static const NLTypeSystem rtnl_link_info_type_system = {
        .count = ELEMENTSOF(rtnl_link_info_types),
        .types = rtnl_link_info_types,
};

static const struct NLType rtnl_prot_info_bridge_port_types[IFLA_BRPORT_MAX + 1] = {
        [IFLA_BRPORT_STATE]             = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_COST]              = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRPORT_PRIORITY]          = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRPORT_MODE]              = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_GUARD]             = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_PROTECT]           = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_LEARNING]          = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_UNICAST_FLOOD]     = { .type = NETLINK_TYPE_U8 },
};

static const NLTypeSystem rtnl_prot_info_type_systems[AF_MAX] = {
        [AF_BRIDGE] =   { .count = ELEMENTSOF(rtnl_prot_info_bridge_port_types),
                          .types = rtnl_prot_info_bridge_port_types },
};

static const NLTypeSystemUnion rtnl_prot_info_type_system_union = {
        .num = AF_MAX,
        .type_systems = rtnl_prot_info_type_systems,
        .match_type = NL_MATCH_PROTOCOL,
};

static const struct NLType rtnl_af_spec_inet6_types[IFLA_INET6_MAX + 1] = {
        [IFLA_INET6_FLAGS]              = { .type = NETLINK_TYPE_U32 },
/*
        IFLA_INET6_CONF,
        IFLA_INET6_STATS,
        IFLA_INET6_MCAST,
        IFLA_INET6_CACHEINFO,
        IFLA_INET6_ICMP6STATS,
*/
        [IFLA_INET6_TOKEN]              = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_INET6_ADDR_GEN_MODE]      = { .type = NETLINK_TYPE_U8 },
};

static const NLTypeSystem rtnl_af_spec_inet6_type_system = {
        .count = ELEMENTSOF(rtnl_af_spec_inet6_types),
        .types = rtnl_af_spec_inet6_types,
};

static const NLType rtnl_af_spec_types[AF_MAX + 1] = {
        [AF_INET6] =    { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_af_spec_inet6_type_system },
};

static const NLTypeSystem rtnl_af_spec_type_system = {
        .count = ELEMENTSOF(rtnl_af_spec_types),
        .types = rtnl_af_spec_types,
};

static const NLType rtnl_link_types[IFLA_MAX + 1 ] = {
        [IFLA_ADDRESS]          = { .type = NETLINK_TYPE_ETHER_ADDR, },
        [IFLA_BROADCAST]        = { .type = NETLINK_TYPE_ETHER_ADDR, },
        [IFLA_IFNAME]           = { .type = NETLINK_TYPE_STRING, .size = IFNAMSIZ - 1, },
        [IFLA_MTU]              = { .type = NETLINK_TYPE_U32 },
        [IFLA_LINK]             = { .type = NETLINK_TYPE_U32 },
/*
        [IFLA_QDISC],
        [IFLA_STATS],
        [IFLA_COST],
        [IFLA_PRIORITY],
*/
        [IFLA_MASTER]           = { .type = NETLINK_TYPE_U32 },
/*
        [IFLA_WIRELESS],
*/
        [IFLA_PROTINFO]         = { .type = NETLINK_TYPE_UNION, .type_system_union = &rtnl_prot_info_type_system_union },
        [IFLA_TXQLEN]           = { .type = NETLINK_TYPE_U32 },
/*
        [IFLA_MAP]              = { .len = sizeof(struct rtnl_link_ifmap) },
*/
        [IFLA_WEIGHT]           = { .type = NETLINK_TYPE_U32 },
        [IFLA_OPERSTATE]        = { .type = NETLINK_TYPE_U8 },
        [IFLA_LINKMODE]         = { .type = NETLINK_TYPE_U8 },
        [IFLA_LINKINFO]         = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_info_type_system },
        [IFLA_NET_NS_PID]       = { .type = NETLINK_TYPE_U32 },
        [IFLA_IFALIAS]          = { .type = NETLINK_TYPE_STRING, .size = IFALIASZ - 1 },
/*
        [IFLA_NUM_VF],
        [IFLA_VFINFO_LIST]      = {. type = NETLINK_TYPE_NESTED, },
        [IFLA_STATS64],
        [IFLA_VF_PORTS]         = { .type = NETLINK_TYPE_NESTED },
        [IFLA_PORT_SELF]        = { .type = NETLINK_TYPE_NESTED },
*/
        [IFLA_AF_SPEC]          = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_af_spec_type_system },
/*
        [IFLA_VF_PORTS],
        [IFLA_PORT_SELF],
        [IFLA_AF_SPEC],
*/
        [IFLA_GROUP]            = { .type = NETLINK_TYPE_U32 },
        [IFLA_NET_NS_FD]        = { .type = NETLINK_TYPE_U32 },
        [IFLA_EXT_MASK]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_PROMISCUITY]      = { .type = NETLINK_TYPE_U32 },
        [IFLA_NUM_TX_QUEUES]    = { .type = NETLINK_TYPE_U32 },
        [IFLA_NUM_RX_QUEUES]    = { .type = NETLINK_TYPE_U32 },
        [IFLA_CARRIER]          = { .type = NETLINK_TYPE_U8 },
/*
        [IFLA_PHYS_PORT_ID]     = { .type = NETLINK_TYPE_BINARY, .len = MAX_PHYS_PORT_ID_LEN },
*/
};

static const NLTypeSystem rtnl_link_type_system = {
        .count = ELEMENTSOF(rtnl_link_types),
        .types = rtnl_link_types,
};

/* IFA_FLAGS was defined in kernel 3.14, but we still support older
 * kernels where IFA_MAX is lower. */
static const NLType rtnl_address_types[CONST_MAX(IFA_MAX, IFA_FLAGS) + 1] = {
        [IFA_ADDRESS]           = { .type = NETLINK_TYPE_IN_ADDR },
        [IFA_LOCAL]             = { .type = NETLINK_TYPE_IN_ADDR },
        [IFA_LABEL]             = { .type = NETLINK_TYPE_STRING, .size = IFNAMSIZ - 1 },
        [IFA_BROADCAST]         = { .type = NETLINK_TYPE_IN_ADDR }, /* 6? */
        [IFA_CACHEINFO]         = { .type = NETLINK_TYPE_CACHE_INFO, .size = sizeof(struct ifa_cacheinfo) },
/*
        [IFA_ANYCAST],
        [IFA_MULTICAST],
*/
        [IFA_FLAGS]             = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem rtnl_address_type_system = {
        .count = ELEMENTSOF(rtnl_address_types),
        .types = rtnl_address_types,
};

static const NLType rtnl_route_types[RTA_MAX + 1] = {
        [RTA_DST]               = { .type = NETLINK_TYPE_IN_ADDR }, /* 6? */
        [RTA_SRC]               = { .type = NETLINK_TYPE_IN_ADDR }, /* 6? */
        [RTA_IIF]               = { .type = NETLINK_TYPE_U32 },
        [RTA_OIF]               = { .type = NETLINK_TYPE_U32 },
        [RTA_GATEWAY]           = { .type = NETLINK_TYPE_IN_ADDR },
        [RTA_PRIORITY]          = { .type = NETLINK_TYPE_U32 },
        [RTA_PREFSRC]           = { .type = NETLINK_TYPE_IN_ADDR }, /* 6? */
/*
        [RTA_METRICS]           = { .type = NETLINK_TYPE_NESTED },
        [RTA_MULTIPATH]         = { .len = sizeof(struct rtnexthop) },
*/
        [RTA_FLOW]              = { .type = NETLINK_TYPE_U32 }, /* 6? */
/*
        RTA_CACHEINFO,
        RTA_TABLE,
        RTA_MARK,
        RTA_MFC_STATS,
*/
};

static const NLTypeSystem rtnl_route_type_system = {
        .count = ELEMENTSOF(rtnl_route_types),
        .types = rtnl_route_types,
};

static const NLType rtnl_neigh_types[NDA_MAX + 1] = {
        [NDA_DST]               = { .type = NETLINK_TYPE_IN_ADDR },
        [NDA_LLADDR]            = { .type = NETLINK_TYPE_ETHER_ADDR },
        [NDA_CACHEINFO]         = { .type = NETLINK_TYPE_CACHE_INFO, .size = sizeof(struct nda_cacheinfo) },
        [NDA_PROBES]            = { .type = NETLINK_TYPE_U32 },
        [NDA_VLAN]              = { .type = NETLINK_TYPE_U16 },
        [NDA_PORT]              = { .type = NETLINK_TYPE_U16 },
        [NDA_VNI]               = { .type = NETLINK_TYPE_U32 },
        [NDA_IFINDEX]           = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem rtnl_neigh_type_system = {
        .count = ELEMENTSOF(rtnl_neigh_types),
        .types = rtnl_neigh_types,
};

static const NLType rtnl_types[RTM_MAX + 1] = {
        [NLMSG_DONE]   = { .type = NETLINK_TYPE_NESTED, .type_system = &empty_type_system, .size = 0 },
        [NLMSG_ERROR]  = { .type = NETLINK_TYPE_NESTED, .type_system = &empty_type_system, .size = sizeof(struct nlmsgerr) },
        [RTM_NEWLINK]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
        [RTM_DELLINK]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
        [RTM_GETLINK]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
        [RTM_SETLINK]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
        [RTM_NEWADDR]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_address_type_system, .size = sizeof(struct ifaddrmsg) },
        [RTM_DELADDR]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_address_type_system, .size = sizeof(struct ifaddrmsg) },
        [RTM_GETADDR]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_address_type_system, .size = sizeof(struct ifaddrmsg) },
        [RTM_NEWROUTE] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_route_type_system, .size = sizeof(struct rtmsg) },
        [RTM_DELROUTE] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_route_type_system, .size = sizeof(struct rtmsg) },
        [RTM_GETROUTE] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_route_type_system, .size = sizeof(struct rtmsg) },
        [RTM_NEWNEIGH] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_neigh_type_system, .size = sizeof(struct ndmsg) },
        [RTM_DELNEIGH] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_neigh_type_system, .size = sizeof(struct ndmsg) },
        [RTM_GETNEIGH] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_neigh_type_system, .size = sizeof(struct ndmsg) },
};

const NLTypeSystem type_system_root = {
        .count = ELEMENTSOF(rtnl_types),
        .types = rtnl_types,
};

uint16_t type_get_type(const NLType *type) {
        assert(type);
        return type->type;
}

size_t type_get_size(const NLType *type) {
        assert(type);
        return type->size;
}

void type_get_type_system(const NLType *nl_type, const NLTypeSystem **ret) {
        assert(nl_type);
        assert(ret);
        assert(nl_type->type == NETLINK_TYPE_NESTED);
        assert(nl_type->type_system);

        *ret = nl_type->type_system;
}

void type_get_type_system_union(const NLType *nl_type, const NLTypeSystemUnion **ret) {
        assert(nl_type);
        assert(ret);
        assert(nl_type->type == NETLINK_TYPE_UNION);
        assert(nl_type->type_system_union);

        *ret = nl_type->type_system_union;
}

uint16_t type_system_get_count(const NLTypeSystem *type_system) {
        assert(type_system);
        return type_system->count;
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

        type_get_type_system(nl_type, ret);
        return 0;
}

int type_system_get_type_system_union(const NLTypeSystem *type_system, const NLTypeSystemUnion **ret, uint16_t type) {
        const NLType *nl_type;
        int r;

        assert(ret);

        r = type_system_get_type(type_system, &nl_type, type);
        if (r < 0)
                return r;

        type_get_type_system_union(nl_type, ret);
        return 0;
}

int type_system_union_get_type_system(const NLTypeSystemUnion *type_system_union, const NLTypeSystem **ret, const char *key) {
        int type;

        assert(type_system_union);
        assert(type_system_union->match_type == NL_MATCH_SIBLING);
        assert(type_system_union->lookup);
        assert(type_system_union->type_systems);
        assert(ret);
        assert(key);

        type = type_system_union->lookup(key);
        if (type < 0)
                return -EOPNOTSUPP;

        assert(type < type_system_union->num);

        *ret = &type_system_union->type_systems[type];

        return 0;
}

int type_system_union_protocol_get_type_system(const NLTypeSystemUnion *type_system_union, const NLTypeSystem **ret, uint16_t protocol) {
        const NLTypeSystem *type_system;

        assert(type_system_union);
        assert(type_system_union->type_systems);
        assert(type_system_union->match_type == NL_MATCH_PROTOCOL);
        assert(ret);

        if (protocol >= type_system_union->num)
                return -EOPNOTSUPP;

        type_system = &type_system_union->type_systems[protocol];
        if (!type_system->types)
                return -EOPNOTSUPP;

        *ret = type_system;

        return 0;
}
