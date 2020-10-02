/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/can/vxcan.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <linux/ip.h>
#include <linux/if.h>
#include <linux/batman_adv.h>
#include <linux/can/netlink.h>
#include <linux/fib_rules.h>
#include <linux/fou.h>
#include <linux/if_addr.h>
#include <linux/if_addrlabel.h>
#include <linux/if_bridge.h>
#include <linux/if_link.h>
#include <linux/if_macsec.h>
#include <linux/if_tunnel.h>
#include <linux/l2tp.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/nexthop.h>
#include <linux/nl80211.h>
#include <linux/pkt_sched.h>
#include <linux/veth.h>
#include <linux/wireguard.h>

#include "sd-netlink.h"

#include "generic-netlink.h"
#include "hashmap.h"
#include "macro.h"
#include "netlink-internal.h"
#include "netlink-types.h"
#include "string-table.h"
#include "util.h"

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

static const NLType rtnl_link_info_data_batadv_types[] = {
        [IFLA_BATADV_ALGO_NAME] = { .type = NETLINK_TYPE_STRING, .size = 20 },
};

static const NLType rtnl_link_info_data_veth_types[] = {
        [VETH_INFO_PEER]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
};

static const NLType rtnl_link_info_data_vxcan_types[] = {
        [VXCAN_INFO_PEER]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
};

static const NLType rtnl_link_info_data_ipvlan_types[] = {
        [IFLA_IPVLAN_MODE]  = { .type = NETLINK_TYPE_U16 },
        [IFLA_IPVLAN_FLAGS]  = { .type = NETLINK_TYPE_U16 },
};

static const NLType rtnl_macvlan_macaddr_types[] = {
        [IFLA_MACVLAN_MACADDR] = { .type = NETLINK_TYPE_ETHER_ADDR },
};

static const NLTypeSystem rtnl_macvlan_macaddr_type_system = {
        .count = ELEMENTSOF(rtnl_macvlan_macaddr_types),
        .types = rtnl_macvlan_macaddr_types,
};

static const NLType rtnl_link_info_data_macvlan_types[] = {
        [IFLA_MACVLAN_MODE]              = { .type = NETLINK_TYPE_U32 },
        [IFLA_MACVLAN_FLAGS]             = { .type = NETLINK_TYPE_U16 },
        [IFLA_MACVLAN_MACADDR_MODE]      = { .type = NETLINK_TYPE_U32 },
        [IFLA_MACVLAN_MACADDR_DATA]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_macvlan_macaddr_type_system },
        [IFLA_MACVLAN_MACADDR_COUNT]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_MACVLAN_BC_QUEUE_LEN]      = { .type = NETLINK_TYPE_U32 },
        [IFLA_MACVLAN_BC_QUEUE_LEN_USED] = { .type = NETLINK_TYPE_REJECT },
};

static const NLType rtnl_link_info_data_bridge_types[] = {
        [IFLA_BR_FORWARD_DELAY]              = { .type = NETLINK_TYPE_U32 },
        [IFLA_BR_HELLO_TIME]                 = { .type = NETLINK_TYPE_U32 },
        [IFLA_BR_MAX_AGE]                    = { .type = NETLINK_TYPE_U32 },
        [IFLA_BR_AGEING_TIME]                = { .type = NETLINK_TYPE_U32 },
        [IFLA_BR_STP_STATE]                  = { .type = NETLINK_TYPE_U32 },
        [IFLA_BR_PRIORITY]                   = { .type = NETLINK_TYPE_U16 },
        [IFLA_BR_VLAN_FILTERING]             = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_VLAN_PROTOCOL]              = { .type = NETLINK_TYPE_U16 },
        [IFLA_BR_GROUP_FWD_MASK]             = { .type = NETLINK_TYPE_U16 },
        [IFLA_BR_ROOT_PORT]                  = { .type = NETLINK_TYPE_U16 },
        [IFLA_BR_ROOT_PATH_COST]             = { .type = NETLINK_TYPE_U32 },
        [IFLA_BR_TOPOLOGY_CHANGE]            = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_TOPOLOGY_CHANGE_DETECTED]   = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_HELLO_TIMER]                = { .type = NETLINK_TYPE_U16 },
        [IFLA_BR_TCN_TIMER]                  = { .type = NETLINK_TYPE_U16 },
        [IFLA_BR_TOPOLOGY_CHANGE_TIMER]      = { .type = NETLINK_TYPE_U16 },
        [IFLA_BR_GC_TIMER]                   = { .type = NETLINK_TYPE_U64 },
        [IFLA_BR_GROUP_ADDR]                 = { .type = NETLINK_TYPE_U16 },
        [IFLA_BR_FDB_FLUSH]                  = { .type = NETLINK_TYPE_U16 },
        [IFLA_BR_MCAST_ROUTER]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_MCAST_SNOOPING]             = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_MCAST_QUERY_USE_IFADDR]     = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_MCAST_QUERIER]              = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_MCAST_HASH_ELASTICITY]      = { .type = NETLINK_TYPE_U32 },
        [IFLA_BR_MCAST_HASH_MAX]             = { .type = NETLINK_TYPE_U16 },
        [IFLA_BR_MCAST_LAST_MEMBER_CNT]      = { .type = NETLINK_TYPE_U32 },
        [IFLA_BR_MCAST_STARTUP_QUERY_CNT]    = { .type = NETLINK_TYPE_U16 },
        [IFLA_BR_MCAST_LAST_MEMBER_INTVL]    = { .type = NETLINK_TYPE_U64 },
        [IFLA_BR_MCAST_MEMBERSHIP_INTVL]     = { .type = NETLINK_TYPE_U64 },
        [IFLA_BR_MCAST_QUERIER_INTVL]        = { .type = NETLINK_TYPE_U64 },
        [IFLA_BR_MCAST_QUERY_INTVL]          = { .type = NETLINK_TYPE_U64 },
        [IFLA_BR_MCAST_QUERY_RESPONSE_INTVL] = { .type = NETLINK_TYPE_U64 },
        [IFLA_BR_MCAST_STARTUP_QUERY_INTVL]  = { .type = NETLINK_TYPE_U64 },
        [IFLA_BR_NF_CALL_IPTABLES]           = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_NF_CALL_IP6TABLES]          = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_NF_CALL_ARPTABLES]          = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_VLAN_DEFAULT_PVID]          = { .type = NETLINK_TYPE_U16 },
        [IFLA_BR_MCAST_IGMP_VERSION]         = { .type = NETLINK_TYPE_U8 },
};

static const NLType rtnl_vlan_qos_map_types[] = {
        [IFLA_VLAN_QOS_MAPPING]        = { .size = sizeof(struct ifla_vlan_qos_mapping) },
};

static const NLTypeSystem rtnl_vlan_qos_map_type_system = {
        .count = ELEMENTSOF(rtnl_vlan_qos_map_types),
        .types = rtnl_vlan_qos_map_types,
};

static const NLType rtnl_link_info_data_vlan_types[] = {
        [IFLA_VLAN_ID]          = { .type = NETLINK_TYPE_U16 },
        [IFLA_VLAN_FLAGS]       = { .size = sizeof(struct ifla_vlan_flags) },
        [IFLA_VLAN_EGRESS_QOS]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_vlan_qos_map_type_system },
        [IFLA_VLAN_INGRESS_QOS] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_vlan_qos_map_type_system },
        [IFLA_VLAN_PROTOCOL]    = { .type = NETLINK_TYPE_U16 },
};

static const NLType rtnl_link_info_data_vxlan_types[] = {
        [IFLA_VXLAN_ID]                = { .type = NETLINK_TYPE_U32 },
        [IFLA_VXLAN_GROUP]             = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_VXLAN_LINK]              = { .type = NETLINK_TYPE_U32 },
        [IFLA_VXLAN_LOCAL]             = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_VXLAN_TTL]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_TOS]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_LEARNING]          = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_AGEING]            = { .type = NETLINK_TYPE_U32 },
        [IFLA_VXLAN_LIMIT]             = { .type = NETLINK_TYPE_U32 },
        [IFLA_VXLAN_PORT_RANGE]        = { .type = NETLINK_TYPE_U32},
        [IFLA_VXLAN_PROXY]             = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_RSC]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_L2MISS]            = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_L3MISS]            = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_PORT]              = { .type = NETLINK_TYPE_U16 },
        [IFLA_VXLAN_GROUP6]            = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_VXLAN_LOCAL6]            = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_VXLAN_UDP_CSUM]          = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_UDP_ZERO_CSUM6_TX] = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_UDP_ZERO_CSUM6_RX] = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_REMCSUM_TX]        = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_REMCSUM_RX]        = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_GBP]               = { .type = NETLINK_TYPE_FLAG },
        [IFLA_VXLAN_REMCSUM_NOPARTIAL] = { .type = NETLINK_TYPE_FLAG },
        [IFLA_VXLAN_COLLECT_METADATA]  = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_LABEL]             = { .type = NETLINK_TYPE_U32 },
        [IFLA_VXLAN_GPE]               = { .type = NETLINK_TYPE_FLAG },
        [IFLA_VXLAN_TTL_INHERIT]       = { .type = NETLINK_TYPE_FLAG },
        [IFLA_VXLAN_DF]                = { .type = NETLINK_TYPE_U8 },
};

static const NLType rtnl_bond_arp_target_types[] = {
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

static const NLType rtnl_link_info_data_bond_types[] = {
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
        [IFLA_BOND_AD_ACTOR_SYS_PRIO]   = { .type = NETLINK_TYPE_U16 },
        [IFLA_BOND_AD_USER_PORT_KEY]    = { .type = NETLINK_TYPE_U16 },
        [IFLA_BOND_AD_ACTOR_SYSTEM]     = { .type = NETLINK_TYPE_ETHER_ADDR },
        [IFLA_BOND_TLB_DYNAMIC_LB]      = { .type = NETLINK_TYPE_U8 },
};

static const NLType rtnl_link_info_data_iptun_types[] = {
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
        [IFLA_IPTUN_ENCAP_TYPE]          = { .type = NETLINK_TYPE_U16 },
        [IFLA_IPTUN_ENCAP_FLAGS]         = { .type = NETLINK_TYPE_U16 },
        [IFLA_IPTUN_ENCAP_SPORT]         = { .type = NETLINK_TYPE_U16 },
        [IFLA_IPTUN_ENCAP_DPORT]         = { .type = NETLINK_TYPE_U16 },
};

static  const NLType rtnl_link_info_data_ipgre_types[] = {
        [IFLA_GRE_LINK]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_GRE_IFLAGS]       = { .type = NETLINK_TYPE_U16 },
        [IFLA_GRE_OFLAGS]       = { .type = NETLINK_TYPE_U16 },
        [IFLA_GRE_IKEY]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_GRE_OKEY]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_GRE_LOCAL]        = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_GRE_REMOTE]       = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_GRE_TTL]          = { .type = NETLINK_TYPE_U8 },
        [IFLA_GRE_TOS]          = { .type = NETLINK_TYPE_U8 },
        [IFLA_GRE_PMTUDISC]     = { .type = NETLINK_TYPE_U8 },
        [IFLA_GRE_FLOWINFO]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_GRE_FLAGS]        = { .type = NETLINK_TYPE_U32 },
        [IFLA_GRE_ENCAP_TYPE]   = { .type = NETLINK_TYPE_U16 },
        [IFLA_GRE_ENCAP_FLAGS]  = { .type = NETLINK_TYPE_U16 },
        [IFLA_GRE_ENCAP_SPORT]  = { .type = NETLINK_TYPE_U16 },
        [IFLA_GRE_ENCAP_DPORT]  = { .type = NETLINK_TYPE_U16 },
        [IFLA_GRE_ERSPAN_INDEX] = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_link_info_data_ipvti_types[] = {
        [IFLA_VTI_LINK]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_VTI_IKEY]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_VTI_OKEY]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_VTI_LOCAL]        = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_VTI_REMOTE]       = { .type = NETLINK_TYPE_IN_ADDR },
};

static const NLType rtnl_link_info_data_ip6tnl_types[] = {
        [IFLA_IPTUN_LINK]                = { .type = NETLINK_TYPE_U32 },
        [IFLA_IPTUN_LOCAL]               = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_IPTUN_REMOTE]              = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_IPTUN_TTL]                 = { .type = NETLINK_TYPE_U8 },
        [IFLA_IPTUN_FLAGS]               = { .type = NETLINK_TYPE_U32 },
        [IFLA_IPTUN_PROTO]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_IPTUN_ENCAP_LIMIT]         = { .type = NETLINK_TYPE_U8 },
        [IFLA_IPTUN_FLOWINFO]            = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_link_info_data_vrf_types[] = {
        [IFLA_VRF_TABLE]                 = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_link_info_data_geneve_types[] = {
        [IFLA_GENEVE_ID]                = { .type = NETLINK_TYPE_U32 },
        [IFLA_GENEVE_TTL]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_GENEVE_TOS]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_GENEVE_PORT]              = { .type = NETLINK_TYPE_U16 },
        [IFLA_GENEVE_REMOTE]            = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_GENEVE_REMOTE6]           = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_GENEVE_UDP_CSUM]          = { .type = NETLINK_TYPE_U8 },
        [IFLA_GENEVE_UDP_ZERO_CSUM6_TX] = { .type = NETLINK_TYPE_U8 },
        [IFLA_GENEVE_UDP_ZERO_CSUM6_RX] = { .type = NETLINK_TYPE_U8 },
        [IFLA_GENEVE_LABEL]             = { .type = NETLINK_TYPE_U32 },
        [IFLA_GENEVE_TTL_INHERIT]       = { .type = NETLINK_TYPE_U8 },
        [IFLA_GENEVE_DF]                = { .type = NETLINK_TYPE_U8 },
};

static const NLType rtnl_link_info_data_can_types[] = {
        [IFLA_CAN_BITTIMING]            = { .size = sizeof(struct can_bittiming) },
        [IFLA_CAN_RESTART_MS]           = { .type = NETLINK_TYPE_U32 },
        [IFLA_CAN_CTRLMODE]             = { .size = sizeof(struct can_ctrlmode) },
        [IFLA_CAN_TERMINATION]          = { .type = NETLINK_TYPE_U16 },
};

static const NLType rtnl_link_info_data_macsec_types[] = {
        [IFLA_MACSEC_SCI]            = { .type = NETLINK_TYPE_U64 },
        [IFLA_MACSEC_PORT]           = { .type = NETLINK_TYPE_U16 },
        [IFLA_MACSEC_ICV_LEN]        = { .type = NETLINK_TYPE_U8 },
        [IFLA_MACSEC_CIPHER_SUITE]   = { .type = NETLINK_TYPE_U64 },
        [IFLA_MACSEC_WINDOW]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_MACSEC_ENCODING_SA]    = { .type = NETLINK_TYPE_U8 },
        [IFLA_MACSEC_ENCRYPT]        = { .type = NETLINK_TYPE_U8 },
        [IFLA_MACSEC_PROTECT]        = { .type = NETLINK_TYPE_U8 },
        [IFLA_MACSEC_INC_SCI]        = { .type = NETLINK_TYPE_U8 },
        [IFLA_MACSEC_ES]             = { .type = NETLINK_TYPE_U8 },
        [IFLA_MACSEC_SCB]            = { .type = NETLINK_TYPE_U8 },
        [IFLA_MACSEC_REPLAY_PROTECT] = { .type = NETLINK_TYPE_U8 },
        [IFLA_MACSEC_VALIDATION]     = { .type = NETLINK_TYPE_U8 },
};

static const NLType rtnl_link_info_data_xfrm_types[] = {
        [IFLA_XFRM_LINK]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_XFRM_IF_ID]        = { .type = NETLINK_TYPE_U32 }
};

static const NLType rtnl_link_info_data_bareudp_types[] = {
        [IFLA_BAREUDP_PORT]            = { .type = NETLINK_TYPE_U16 },
        [IFLA_BAREUDP_ETHERTYPE]       = { .type = NETLINK_TYPE_U16 },
        [IFLA_BAREUDP_SRCPORT_MIN]     = { .type = NETLINK_TYPE_U16 },
        [IFLA_BAREUDP_MULTIPROTO_MODE] = { .type = NETLINK_TYPE_FLAG },
};
/* these strings must match the .kind entries in the kernel */
static const char* const nl_union_link_info_data_table[] = {
        [NL_UNION_LINK_INFO_DATA_BOND] = "bond",
        [NL_UNION_LINK_INFO_DATA_BRIDGE] = "bridge",
        [NL_UNION_LINK_INFO_DATA_VLAN] = "vlan",
        [NL_UNION_LINK_INFO_DATA_VETH] = "veth",
        [NL_UNION_LINK_INFO_DATA_DUMMY] = "dummy",
        [NL_UNION_LINK_INFO_DATA_MACVLAN] = "macvlan",
        [NL_UNION_LINK_INFO_DATA_MACVTAP] = "macvtap",
        [NL_UNION_LINK_INFO_DATA_IPVLAN] = "ipvlan",
        [NL_UNION_LINK_INFO_DATA_IPVTAP] = "ipvtap",
        [NL_UNION_LINK_INFO_DATA_VXLAN] = "vxlan",
        [NL_UNION_LINK_INFO_DATA_IPIP_TUNNEL] = "ipip",
        [NL_UNION_LINK_INFO_DATA_IPGRE_TUNNEL] = "gre",
        [NL_UNION_LINK_INFO_DATA_ERSPAN] = "erspan",
        [NL_UNION_LINK_INFO_DATA_IPGRETAP_TUNNEL] = "gretap",
        [NL_UNION_LINK_INFO_DATA_IP6GRE_TUNNEL] = "ip6gre",
        [NL_UNION_LINK_INFO_DATA_IP6GRETAP_TUNNEL] = "ip6gretap",
        [NL_UNION_LINK_INFO_DATA_SIT_TUNNEL] = "sit",
        [NL_UNION_LINK_INFO_DATA_VTI_TUNNEL] = "vti",
        [NL_UNION_LINK_INFO_DATA_VTI6_TUNNEL] = "vti6",
        [NL_UNION_LINK_INFO_DATA_IP6TNL_TUNNEL] = "ip6tnl",
        [NL_UNION_LINK_INFO_DATA_VRF] = "vrf",
        [NL_UNION_LINK_INFO_DATA_VCAN] = "vcan",
        [NL_UNION_LINK_INFO_DATA_GENEVE] = "geneve",
        [NL_UNION_LINK_INFO_DATA_VXCAN] = "vxcan",
        [NL_UNION_LINK_INFO_DATA_WIREGUARD] = "wireguard",
        [NL_UNION_LINK_INFO_DATA_NETDEVSIM] = "netdevsim",
        [NL_UNION_LINK_INFO_DATA_CAN] = "can",
        [NL_UNION_LINK_INFO_DATA_MACSEC] = "macsec",
        [NL_UNION_LINK_INFO_DATA_NLMON] = "nlmon",
        [NL_UNION_LINK_INFO_DATA_XFRM] = "xfrm",
        [NL_UNION_LINK_INFO_DATA_IFB] = "ifb",
        [NL_UNION_LINK_INFO_DATA_BAREUDP] = "bareudp",
        [NL_UNION_LINK_INFO_DATA_BATADV] = "batadv",
};

DEFINE_STRING_TABLE_LOOKUP(nl_union_link_info_data, NLUnionLinkInfoData);

static const NLTypeSystem rtnl_link_info_data_type_systems[] = {
        [NL_UNION_LINK_INFO_DATA_BOND] =             { .count = ELEMENTSOF(rtnl_link_info_data_bond_types),
                                                       .types = rtnl_link_info_data_bond_types },
        [NL_UNION_LINK_INFO_DATA_BRIDGE] =           { .count = ELEMENTSOF(rtnl_link_info_data_bridge_types),
                                                       .types = rtnl_link_info_data_bridge_types },
        [NL_UNION_LINK_INFO_DATA_VLAN] =             { .count = ELEMENTSOF(rtnl_link_info_data_vlan_types),
                                                       .types = rtnl_link_info_data_vlan_types },
        [NL_UNION_LINK_INFO_DATA_VETH] =             { .count = ELEMENTSOF(rtnl_link_info_data_veth_types),
                                                       .types = rtnl_link_info_data_veth_types },
        [NL_UNION_LINK_INFO_DATA_MACVLAN] =          { .count = ELEMENTSOF(rtnl_link_info_data_macvlan_types),
                                                       .types = rtnl_link_info_data_macvlan_types },
        [NL_UNION_LINK_INFO_DATA_MACVTAP] =          { .count = ELEMENTSOF(rtnl_link_info_data_macvlan_types),
                                                       .types = rtnl_link_info_data_macvlan_types },
        [NL_UNION_LINK_INFO_DATA_IPVLAN] =           { .count = ELEMENTSOF(rtnl_link_info_data_ipvlan_types),
                                                       .types = rtnl_link_info_data_ipvlan_types },
        [NL_UNION_LINK_INFO_DATA_IPVTAP] =           { .count = ELEMENTSOF(rtnl_link_info_data_ipvlan_types),
                                                       .types = rtnl_link_info_data_ipvlan_types },
        [NL_UNION_LINK_INFO_DATA_VXLAN] =            { .count = ELEMENTSOF(rtnl_link_info_data_vxlan_types),
                                                       .types = rtnl_link_info_data_vxlan_types },
        [NL_UNION_LINK_INFO_DATA_IPIP_TUNNEL] =      { .count = ELEMENTSOF(rtnl_link_info_data_iptun_types),
                                                       .types = rtnl_link_info_data_iptun_types },
        [NL_UNION_LINK_INFO_DATA_IPGRE_TUNNEL] =     { .count = ELEMENTSOF(rtnl_link_info_data_ipgre_types),
                                                       .types = rtnl_link_info_data_ipgre_types },
        [NL_UNION_LINK_INFO_DATA_ERSPAN] =           { .count = ELEMENTSOF(rtnl_link_info_data_ipgre_types),
                                                       .types = rtnl_link_info_data_ipgre_types },
        [NL_UNION_LINK_INFO_DATA_IPGRETAP_TUNNEL] =  { .count = ELEMENTSOF(rtnl_link_info_data_ipgre_types),
                                                       .types = rtnl_link_info_data_ipgre_types },
        [NL_UNION_LINK_INFO_DATA_IP6GRE_TUNNEL] =    { .count = ELEMENTSOF(rtnl_link_info_data_ipgre_types),
                                                       .types = rtnl_link_info_data_ipgre_types },
        [NL_UNION_LINK_INFO_DATA_IP6GRETAP_TUNNEL] = { .count = ELEMENTSOF(rtnl_link_info_data_ipgre_types),
                                                       .types = rtnl_link_info_data_ipgre_types },
        [NL_UNION_LINK_INFO_DATA_SIT_TUNNEL] =       { .count = ELEMENTSOF(rtnl_link_info_data_iptun_types),
                                                       .types = rtnl_link_info_data_iptun_types },
        [NL_UNION_LINK_INFO_DATA_VTI_TUNNEL] =       { .count = ELEMENTSOF(rtnl_link_info_data_ipvti_types),
                                                       .types = rtnl_link_info_data_ipvti_types },
        [NL_UNION_LINK_INFO_DATA_VTI6_TUNNEL] =      { .count = ELEMENTSOF(rtnl_link_info_data_ipvti_types),
                                                       .types = rtnl_link_info_data_ipvti_types },
        [NL_UNION_LINK_INFO_DATA_IP6TNL_TUNNEL] =    { .count = ELEMENTSOF(rtnl_link_info_data_ip6tnl_types),
                                                       .types = rtnl_link_info_data_ip6tnl_types },
        [NL_UNION_LINK_INFO_DATA_VRF] =              { .count = ELEMENTSOF(rtnl_link_info_data_vrf_types),
                                                       .types = rtnl_link_info_data_vrf_types },
        [NL_UNION_LINK_INFO_DATA_GENEVE] =           { .count = ELEMENTSOF(rtnl_link_info_data_geneve_types),
                                                       .types = rtnl_link_info_data_geneve_types },
        [NL_UNION_LINK_INFO_DATA_VXCAN] =            { .count = ELEMENTSOF(rtnl_link_info_data_vxcan_types),
                                                       .types = rtnl_link_info_data_vxcan_types },
        [NL_UNION_LINK_INFO_DATA_CAN] =              { .count = ELEMENTSOF(rtnl_link_info_data_can_types),
                                                       .types = rtnl_link_info_data_can_types },
        [NL_UNION_LINK_INFO_DATA_MACSEC] =           { .count = ELEMENTSOF(rtnl_link_info_data_macsec_types),
                                                       .types = rtnl_link_info_data_macsec_types },
        [NL_UNION_LINK_INFO_DATA_XFRM] =             { .count = ELEMENTSOF(rtnl_link_info_data_xfrm_types),
                                                       .types = rtnl_link_info_data_xfrm_types },
        [NL_UNION_LINK_INFO_DATA_BAREUDP] =          { .count = ELEMENTSOF(rtnl_link_info_data_bareudp_types),
                                                       .types = rtnl_link_info_data_bareudp_types },
        [NL_UNION_LINK_INFO_DATA_BATADV] =           { .count = ELEMENTSOF(rtnl_link_info_data_batadv_types),
                                                       .types = rtnl_link_info_data_batadv_types },
};

static const NLTypeSystemUnion rtnl_link_info_data_type_system_union = {
        .num = _NL_UNION_LINK_INFO_DATA_MAX,
        .lookup = nl_union_link_info_data_from_string,
        .type_systems = rtnl_link_info_data_type_systems,
        .match_type = NL_MATCH_SIBLING,
        .match = IFLA_INFO_KIND,
};

static const NLType rtnl_link_info_types[] = {
        [IFLA_INFO_KIND]        = { .type = NETLINK_TYPE_STRING },
        [IFLA_INFO_DATA]        = { .type = NETLINK_TYPE_UNION, .type_system_union = &rtnl_link_info_data_type_system_union },
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

static const struct NLType rtnl_prot_info_bridge_port_types[] = {
        [IFLA_BRPORT_STATE]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_COST]                = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRPORT_PRIORITY]            = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRPORT_MODE]                = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_GUARD]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_PROTECT]             = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_FAST_LEAVE]          = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_LEARNING]            = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_UNICAST_FLOOD]       = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_PROXYARP]            = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_LEARNING_SYNC]       = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_PROXYARP_WIFI]       = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_ROOT_ID]             = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_BRIDGE_ID]           = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_DESIGNATED_PORT]     = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRPORT_DESIGNATED_COST]     = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRPORT_ID]                  = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRPORT_NO]                  = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRPORT_TOPOLOGY_CHANGE_ACK] = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_CONFIG_PENDING]      = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_MESSAGE_AGE_TIMER]   = { .type = NETLINK_TYPE_U64 },
        [IFLA_BRPORT_FORWARD_DELAY_TIMER] = { .type = NETLINK_TYPE_U64 },
        [IFLA_BRPORT_HOLD_TIMER]          = { .type = NETLINK_TYPE_U64 },
        [IFLA_BRPORT_FLUSH]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_MULTICAST_ROUTER]    = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_PAD]                 = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_MCAST_FLOOD]         = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_MCAST_TO_UCAST]      = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_VLAN_TUNNEL]         = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_BCAST_FLOOD]         = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_GROUP_FWD_MASK]      = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRPORT_NEIGH_SUPPRESS]      = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_ISOLATED]            = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_BACKUP_PORT]         = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem rtnl_prot_info_type_systems[] = {
        [AF_BRIDGE] =   { .count = ELEMENTSOF(rtnl_prot_info_bridge_port_types),
                          .types = rtnl_prot_info_bridge_port_types },
};

static const NLTypeSystemUnion rtnl_prot_info_type_system_union = {
        .num = AF_MAX,
        .type_systems = rtnl_prot_info_type_systems,
        .match_type = NL_MATCH_PROTOCOL,
};

static const struct NLType rtnl_af_spec_inet6_types[] = {
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

static const NLType rtnl_af_spec_types[] = {
        [AF_INET6] =    { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_af_spec_inet6_type_system },
};

static const NLTypeSystem rtnl_af_spec_type_system = {
        .count = ELEMENTSOF(rtnl_af_spec_types),
        .types = rtnl_af_spec_types,
};

static const NLType rtnl_prop_list_types[] = {
        [IFLA_ALT_IFNAME]       = { .type = NETLINK_TYPE_STRING, .size = ALTIFNAMSIZ - 1 },
};

static const NLTypeSystem rtnl_prop_list_type_system = {
        .count = ELEMENTSOF(rtnl_prop_list_types),
        .types = rtnl_prop_list_types,
};

static const NLType rtnl_vf_vlan_list_types[] = {
        [IFLA_VF_VLAN_INFO]  = { .size = sizeof(struct ifla_vf_vlan_info) },
};

static const NLTypeSystem rtnl_vf_vlan_type_system = {
        .count = ELEMENTSOF(rtnl_vf_vlan_list_types),
        .types = rtnl_vf_vlan_list_types,
};

static const NLType rtnl_vf_vlan_info_types[] = {
        [IFLA_VF_MAC]           = { .size = sizeof(struct ifla_vf_mac) },
        [IFLA_VF_VLAN]          = { .size = sizeof(struct ifla_vf_vlan) },
        [IFLA_VF_VLAN_LIST]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_vf_vlan_type_system},
        [IFLA_VF_TX_RATE]       = { .size = sizeof(struct ifla_vf_tx_rate) },
        [IFLA_VF_SPOOFCHK]      = { .size = sizeof(struct ifla_vf_spoofchk) },
        [IFLA_VF_RATE]          = { .size = sizeof(struct ifla_vf_rate) },
        [IFLA_VF_LINK_STATE]    = { .size = sizeof(struct ifla_vf_link_state) },
        [IFLA_VF_RSS_QUERY_EN]  = { .size = sizeof(struct ifla_vf_rss_query_en) },
        [IFLA_VF_TRUST]         = { .size = sizeof(struct ifla_vf_trust) },
        [IFLA_VF_IB_NODE_GUID]  = { .size = sizeof(struct ifla_vf_guid) },
        [IFLA_VF_IB_PORT_GUID]  = { .size = sizeof(struct ifla_vf_guid) },
};

static const NLTypeSystem rtnl_vf_vlan_info_type_system = {
        .count = ELEMENTSOF(rtnl_vf_vlan_info_types),
        .types = rtnl_vf_vlan_info_types,
};

static const NLType rtnl_link_io_srv_types[] = {
        [IFLA_VF_INFO] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_vf_vlan_info_type_system },
};

static const NLTypeSystem rtnl_io_srv_type_system = {
        .count = ELEMENTSOF(rtnl_link_io_srv_types),
        .types = rtnl_link_io_srv_types,
};

static const NLType rtnl_link_types[] = {
        [IFLA_ADDRESS]          = { .type = NETLINK_TYPE_ETHER_ADDR },
        [IFLA_BROADCAST]        = { .type = NETLINK_TYPE_ETHER_ADDR },
        [IFLA_IFNAME]           = { .type = NETLINK_TYPE_STRING, .size = IFNAMSIZ - 1 },
        [IFLA_MTU]              = { .type = NETLINK_TYPE_U32 },
        [IFLA_LINK]             = { .type = NETLINK_TYPE_U32 },
        [IFLA_QDISC]            = { .type = NETLINK_TYPE_STRING },
        [IFLA_STATS]            = { .size = sizeof(struct rtnl_link_stats) },
/*
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
        [IFLA_NUM_VF]           = { .type = NETLINK_TYPE_U32 },
        [IFLA_VFINFO_LIST]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_io_srv_type_system },
        [IFLA_STATS64]          = { .size = sizeof(struct rtnl_link_stats64) },
/*
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
        [IFLA_GSO_MAX_SEGS]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_GSO_MAX_SIZE]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_CARRIER]          = { .type = NETLINK_TYPE_U8 },
/*
        [IFLA_PHYS_PORT_ID]     = { .type = NETLINK_TYPE_BINARY, .len = MAX_PHYS_PORT_ID_LEN },
*/
        [IFLA_MIN_MTU]          = { .type = NETLINK_TYPE_U32 },
        [IFLA_MAX_MTU]          = { .type = NETLINK_TYPE_U32 },
        [IFLA_PROP_LIST]        = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_prop_list_type_system },
        [IFLA_ALT_IFNAME]       = { .type = NETLINK_TYPE_STRING, .size = ALTIFNAMSIZ - 1 },
};

static const NLTypeSystem rtnl_link_type_system = {
        .count = ELEMENTSOF(rtnl_link_types),
        .types = rtnl_link_types,
};

/* IFA_FLAGS was defined in kernel 3.14, but we still support older
 * kernels where IFA_MAX is lower. */
static const NLType rtnl_address_types[] = {
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

/* RTM_METRICS --- array of struct rtattr with types of RTAX_* */

static const NLType rtnl_route_metrics_types[] = {
        [RTAX_MTU]                = { .type = NETLINK_TYPE_U32 },
        [RTAX_WINDOW]             = { .type = NETLINK_TYPE_U32 },
        [RTAX_RTT]                = { .type = NETLINK_TYPE_U32 },
        [RTAX_RTTVAR]             = { .type = NETLINK_TYPE_U32 },
        [RTAX_SSTHRESH]           = { .type = NETLINK_TYPE_U32 },
        [RTAX_CWND]               = { .type = NETLINK_TYPE_U32 },
        [RTAX_ADVMSS]             = { .type = NETLINK_TYPE_U32 },
        [RTAX_REORDERING]         = { .type = NETLINK_TYPE_U32 },
        [RTAX_HOPLIMIT]           = { .type = NETLINK_TYPE_U32 },
        [RTAX_INITCWND]           = { .type = NETLINK_TYPE_U32 },
        [RTAX_FEATURES]           = { .type = NETLINK_TYPE_U32 },
        [RTAX_RTO_MIN]            = { .type = NETLINK_TYPE_U32 },
        [RTAX_INITRWND]           = { .type = NETLINK_TYPE_U32 },
        [RTAX_QUICKACK]           = { .type = NETLINK_TYPE_U32 },
        [RTAX_CC_ALGO]            = { .type = NETLINK_TYPE_U32 },
        [RTAX_FASTOPEN_NO_COOKIE] = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem rtnl_route_metrics_type_system = {
        .count = ELEMENTSOF(rtnl_route_metrics_types),
        .types = rtnl_route_metrics_types,
};

static const NLType rtnl_route_types[] = {
        [RTA_DST]               = { .type = NETLINK_TYPE_IN_ADDR }, /* 6? */
        [RTA_SRC]               = { .type = NETLINK_TYPE_IN_ADDR }, /* 6? */
        [RTA_IIF]               = { .type = NETLINK_TYPE_U32 },
        [RTA_OIF]               = { .type = NETLINK_TYPE_U32 },
        [RTA_GATEWAY]           = { .type = NETLINK_TYPE_IN_ADDR },
        [RTA_PRIORITY]          = { .type = NETLINK_TYPE_U32 },
        [RTA_PREFSRC]           = { .type = NETLINK_TYPE_IN_ADDR }, /* 6? */
        [RTA_METRICS]           = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_route_metrics_type_system},
        [RTA_MULTIPATH]         = { .size = sizeof(struct rtnexthop) },
        [RTA_FLOW]              = { .type = NETLINK_TYPE_U32 }, /* 6? */
        [RTA_CACHEINFO]         = { .size = sizeof(struct rta_cacheinfo) },
        [RTA_TABLE]             = { .type = NETLINK_TYPE_U32 },
        [RTA_MARK]              = { .type = NETLINK_TYPE_U32 },
        [RTA_MFC_STATS]         = { .type = NETLINK_TYPE_U64 },
        [RTA_VIA]               = { /* See struct rtvia */ },
        [RTA_NEWDST]            = { .type = NETLINK_TYPE_U32 },
        [RTA_PREF]              = { .type = NETLINK_TYPE_U8 },
        [RTA_ENCAP_TYPE]        = { .type = NETLINK_TYPE_U16 },
        [RTA_ENCAP]             = { .type = NETLINK_TYPE_NESTED }, /* Multiple type systems i.e. LWTUNNEL_ENCAP_MPLS/LWTUNNEL_ENCAP_IP/LWTUNNEL_ENCAP_ILA etc... */
        [RTA_EXPIRES]           = { .type = NETLINK_TYPE_U32 },
        [RTA_UID]               = { .type = NETLINK_TYPE_U32 },
        [RTA_TTL_PROPAGATE]     = { .type = NETLINK_TYPE_U8 },
        [RTA_IP_PROTO]          = { .type = NETLINK_TYPE_U8 },
        [RTA_SPORT]             = { .type = NETLINK_TYPE_U16 },
        [RTA_DPORT]             = { .type = NETLINK_TYPE_U16 },
        [RTA_NH_ID]             = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem rtnl_route_type_system = {
        .count = ELEMENTSOF(rtnl_route_types),
        .types = rtnl_route_types,
};

static const NLType rtnl_neigh_types[] = {
        [NDA_DST]               = { .type = NETLINK_TYPE_IN_ADDR },
        [NDA_LLADDR]            = { /* struct ether_addr, struct in_addr, or struct in6_addr */ },
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

static const NLType rtnl_addrlabel_types[] = {
        [IFAL_ADDRESS]         = { .type = NETLINK_TYPE_IN_ADDR, .size = sizeof(struct in6_addr) },
        [IFAL_LABEL]           = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem rtnl_addrlabel_type_system = {
        .count = ELEMENTSOF(rtnl_addrlabel_types),
        .types = rtnl_addrlabel_types,
};

static const NLType rtnl_routing_policy_rule_types[] = {
        [FRA_DST]                 = { .type = NETLINK_TYPE_IN_ADDR },
        [FRA_SRC]                 = { .type = NETLINK_TYPE_IN_ADDR },
        [FRA_IIFNAME]             = { .type = NETLINK_TYPE_STRING },
        [FRA_GOTO]                = { .type = NETLINK_TYPE_U32 },
        [FRA_PRIORITY]            = { .type = NETLINK_TYPE_U32 },
        [FRA_FWMARK]              = { .type = NETLINK_TYPE_U32 },
        [FRA_FLOW]                = { .type = NETLINK_TYPE_U32 },
        [FRA_TUN_ID]              = { .type = NETLINK_TYPE_U64 },
        [FRA_SUPPRESS_IFGROUP]    = { .type = NETLINK_TYPE_U32 },
        [FRA_SUPPRESS_PREFIXLEN]  = { .type = NETLINK_TYPE_U32 },
        [FRA_TABLE]               = { .type = NETLINK_TYPE_U32 },
        [FRA_FWMASK]              = { .type = NETLINK_TYPE_U32 },
        [FRA_OIFNAME]             = { .type = NETLINK_TYPE_STRING },
        [FRA_PAD]                 = { .type = NETLINK_TYPE_U32 },
        [FRA_L3MDEV]              = { .type = NETLINK_TYPE_U8 },
        [FRA_UID_RANGE]           = { .size = sizeof(struct fib_rule_uid_range) },
        [FRA_PROTOCOL]            = { .type = NETLINK_TYPE_U8 },
        [FRA_IP_PROTO]            = { .type = NETLINK_TYPE_U8 },
        [FRA_SPORT_RANGE]         = { .size = sizeof(struct fib_rule_port_range) },
        [FRA_DPORT_RANGE]         = { .size = sizeof(struct fib_rule_port_range) },
};

static const NLTypeSystem rtnl_routing_policy_rule_type_system = {
        .count = ELEMENTSOF(rtnl_routing_policy_rule_types),
        .types = rtnl_routing_policy_rule_types,
};

static const NLType rtnl_nexthop_types[] = {
        [NHA_ID]                  = { .type = NETLINK_TYPE_U32 },
        [NHA_GROUP]               = { /* array of struct nexthop_grp */ },
        [NHA_GROUP_TYPE]          = { .type = NETLINK_TYPE_U16 },
        [NHA_BLACKHOLE]           = { .type = NETLINK_TYPE_FLAG },
        [NHA_OIF]                 = { .type = NETLINK_TYPE_U32 },
        [NHA_GATEWAY]             = { .type = NETLINK_TYPE_IN_ADDR },
        [NHA_ENCAP_TYPE]          = { .type = NETLINK_TYPE_U16 },
        [NHA_ENCAP]               = { .type = NETLINK_TYPE_NESTED },
        [NHA_GROUPS]              = { .type = NETLINK_TYPE_FLAG },
        [NHA_MASTER]              = { .type = NETLINK_TYPE_U32 },
        [NHA_FDB]                 = { .type = NETLINK_TYPE_FLAG },
};

static const NLTypeSystem rtnl_nexthop_type_system = {
       .count = ELEMENTSOF(rtnl_nexthop_types),
       .types = rtnl_nexthop_types,
};

static const NLType rtnl_tca_option_data_cake_types[] = {
        [TCA_CAKE_BASE_RATE64] = { .type = NETLINK_TYPE_U64 },
        [TCA_CAKE_OVERHEAD]    = { .type = NETLINK_TYPE_S32 },
        [TCA_CAKE_MPU]         = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_tca_option_data_codel_types[] = {
        [TCA_CODEL_TARGET]        = { .type = NETLINK_TYPE_U32 },
        [TCA_CODEL_LIMIT]         = { .type = NETLINK_TYPE_U32 },
        [TCA_CODEL_INTERVAL]      = { .type = NETLINK_TYPE_U32 },
        [TCA_CODEL_ECN]           = { .type = NETLINK_TYPE_U32 },
        [TCA_CODEL_CE_THRESHOLD]  = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_tca_option_data_drr_types[] = {
        [TCA_DRR_QUANTUM] = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_tca_option_data_ets_quanta_types[] = {
        [TCA_ETS_QUANTA_BAND] = { .type = NETLINK_TYPE_U32, },
};

static const NLTypeSystem rtnl_tca_option_data_ets_quanta_type_system = {
        .count = ELEMENTSOF(rtnl_tca_option_data_ets_quanta_types),
        .types = rtnl_tca_option_data_ets_quanta_types,
};

static const NLType rtnl_tca_option_data_ets_prio_types[] = {
        [TCA_ETS_PRIOMAP_BAND] = { .type = NETLINK_TYPE_U8, },
};

static const NLTypeSystem rtnl_tca_option_data_ets_prio_type_system = {
        .count = ELEMENTSOF(rtnl_tca_option_data_ets_prio_types),
        .types = rtnl_tca_option_data_ets_prio_types,
};

static const NLType rtnl_tca_option_data_ets_types[] = {
        [TCA_ETS_NBANDS]      = { .type = NETLINK_TYPE_U8 },
        [TCA_ETS_NSTRICT]     = { .type = NETLINK_TYPE_U8 },
        [TCA_ETS_QUANTA]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_tca_option_data_ets_quanta_type_system },
        [TCA_ETS_PRIOMAP]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_tca_option_data_ets_prio_type_system },
        [TCA_ETS_QUANTA_BAND] = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_tca_option_data_fq_types[] = {
        [TCA_FQ_PLIMIT]             = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_FLOW_PLIMIT]        = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_QUANTUM]            = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_INITIAL_QUANTUM]    = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_RATE_ENABLE]        = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_FLOW_DEFAULT_RATE]  = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_FLOW_MAX_RATE]      = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_BUCKETS_LOG]        = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_FLOW_REFILL_DELAY]  = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_LOW_RATE_THRESHOLD] = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_CE_THRESHOLD]       = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_ORPHAN_MASK]        = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_tca_option_data_fq_codel_types[] = {
        [TCA_FQ_CODEL_TARGET]          = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_CODEL_LIMIT]           = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_CODEL_INTERVAL]        = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_CODEL_ECN]             = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_CODEL_FLOWS]           = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_CODEL_QUANTUM]         = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_CODEL_CE_THRESHOLD]    = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_CODEL_DROP_BATCH_SIZE] = { .type = NETLINK_TYPE_U32 },
        [TCA_FQ_CODEL_MEMORY_LIMIT]    = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_tca_option_data_fq_pie_types[] = {
        [TCA_FQ_PIE_LIMIT]   = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_tca_option_data_gred_types[] = {
        [TCA_GRED_DPS] = { .size = sizeof(struct tc_gred_sopt) },
};

static const NLType rtnl_tca_option_data_hhf_types[] = {
        [TCA_HHF_BACKLOG_LIMIT] = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_tca_option_data_htb_types[] = {
        [TCA_HTB_PARMS]  = { .size = sizeof(struct tc_htb_opt) },
        [TCA_HTB_INIT]   = { .size = sizeof(struct tc_htb_glob) },
        [TCA_HTB_CTAB]   = { .size = TC_RTAB_SIZE },
        [TCA_HTB_RTAB]   = { .size = TC_RTAB_SIZE },
        [TCA_HTB_RATE64] = { .type = NETLINK_TYPE_U64 },
        [TCA_HTB_CEIL64] = { .type = NETLINK_TYPE_U64 },
};

static const NLType rtnl_tca_option_data_pie_types[] = {
        [TCA_PIE_LIMIT]   = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_tca_option_data_qfq_types[] = {
        [TCA_QFQ_WEIGHT] = { .type = NETLINK_TYPE_U32 },
        [TCA_QFQ_LMAX]   = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_tca_option_data_sfb_types[] = {
        [TCA_SFB_PARMS] = { .size = sizeof(struct tc_sfb_qopt) },
};

static const NLType rtnl_tca_option_data_tbf_types[] = {
        [TCA_TBF_PARMS]   = { .size = sizeof(struct tc_tbf_qopt) },
        [TCA_TBF_RTAB]    = { .size = TC_RTAB_SIZE },
        [TCA_TBF_PTAB]    = { .size = TC_RTAB_SIZE },
        [TCA_TBF_RATE64]  = { .type = NETLINK_TYPE_U64 },
        [TCA_TBF_PRATE64] = { .type = NETLINK_TYPE_U64 },
        [TCA_TBF_BURST]   = { .type = NETLINK_TYPE_U32 },
        [TCA_TBF_PBURST]  = { .type = NETLINK_TYPE_U32 },
};

static const char* const nl_union_tca_option_data_table[] = {
        [NL_UNION_TCA_OPTION_DATA_CAKE] = "cake",
        [NL_UNION_TCA_OPTION_DATA_CODEL] = "codel",
        [NL_UNION_TCA_OPTION_DATA_DRR] = "drr",
        [NL_UNION_TCA_OPTION_DATA_ETS] = "ets",
        [NL_UNION_TCA_OPTION_DATA_FQ] = "fq",
        [NL_UNION_TCA_OPTION_DATA_FQ_CODEL] = "fq_codel",
        [NL_UNION_TCA_OPTION_DATA_FQ_PIE] = "fq_pie",
        [NL_UNION_TCA_OPTION_DATA_GRED] = "gred",
        [NL_UNION_TCA_OPTION_DATA_HHF] = "hhf",
        [NL_UNION_TCA_OPTION_DATA_HTB] = "htb",
        [NL_UNION_TCA_OPTION_DATA_PIE] = "pie",
        [NL_UNION_TCA_OPTION_DATA_QFQ] = "qfq",
        [NL_UNION_TCA_OPTION_DATA_SFB] = "sfb",
        [NL_UNION_TCA_OPTION_DATA_TBF] = "tbf",
};

DEFINE_STRING_TABLE_LOOKUP(nl_union_tca_option_data, NLUnionTCAOptionData);

static const NLTypeSystem rtnl_tca_option_data_type_systems[] = {
        [NL_UNION_TCA_OPTION_DATA_CAKE] =        { .count = ELEMENTSOF(rtnl_tca_option_data_cake_types),
                                                   .types = rtnl_tca_option_data_cake_types },
        [NL_UNION_TCA_OPTION_DATA_CODEL] =       { .count = ELEMENTSOF(rtnl_tca_option_data_codel_types),
                                                   .types = rtnl_tca_option_data_codel_types },
        [NL_UNION_TCA_OPTION_DATA_DRR] =         { .count = ELEMENTSOF(rtnl_tca_option_data_drr_types),
                                                   .types = rtnl_tca_option_data_drr_types },
        [NL_UNION_TCA_OPTION_DATA_ETS] =         { .count = ELEMENTSOF(rtnl_tca_option_data_ets_types),
                                                   .types = rtnl_tca_option_data_ets_types },
        [NL_UNION_TCA_OPTION_DATA_FQ] =          { .count = ELEMENTSOF(rtnl_tca_option_data_fq_types),
                                                   .types = rtnl_tca_option_data_fq_types },
        [NL_UNION_TCA_OPTION_DATA_FQ_CODEL] =    { .count = ELEMENTSOF(rtnl_tca_option_data_fq_codel_types),
                                                   .types = rtnl_tca_option_data_fq_codel_types },
        [NL_UNION_TCA_OPTION_DATA_FQ_PIE] =      { .count = ELEMENTSOF(rtnl_tca_option_data_fq_pie_types),
                                                   .types = rtnl_tca_option_data_fq_pie_types },
        [NL_UNION_TCA_OPTION_DATA_GRED] =        { .count = ELEMENTSOF(rtnl_tca_option_data_gred_types),
                                                   .types = rtnl_tca_option_data_gred_types },
        [NL_UNION_TCA_OPTION_DATA_HHF] =         { .count = ELEMENTSOF(rtnl_tca_option_data_hhf_types),
                                                   .types = rtnl_tca_option_data_hhf_types },
        [NL_UNION_TCA_OPTION_DATA_HTB] =         { .count = ELEMENTSOF(rtnl_tca_option_data_htb_types),
                                                   .types = rtnl_tca_option_data_htb_types },
        [NL_UNION_TCA_OPTION_DATA_PIE] =         { .count = ELEMENTSOF(rtnl_tca_option_data_pie_types),
                                                   .types = rtnl_tca_option_data_pie_types },
        [NL_UNION_TCA_OPTION_DATA_QFQ] =         { .count = ELEMENTSOF(rtnl_tca_option_data_qfq_types),
                                                   .types = rtnl_tca_option_data_qfq_types },
        [NL_UNION_TCA_OPTION_DATA_SFB] =         { .count = ELEMENTSOF(rtnl_tca_option_data_sfb_types),
                                                   .types = rtnl_tca_option_data_sfb_types },
        [NL_UNION_TCA_OPTION_DATA_TBF] =         { .count = ELEMENTSOF(rtnl_tca_option_data_tbf_types),
                                                   .types = rtnl_tca_option_data_tbf_types },
};

static const NLTypeSystemUnion rtnl_tca_option_data_type_system_union = {
        .num = _NL_UNION_TCA_OPTION_DATA_MAX,
        .lookup = nl_union_tca_option_data_from_string,
        .type_systems = rtnl_tca_option_data_type_systems,
        .match_type = NL_MATCH_SIBLING,
        .match = TCA_KIND,
};

static const NLType rtnl_tca_types[] = {
        [TCA_KIND]           = { .type = NETLINK_TYPE_STRING },
        [TCA_OPTIONS]        = { .type = NETLINK_TYPE_UNION, .type_system_union = &rtnl_tca_option_data_type_system_union },
        [TCA_INGRESS_BLOCK]  = { .type = NETLINK_TYPE_U32 },
        [TCA_EGRESS_BLOCK]   = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem rtnl_tca_type_system = {
        .count = ELEMENTSOF(rtnl_tca_types),
        .types = rtnl_tca_types,
};

static const NLType mdb_types[] = {
        [MDBA_SET_ENTRY]     = { .size = sizeof(struct br_port_msg) },
};

static const NLTypeSystem rtnl_mdb_type_system = {
        .count = ELEMENTSOF(mdb_types),
        .types = mdb_types,
};

static const NLType error_types[] = {
        [NLMSGERR_ATTR_MSG]  = { .type = NETLINK_TYPE_STRING },
        [NLMSGERR_ATTR_OFFS] = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem error_type_system = {
        .count = ELEMENTSOF(error_types),
        .types = error_types,
};

static const NLType rtnl_types[] = {
        [NLMSG_DONE]       = { .type = NETLINK_TYPE_NESTED, .type_system = &empty_type_system, .size = 0 },
        [NLMSG_ERROR]      = { .type = NETLINK_TYPE_NESTED, .type_system = &error_type_system, .size = sizeof(struct nlmsgerr) },
        [RTM_NEWLINK]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
        [RTM_DELLINK]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
        [RTM_GETLINK]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
        [RTM_SETLINK]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
        [RTM_NEWLINKPROP]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
        [RTM_DELLINKPROP]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
        [RTM_GETLINKPROP]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
        [RTM_NEWADDR]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_address_type_system, .size = sizeof(struct ifaddrmsg) },
        [RTM_DELADDR]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_address_type_system, .size = sizeof(struct ifaddrmsg) },
        [RTM_GETADDR]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_address_type_system, .size = sizeof(struct ifaddrmsg) },
        [RTM_NEWROUTE]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_route_type_system, .size = sizeof(struct rtmsg) },
        [RTM_DELROUTE]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_route_type_system, .size = sizeof(struct rtmsg) },
        [RTM_GETROUTE]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_route_type_system, .size = sizeof(struct rtmsg) },
        [RTM_NEWNEIGH]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_neigh_type_system, .size = sizeof(struct ndmsg) },
        [RTM_DELNEIGH]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_neigh_type_system, .size = sizeof(struct ndmsg) },
        [RTM_GETNEIGH]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_neigh_type_system, .size = sizeof(struct ndmsg) },
        [RTM_NEWADDRLABEL] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_addrlabel_type_system, .size = sizeof(struct ifaddrlblmsg) },
        [RTM_DELADDRLABEL] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_addrlabel_type_system, .size = sizeof(struct ifaddrlblmsg) },
        [RTM_GETADDRLABEL] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_addrlabel_type_system, .size = sizeof(struct ifaddrlblmsg) },
        [RTM_NEWRULE]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_routing_policy_rule_type_system, .size = sizeof(struct fib_rule_hdr) },
        [RTM_DELRULE]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_routing_policy_rule_type_system, .size = sizeof(struct fib_rule_hdr) },
        [RTM_GETRULE]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_routing_policy_rule_type_system, .size = sizeof(struct fib_rule_hdr) },
        [RTM_NEWNEXTHOP]   = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_nexthop_type_system, .size = sizeof(struct nhmsg) },
        [RTM_DELNEXTHOP]   = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_nexthop_type_system, .size = sizeof(struct nhmsg) },
        [RTM_GETNEXTHOP]   = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_nexthop_type_system, .size = sizeof(struct nhmsg) },
        [RTM_NEWQDISC]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_tca_type_system, .size = sizeof(struct tcmsg) },
        [RTM_DELQDISC]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_tca_type_system, .size = sizeof(struct tcmsg) },
        [RTM_GETQDISC]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_tca_type_system, .size = sizeof(struct tcmsg) },
        [RTM_NEWTCLASS]    = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_tca_type_system, .size = sizeof(struct tcmsg) },
        [RTM_DELTCLASS]    = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_tca_type_system, .size = sizeof(struct tcmsg) },
        [RTM_GETTCLASS]    = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_tca_type_system, .size = sizeof(struct tcmsg) },
        [RTM_NEWMDB]       = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_mdb_type_system, .size = sizeof(struct br_port_msg) },
        [RTM_DELMDB]       = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_mdb_type_system, .size = sizeof(struct br_port_msg) },
        [RTM_GETMDB]       = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_mdb_type_system, .size = sizeof(struct br_port_msg) },
};

const NLTypeSystem rtnl_type_system_root = {
        .count = ELEMENTSOF(rtnl_types),
        .types = rtnl_types,
};

static const NLType genl_wireguard_allowedip_types[] = {
        [WGALLOWEDIP_A_FAMILY] = { .type = NETLINK_TYPE_U16 },
        [WGALLOWEDIP_A_IPADDR] = { .type = NETLINK_TYPE_IN_ADDR },
        [WGALLOWEDIP_A_CIDR_MASK] = { .type = NETLINK_TYPE_U8 },
};

static const NLTypeSystem genl_wireguard_allowedip_type_system = {
        .count = ELEMENTSOF(genl_wireguard_allowedip_types),
        .types = genl_wireguard_allowedip_types,
};

static const NLType genl_wireguard_peer_types[] = {
        [WGPEER_A_PUBLIC_KEY] = { .size = WG_KEY_LEN  },
        [WGPEER_A_FLAGS] = { .type = NETLINK_TYPE_U32 },
        [WGPEER_A_PRESHARED_KEY] = { .size = WG_KEY_LEN },
        [WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL] = { .type = NETLINK_TYPE_U16 },
        [WGPEER_A_ENDPOINT] = { .type = NETLINK_TYPE_SOCKADDR },
        [WGPEER_A_ALLOWEDIPS] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_wireguard_allowedip_type_system },
};

static const NLTypeSystem genl_wireguard_peer_type_system = {
        .count = ELEMENTSOF(genl_wireguard_peer_types),
        .types = genl_wireguard_peer_types,
};

static const NLType genl_wireguard_set_device_types[] = {
        [WGDEVICE_A_IFINDEX] = { .type = NETLINK_TYPE_U32 },
        [WGDEVICE_A_IFNAME] = { .type = NETLINK_TYPE_STRING, .size = IFNAMSIZ-1 },
        [WGDEVICE_A_FLAGS] = { .type = NETLINK_TYPE_U32 },
        [WGDEVICE_A_PRIVATE_KEY] = { .size = WG_KEY_LEN },
        [WGDEVICE_A_LISTEN_PORT] = { .type = NETLINK_TYPE_U16 },
        [WGDEVICE_A_FWMARK] = { .type = NETLINK_TYPE_U32 },
        [WGDEVICE_A_PEERS] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_wireguard_peer_type_system },
};

static const NLTypeSystem genl_wireguard_set_device_type_system = {
        .count = ELEMENTSOF(genl_wireguard_set_device_types),
        .types = genl_wireguard_set_device_types,
};

static const NLType genl_wireguard_cmds[] = {
        [WG_CMD_SET_DEVICE] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_wireguard_set_device_type_system },
};

static const NLTypeSystem genl_wireguard_type_system = {
        .count = ELEMENTSOF(genl_wireguard_cmds),
        .types = genl_wireguard_cmds,
};

static const NLType genl_mcast_group_types[] = {
        [CTRL_ATTR_MCAST_GRP_NAME]  = { .type = NETLINK_TYPE_STRING },
        [CTRL_ATTR_MCAST_GRP_ID]    = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem genl_mcast_group_type_system = {
        .count = ELEMENTSOF(genl_mcast_group_types),
        .types = genl_mcast_group_types,
};

static const NLType genl_get_family_types[] = {
        [CTRL_ATTR_FAMILY_NAME]  = { .type = NETLINK_TYPE_STRING },
        [CTRL_ATTR_FAMILY_ID]    = { .type = NETLINK_TYPE_U16 },
        [CTRL_ATTR_MCAST_GROUPS] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_mcast_group_type_system },
};

static const NLTypeSystem genl_get_family_type_system = {
        .count = ELEMENTSOF(genl_get_family_types),
        .types = genl_get_family_types,
};

static const NLType genl_ctrl_id_ctrl_cmds[] = {
        [CTRL_CMD_GETFAMILY] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_get_family_type_system },
};

static const NLTypeSystem genl_ctrl_id_ctrl_type_system = {
        .count = ELEMENTSOF(genl_ctrl_id_ctrl_cmds),
        .types = genl_ctrl_id_ctrl_cmds,
};

static const NLType genl_fou_types[] = {
        [FOU_ATTR_PORT]              = { .type = NETLINK_TYPE_U16 },
        [FOU_ATTR_AF]                = { .type = NETLINK_TYPE_U8 },
        [FOU_ATTR_IPPROTO]           = { .type = NETLINK_TYPE_U8 },
        [FOU_ATTR_TYPE]              = { .type = NETLINK_TYPE_U8 },
        [FOU_ATTR_REMCSUM_NOPARTIAL] = { .type = NETLINK_TYPE_FLAG },
        [FOU_ATTR_LOCAL_V4]          = { .type = NETLINK_TYPE_IN_ADDR },
        [FOU_ATTR_PEER_V4]           = { .type = NETLINK_TYPE_IN_ADDR },
        [FOU_ATTR_LOCAL_V6]          = { .type = NETLINK_TYPE_IN_ADDR },
        [FOU_ATTR_PEER_V6]           = { .type = NETLINK_TYPE_IN_ADDR},
        [FOU_ATTR_PEER_PORT]         = { .type = NETLINK_TYPE_U16},
        [FOU_ATTR_IFINDEX]           = { .type = NETLINK_TYPE_U32},
};

static const NLTypeSystem genl_fou_type_system = {
        .count = ELEMENTSOF(genl_fou_types),
        .types = genl_fou_types,
};

static const NLType genl_fou_cmds[] = {
        [FOU_CMD_ADD] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_fou_type_system },
        [FOU_CMD_DEL] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_fou_type_system },
        [FOU_CMD_GET] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_fou_type_system },
};

static const NLTypeSystem genl_fou_cmds_type_system = {
        .count = ELEMENTSOF(genl_fou_cmds),
        .types = genl_fou_cmds,
};

static const NLType genl_l2tp_types[] = {
        [L2TP_ATTR_PW_TYPE]           = { .type = NETLINK_TYPE_U16 },
        [L2TP_ATTR_ENCAP_TYPE]        = { .type = NETLINK_TYPE_U16 },
        [L2TP_ATTR_OFFSET]            = { .type = NETLINK_TYPE_U16 },
        [L2TP_ATTR_DATA_SEQ]          = { .type = NETLINK_TYPE_U16 },
        [L2TP_ATTR_L2SPEC_TYPE]       = { .type = NETLINK_TYPE_U8 },
        [L2TP_ATTR_L2SPEC_LEN]        = { .type = NETLINK_TYPE_U8 },
        [L2TP_ATTR_PROTO_VERSION]     = { .type = NETLINK_TYPE_U8 },
        [L2TP_ATTR_IFNAME]            = { .type = NETLINK_TYPE_STRING },
        [L2TP_ATTR_CONN_ID]           = { .type = NETLINK_TYPE_U32 },
        [L2TP_ATTR_PEER_CONN_ID]      = { .type = NETLINK_TYPE_U32 },
        [L2TP_ATTR_SESSION_ID]        = { .type = NETLINK_TYPE_U32 },
        [L2TP_ATTR_PEER_SESSION_ID]   = { .type = NETLINK_TYPE_U32 },
        [L2TP_ATTR_UDP_CSUM]          = { .type = NETLINK_TYPE_U8 },
        [L2TP_ATTR_VLAN_ID]           = { .type = NETLINK_TYPE_U16 },
        [L2TP_ATTR_RECV_SEQ]          = { .type = NETLINK_TYPE_U8 },
        [L2TP_ATTR_SEND_SEQ]          = { .type = NETLINK_TYPE_U8 },
        [L2TP_ATTR_LNS_MODE]          = { .type = NETLINK_TYPE_U8 },
        [L2TP_ATTR_USING_IPSEC]       = { .type = NETLINK_TYPE_U8 },
        [L2TP_ATTR_FD]                = { .type = NETLINK_TYPE_U32 },
        [L2TP_ATTR_IP_SADDR]          = { .type = NETLINK_TYPE_IN_ADDR },
        [L2TP_ATTR_IP_DADDR]          = { .type = NETLINK_TYPE_IN_ADDR },
        [L2TP_ATTR_UDP_SPORT]         = { .type = NETLINK_TYPE_U16 },
        [L2TP_ATTR_UDP_DPORT]         = { .type = NETLINK_TYPE_U16 },
        [L2TP_ATTR_IP6_SADDR]         = { .type = NETLINK_TYPE_IN_ADDR },
        [L2TP_ATTR_IP6_DADDR]         = { .type = NETLINK_TYPE_IN_ADDR },
        [L2TP_ATTR_UDP_ZERO_CSUM6_TX] = { .type = NETLINK_TYPE_FLAG },
        [L2TP_ATTR_UDP_ZERO_CSUM6_RX] = { .type = NETLINK_TYPE_FLAG },
};

static const NLTypeSystem genl_l2tp_type_system = {
        .count = ELEMENTSOF(genl_l2tp_types),
        .types = genl_l2tp_types,
};

static const NLType genl_l2tp[]   = {
        [L2TP_CMD_TUNNEL_CREATE]  = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_l2tp_type_system },
        [L2TP_CMD_TUNNEL_DELETE]  = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_l2tp_type_system },
        [L2TP_CMD_TUNNEL_MODIFY]  = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_l2tp_type_system },
        [L2TP_CMD_TUNNEL_GET]     = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_l2tp_type_system },
        [L2TP_CMD_SESSION_CREATE] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_l2tp_type_system },
        [L2TP_CMD_SESSION_DELETE] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_l2tp_type_system },
        [L2TP_CMD_SESSION_MODIFY] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_l2tp_type_system },
        [L2TP_CMD_SESSION_GET]    = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_l2tp_type_system },
};

static const NLTypeSystem genl_l2tp_tunnel_session_type_system = {
        .count = ELEMENTSOF(genl_l2tp),
        .types = genl_l2tp,
};

static const NLType genl_rxsc_types[] = {
        [MACSEC_RXSC_ATTR_SCI] = { .type = NETLINK_TYPE_U64 },
};

static const NLTypeSystem genl_rxsc_config_type_system = {
        .count = ELEMENTSOF(genl_rxsc_types),
        .types = genl_rxsc_types,
};

static const NLType genl_macsec_rxsc_types[] = {
        [MACSEC_ATTR_IFINDEX]     = { .type = NETLINK_TYPE_U32 },
        [MACSEC_ATTR_RXSC_CONFIG] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_rxsc_config_type_system },
};

static const NLTypeSystem genl_macsec_rxsc_type_system = {
        .count = ELEMENTSOF(genl_macsec_rxsc_types),
        .types = genl_macsec_rxsc_types,
};

static const NLType genl_macsec_sa_config_types[] = {
        [MACSEC_SA_ATTR_AN]     = { .type = NETLINK_TYPE_U8 },
        [MACSEC_SA_ATTR_ACTIVE] = { .type = NETLINK_TYPE_U8 },
        [MACSEC_SA_ATTR_PN]     = { .type = NETLINK_TYPE_U32 },
        [MACSEC_SA_ATTR_KEYID]  = { .size = MACSEC_KEYID_LEN },
        [MACSEC_SA_ATTR_KEY]    = { .size = MACSEC_MAX_KEY_LEN },
};

static const NLTypeSystem genl_macsec_sa_config_type_system = {
        .count = ELEMENTSOF(genl_macsec_sa_config_types),
        .types = genl_macsec_sa_config_types,
};

static const NLType genl_macsec_rxsa_types[] = {
        [MACSEC_ATTR_IFINDEX]   = { .type = NETLINK_TYPE_U32 },
        [MACSEC_ATTR_SA_CONFIG] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_macsec_sa_config_type_system },
};

static const NLTypeSystem genl_macsec_rxsa_type_system = {
        .count = ELEMENTSOF(genl_macsec_rxsa_types),
        .types = genl_macsec_rxsa_types,
};

static const NLType genl_macsec_sa_types[] = {
        [MACSEC_ATTR_IFINDEX]     = { .type = NETLINK_TYPE_U32 },
        [MACSEC_ATTR_RXSC_CONFIG] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_rxsc_config_type_system },
        [MACSEC_ATTR_SA_CONFIG]   = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_macsec_sa_config_type_system },
};

static const NLTypeSystem genl_macsec_sa_type_system = {
        .count = ELEMENTSOF(genl_macsec_sa_types),
        .types = genl_macsec_sa_types,
};

static const NLType genl_macsec[]   = {
        [MACSEC_CMD_ADD_RXSC]  = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_macsec_rxsc_type_system },
        [MACSEC_CMD_ADD_TXSA]  = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_macsec_rxsa_type_system},
        [MACSEC_CMD_ADD_RXSA]  = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_macsec_sa_type_system },
};

static const NLTypeSystem genl_macsec_device_type_system = {
        .count = ELEMENTSOF(genl_macsec),
        .types = genl_macsec,
};

static const NLType genl_nl80211_types[] = {
        [NL80211_ATTR_IFINDEX] = { .type = NETLINK_TYPE_U32 },
        [NL80211_ATTR_MAC]     = { .type = NETLINK_TYPE_ETHER_ADDR },
        [NL80211_ATTR_SSID]    = { .type = NETLINK_TYPE_STRING },
        [NL80211_ATTR_IFTYPE]  = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem genl_nl80211_type_system = {
        .count = ELEMENTSOF(genl_nl80211_types),
        .types = genl_nl80211_types,
};

static const NLType genl_nl80211_cmds[] = {
        [NL80211_CMD_GET_WIPHY]     = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_nl80211_type_system },
        [NL80211_CMD_SET_WIPHY]     = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_nl80211_type_system },
        [NL80211_CMD_NEW_WIPHY]     = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_nl80211_type_system },
        [NL80211_CMD_DEL_WIPHY]     = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_nl80211_type_system },
        [NL80211_CMD_GET_INTERFACE] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_nl80211_type_system },
        [NL80211_CMD_SET_INTERFACE] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_nl80211_type_system },
        [NL80211_CMD_NEW_INTERFACE] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_nl80211_type_system },
        [NL80211_CMD_DEL_INTERFACE] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_nl80211_type_system },
        [NL80211_CMD_GET_STATION]   = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_nl80211_type_system },
        [NL80211_CMD_SET_STATION]   = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_nl80211_type_system },
        [NL80211_CMD_NEW_STATION]   = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_nl80211_type_system },
        [NL80211_CMD_DEL_STATION]   = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_nl80211_type_system },
};

static const NLTypeSystem genl_nl80211_cmds_type_system = {
        .count = ELEMENTSOF(genl_nl80211_cmds),
        .types = genl_nl80211_cmds,
};

static const NLType genl_batadv_types[] = {
        [BATADV_ATTR_VERSION]                       = { .type = NETLINK_TYPE_STRING },
        [BATADV_ATTR_ALGO_NAME]                     = { .type = NETLINK_TYPE_STRING },
        [BATADV_ATTR_MESH_IFINDEX]                  = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_MESH_IFNAME]                   = { .type = NETLINK_TYPE_STRING, .size = IFNAMSIZ },
        [BATADV_ATTR_MESH_ADDRESS]                  = { .size = ETH_ALEN },
        [BATADV_ATTR_HARD_IFINDEX]                  = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_HARD_IFNAME]                   = { .type = NETLINK_TYPE_STRING, .size = IFNAMSIZ },
        [BATADV_ATTR_HARD_ADDRESS]                  = { .size = ETH_ALEN },
        [BATADV_ATTR_ORIG_ADDRESS]                  = { .size = ETH_ALEN },
        [BATADV_ATTR_TPMETER_RESULT]                = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_TPMETER_TEST_TIME]             = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_TPMETER_BYTES]                 = { .type = NETLINK_TYPE_U64 },
        [BATADV_ATTR_TPMETER_COOKIE]                = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_PAD]                           = { .type = NETLINK_TYPE_UNSPEC },
        [BATADV_ATTR_ACTIVE]                        = { .type = NETLINK_TYPE_FLAG },
        [BATADV_ATTR_TT_ADDRESS]                    = { .size = ETH_ALEN },
        [BATADV_ATTR_TT_TTVN]                       = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_TT_LAST_TTVN]                  = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_TT_CRC32]                      = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_TT_VID]                        = { .type = NETLINK_TYPE_U16 },
        [BATADV_ATTR_TT_FLAGS]                      = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_FLAG_BEST]                     = { .type = NETLINK_TYPE_FLAG },
        [BATADV_ATTR_LAST_SEEN_MSECS]               = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_NEIGH_ADDRESS]                 = { .size = ETH_ALEN },
        [BATADV_ATTR_TQ]                            = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_THROUGHPUT]                    = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_BANDWIDTH_UP]                  = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_BANDWIDTH_DOWN]                = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_ROUTER]                        = { .size = ETH_ALEN },
        [BATADV_ATTR_BLA_OWN]                       = { .type = NETLINK_TYPE_FLAG },
        [BATADV_ATTR_BLA_ADDRESS]                   = { .size = ETH_ALEN },
        [BATADV_ATTR_BLA_VID]                       = { .type = NETLINK_TYPE_U16 },
        [BATADV_ATTR_BLA_BACKBONE]                  = { .size = ETH_ALEN },
        [BATADV_ATTR_BLA_CRC]                       = { .type = NETLINK_TYPE_U16 },
        [BATADV_ATTR_DAT_CACHE_IP4ADDRESS]          = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_DAT_CACHE_HWADDRESS]           = { .size = ETH_ALEN },
        [BATADV_ATTR_DAT_CACHE_VID]                 = { .type = NETLINK_TYPE_U16 },
        [BATADV_ATTR_MCAST_FLAGS]                   = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_MCAST_FLAGS_PRIV]              = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_VLANID]                        = { .type = NETLINK_TYPE_U16 },
        [BATADV_ATTR_AGGREGATED_OGMS_ENABLED]       = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_AP_ISOLATION_ENABLED]          = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_ISOLATION_MARK]                = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_ISOLATION_MASK]                = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_BONDING_ENABLED]               = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_BRIDGE_LOOP_AVOIDANCE_ENABLED] = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_DISTRIBUTED_ARP_TABLE_ENABLED] = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_FRAGMENTATION_ENABLED]         = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_GW_BANDWIDTH_DOWN]             = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_GW_BANDWIDTH_UP]               = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_GW_MODE]                       = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_GW_SEL_CLASS]                  = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_HOP_PENALTY]                   = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_LOG_LEVEL]                     = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_MULTICAST_FORCEFLOOD_ENABLED]  = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_MULTICAST_FANOUT]              = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_NETWORK_CODING_ENABLED]        = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_ORIG_INTERVAL]                 = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_ELP_INTERVAL]                  = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_THROUGHPUT_OVERRIDE]           = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem genl_batadv_type_system = {
        .count = ELEMENTSOF(genl_batadv_types),
        .types = genl_batadv_types,
};

static const NLType genl_batadv_cmds[] = {
        [BATADV_CMD_SET_MESH] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_batadv_type_system },
};

static const NLTypeSystem genl_batadv_cmds_type_system = {
        .count = ELEMENTSOF(genl_batadv_cmds),
        .types = genl_batadv_cmds,
};

static const NLType genl_families[] = {
        [SD_GENL_ID_CTRL]   = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_ctrl_id_ctrl_type_system },
        [SD_GENL_WIREGUARD] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_wireguard_type_system },
        [SD_GENL_FOU]       = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_fou_cmds_type_system },
        [SD_GENL_L2TP]      = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_l2tp_tunnel_session_type_system },
        [SD_GENL_MACSEC]    = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_macsec_device_type_system },
        [SD_GENL_NL80211]   = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_nl80211_cmds_type_system },
        [SD_GENL_BATADV]    = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_batadv_cmds_type_system },
};

static const NLType nfnl_nft_table_types[] = {
        [NFTA_TABLE_NAME]  = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_TABLE_FLAGS] = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem nfnl_nft_table_type_system = {
        .count = ELEMENTSOF(nfnl_nft_table_types),
        .types = nfnl_nft_table_types,
};

static const NLType nfnl_nft_chain_hook_types[] = {
        [NFTA_HOOK_HOOKNUM]  = { .type = NETLINK_TYPE_U32 },
        [NFTA_HOOK_PRIORITY] = { .type = NETLINK_TYPE_U32 },
        [NFTA_HOOK_DEV]      = { .type = NETLINK_TYPE_STRING, .size = IFNAMSIZ - 1 },
};

static const NLTypeSystem nfnl_nft_chain_hook_type_system = {
        .count = ELEMENTSOF(nfnl_nft_chain_hook_types),
        .types = nfnl_nft_chain_hook_types,
};

static const NLType nfnl_nft_chain_types[] = {
        [NFTA_CHAIN_TABLE] = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_CHAIN_NAME]  = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_CHAIN_HOOK]  = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_chain_hook_type_system },
        [NFTA_CHAIN_TYPE]  = { .type = NETLINK_TYPE_STRING, .size = 16 },
        [NFTA_CHAIN_FLAGS] = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem nfnl_nft_chain_type_system = {
        .count = ELEMENTSOF(nfnl_nft_chain_types),
        .types = nfnl_nft_chain_types,
};

static const NLType nfnl_nft_expr_meta_types[] = {
        [NFTA_META_DREG] = { .type = NETLINK_TYPE_U32 },
        [NFTA_META_KEY]  = { .type = NETLINK_TYPE_U32 },
        [NFTA_META_SREG] = { .type = NETLINK_TYPE_U32 },
};

static const NLType nfnl_nft_expr_payload_types[] = {
        [NFTA_PAYLOAD_DREG]   = { .type = NETLINK_TYPE_U32 },
        [NFTA_PAYLOAD_BASE]   = { .type = NETLINK_TYPE_U32 },
        [NFTA_PAYLOAD_OFFSET] = { .type = NETLINK_TYPE_U32 },
        [NFTA_PAYLOAD_LEN]    = { .type = NETLINK_TYPE_U32 },
};

static const NLType nfnl_nft_expr_nat_types[] = {
        [NFTA_NAT_TYPE]          = { .type = NETLINK_TYPE_U32 },
        [NFTA_NAT_FAMILY]        = { .type = NETLINK_TYPE_U32 },
        [NFTA_NAT_REG_ADDR_MIN]  = { .type = NETLINK_TYPE_U32 },
        [NFTA_NAT_REG_ADDR_MAX]  = { .type = NETLINK_TYPE_U32 },
        [NFTA_NAT_REG_PROTO_MIN] = { .type = NETLINK_TYPE_U32 },
        [NFTA_NAT_REG_PROTO_MAX] = { .type = NETLINK_TYPE_U32 },
        [NFTA_NAT_FLAGS]         = { .type = NETLINK_TYPE_U32 },
};

static const NLType nfnl_nft_data_types[] = {
        [NFTA_DATA_VALUE] = { .type = NETLINK_TYPE_BINARY },
};

static const NLTypeSystem nfnl_nft_data_type_system = {
        .count = ELEMENTSOF(nfnl_nft_data_types),
        .types = nfnl_nft_data_types,
};

static const NLType nfnl_nft_expr_bitwise_types[] = {
        [NFTA_BITWISE_SREG] = { .type = NETLINK_TYPE_U32 },
        [NFTA_BITWISE_DREG] = { .type = NETLINK_TYPE_U32 },
        [NFTA_BITWISE_LEN]  = { .type = NETLINK_TYPE_U32 },
        [NFTA_BITWISE_MASK] = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_data_type_system },
        [NFTA_BITWISE_XOR]  = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_data_type_system },
};

static const NLType nfnl_nft_expr_cmp_types[] = {
        [NFTA_CMP_SREG] = { .type = NETLINK_TYPE_U32 },
        [NFTA_CMP_OP]   = { .type = NETLINK_TYPE_U32 },
        [NFTA_CMP_DATA] = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_data_type_system },
};

static const NLType nfnl_nft_expr_fib_types[] = {
        [NFTA_FIB_DREG]   = { .type = NETLINK_TYPE_U32 },
        [NFTA_FIB_RESULT] = { .type = NETLINK_TYPE_U32 },
        [NFTA_FIB_FLAGS]  = { .type = NETLINK_TYPE_U32 },
};

static const NLType nfnl_nft_expr_lookup_types[] = {
        [NFTA_LOOKUP_SET]   = { .type = NETLINK_TYPE_STRING },
        [NFTA_LOOKUP_SREG]  = { .type = NETLINK_TYPE_U32 },
        [NFTA_LOOKUP_DREG]  = { .type = NETLINK_TYPE_U32 },
        [NFTA_LOOKUP_FLAGS] = { .type = NETLINK_TYPE_U32 },
};

static const NLType nfnl_nft_expr_masq_types[] = {
        [NFTA_MASQ_FLAGS]         = { .type = NETLINK_TYPE_U32 },
        [NFTA_MASQ_REG_PROTO_MIN] = { .type = NETLINK_TYPE_U32 },
        [NFTA_MASQ_REG_PROTO_MAX] = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem nfnl_expr_data_type_systems[] = {
        [NL_UNION_NFT_EXPR_DATA_BITWISE]   =  { .count = ELEMENTSOF(nfnl_nft_expr_bitwise_types),
                                                .types = nfnl_nft_expr_bitwise_types },
        [NL_UNION_NFT_EXPR_DATA_CMP]       =  { .count = ELEMENTSOF(nfnl_nft_expr_cmp_types),
                                                .types = nfnl_nft_expr_cmp_types },
        [NL_UNION_NFT_EXPR_DATA_FIB]       =  { .count = ELEMENTSOF(nfnl_nft_expr_fib_types),
                                                .types = nfnl_nft_expr_fib_types },
        [NL_UNION_NFT_EXPR_DATA_LOOKUP]    =  { .count = ELEMENTSOF(nfnl_nft_expr_lookup_types),
                                                .types = nfnl_nft_expr_lookup_types },
        [NL_UNION_NFT_EXPR_DATA_MASQ]      =  { .count = ELEMENTSOF(nfnl_nft_expr_masq_types),
                                                .types = nfnl_nft_expr_masq_types },
        [NL_UNION_NFT_EXPR_DATA_META]      =  { .count = ELEMENTSOF(nfnl_nft_expr_meta_types),
                                                .types = nfnl_nft_expr_meta_types },
        [NL_UNION_NFT_EXPR_DATA_NAT]       =  { .count = ELEMENTSOF(nfnl_nft_expr_nat_types),
                                                .types = nfnl_nft_expr_nat_types },
        [NL_UNION_NFT_EXPR_DATA_PAYLOAD]   =  { .count = ELEMENTSOF(nfnl_nft_expr_payload_types),
                                                .types = nfnl_nft_expr_payload_types },
};

static const char* const nl_union_nft_expr_data_table[] = {
        [NL_UNION_NFT_EXPR_DATA_BITWISE] = "bitwise",
        [NL_UNION_NFT_EXPR_DATA_CMP]     = "cmp",
        [NL_UNION_NFT_EXPR_DATA_LOOKUP]  = "lookup",
        [NL_UNION_NFT_EXPR_DATA_META]    = "meta",
        [NL_UNION_NFT_EXPR_DATA_FIB]     = "fib",
        [NL_UNION_NFT_EXPR_DATA_MASQ]    = "masq",
        [NL_UNION_NFT_EXPR_DATA_NAT]     = "nat",
        [NL_UNION_NFT_EXPR_DATA_PAYLOAD] = "payload",
};

DEFINE_STRING_TABLE_LOOKUP(nl_union_nft_expr_data, NLUnionNFTExprData);

static const NLTypeSystemUnion nfnl_nft_data_expr_type_system_union = {
        .num = _NL_UNION_NFT_EXPR_DATA_MAX,
        .lookup = nl_union_nft_expr_data_from_string,
        .type_systems = nfnl_expr_data_type_systems,
        .match_type = NL_MATCH_SIBLING,
        .match = NFTA_EXPR_NAME,
};

static const NLType nfnl_nft_rule_expr_types[] = {
        [NFTA_EXPR_NAME] = { .type = NETLINK_TYPE_STRING, .size = 16 },
        [NFTA_EXPR_DATA] = { .type = NETLINK_TYPE_UNION,
                             .type_system_union = &nfnl_nft_data_expr_type_system_union },
};

static const NLTypeSystem nfnl_nft_rule_expr_type_system = {
        .count = ELEMENTSOF(nfnl_nft_rule_expr_types),
        .types = nfnl_nft_rule_expr_types,
};

static const NLType nfnl_nft_rule_types[] = {
        [NFTA_RULE_TABLE]       = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_RULE_CHAIN]       = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_RULE_EXPRESSIONS] = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_rule_expr_type_system }
};

static const NLTypeSystem nfnl_nft_rule_type_system = {
        .count = ELEMENTSOF(nfnl_nft_rule_types),
        .types = nfnl_nft_rule_types,
};

static const NLType nfnl_nft_set_types[] = {
        [NFTA_SET_TABLE]      = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_SET_NAME]       = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_SET_FLAGS]      = { .type = NETLINK_TYPE_U32 },
        [NFTA_SET_KEY_TYPE]   = { .type = NETLINK_TYPE_U32 },
        [NFTA_SET_KEY_LEN]    = { .type = NETLINK_TYPE_U32 },
        [NFTA_SET_DATA_TYPE]  = { .type = NETLINK_TYPE_U32 },
        [NFTA_SET_DATA_LEN]   = { .type = NETLINK_TYPE_U32 },
        [NFTA_SET_POLICY]     = { .type = NETLINK_TYPE_U32 },
        [NFTA_SET_ID]         = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem nfnl_nft_set_type_system = {
        .count = ELEMENTSOF(nfnl_nft_set_types),
        .types = nfnl_nft_set_types,
};

static const NLType nfnl_nft_setelem_types[] = {
        [NFTA_SET_ELEM_KEY]   = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_data_type_system },
        [NFTA_SET_ELEM_DATA]  = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_data_type_system },
        [NFTA_SET_ELEM_FLAGS] = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem nfnl_nft_setelem_type_system = {
        .count = ELEMENTSOF(nfnl_nft_setelem_types),
        .types = nfnl_nft_setelem_types,
};

static const NLType nfnl_nft_setelem_list_types[] = {
        [NFTA_SET_ELEM_LIST_TABLE]    = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_SET_ELEM_LIST_SET]      = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_SET_ELEM_LIST_ELEMENTS] = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_setelem_type_system },
};

static const NLTypeSystem nfnl_nft_setelem_list_type_system = {
        .count = ELEMENTSOF(nfnl_nft_setelem_list_types),
        .types = nfnl_nft_setelem_list_types,
};

static const NLType nfnl_nft_msg_types [] = {
        [NFT_MSG_DELTABLE]   = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_table_type_system, .size = sizeof(struct nfgenmsg) },
        [NFT_MSG_NEWTABLE]   = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_table_type_system, .size = sizeof(struct nfgenmsg) },
        [NFT_MSG_NEWCHAIN]   = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_chain_type_system, .size = sizeof(struct nfgenmsg) },
        [NFT_MSG_NEWRULE]    = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_rule_type_system, .size = sizeof(struct nfgenmsg) },
        [NFT_MSG_NEWSET]     = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_set_type_system, .size = sizeof(struct nfgenmsg) },
        [NFT_MSG_NEWSETELEM] = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_setelem_list_type_system, .size = sizeof(struct nfgenmsg) },
        [NFT_MSG_DELSETELEM] = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_setelem_list_type_system, .size = sizeof(struct nfgenmsg) },
};

static const NLTypeSystem nfnl_nft_msg_type_system = {
        .count = ELEMENTSOF(nfnl_nft_msg_types),
        .types = nfnl_nft_msg_types,
};

static const NLType nfnl_msg_batch_types [] = {
        [NFNL_BATCH_GENID] = { .type = NETLINK_TYPE_U32 }
};

static const NLTypeSystem nfnl_msg_batch_type_system = {
        .count = ELEMENTSOF(nfnl_msg_batch_types),
        .types = nfnl_msg_batch_types,
};

static const NLType nfnl_types[] = {
        [NLMSG_DONE]           = { .type = NETLINK_TYPE_NESTED, .type_system = &empty_type_system, .size = 0 },
        [NLMSG_ERROR]          = { .type = NETLINK_TYPE_NESTED, .type_system = &error_type_system, .size = sizeof(struct nlmsgerr) },
        [NFNL_MSG_BATCH_BEGIN] = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_msg_batch_type_system, .size = sizeof(struct nfgenmsg) },
        [NFNL_MSG_BATCH_END]   = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_msg_batch_type_system, .size = sizeof(struct nfgenmsg) },
        [NFNL_SUBSYS_NFTABLES] = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_msg_type_system, .size = sizeof(struct nfgenmsg) },
};

const NLTypeSystem nfnl_type_system_root = {
        .count = ELEMENTSOF(nfnl_types),
        .types = nfnl_types,
};

/* Mainly used when sending message */
const NLTypeSystem genl_family_type_system_root = {
        .count = ELEMENTSOF(genl_families),
        .types = genl_families,
};

static const NLType genl_types[] = {
        [SD_GENL_ERROR]   = { .type = NETLINK_TYPE_NESTED, .type_system = &error_type_system, .size = sizeof(struct nlmsgerr) },
        [SD_GENL_DONE]    = { .type = NETLINK_TYPE_NESTED, .type_system = &empty_type_system },
        [SD_GENL_ID_CTRL] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_get_family_type_system, .size = sizeof(struct genlmsghdr) },
        [SD_GENL_NL80211] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_nl80211_type_system, .size = sizeof(struct genlmsghdr) },
};

/* Mainly used when message received */
const NLTypeSystem genl_type_system_root = {
        .count = ELEMENTSOF(genl_types),
        .types = genl_types,
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

const NLTypeSystem *type_system_get_root(int protocol) {
        switch (protocol) {
                case NETLINK_GENERIC:
                        return &genl_type_system_root;
                case NETLINK_NETFILTER:
                        return &nfnl_type_system_root;
                default: /* NETLINK_ROUTE: */
                        return &rtnl_type_system_root;
        }
}

int type_system_root_get_type(sd_netlink *nl, const NLType **ret, uint16_t type) {
        sd_genl_family_t family;
        const NLType *nl_type;
        int r;

        if (!nl)
                return type_system_get_type(&rtnl_type_system_root, ret, type);

        if (nl->protocol != NETLINK_GENERIC)
                return type_system_get_type(type_system_get_root(nl->protocol), ret, type);

        r = nlmsg_type_to_genl_family(nl, type, &family);
        if (r < 0)
                return r;

        if (family >= genl_type_system_root.count)
                return -EOPNOTSUPP;

        nl_type = &genl_type_system_root.types[family];

        if (nl_type->type == NETLINK_TYPE_UNSPEC)
                return -EOPNOTSUPP;

        *ret = nl_type;

        return 0;
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
