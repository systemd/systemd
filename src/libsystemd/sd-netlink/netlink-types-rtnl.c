/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/batman_adv.h>
#include <linux/can/netlink.h>
#include <linux/can/vxcan.h>
#include <linux/cfm_bridge.h>
#include <linux/fib_rules.h>
#include <linux/fou.h>
#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/if_addrlabel.h>
#include <linux/if_bridge.h>
#include <linux/if_link.h>
#include <linux/if_macsec.h>
#include <linux/if_tunnel.h>
#include <linux/ip.h>
#include <linux/l2tp.h>
#include <linux/netlink.h>
#include <linux/nexthop.h>
#include <linux/nl80211.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <linux/wireguard.h>

#include "sd-netlink.h"

#include "missing_network.h"
#include "netlink-types-internal.h"
#include "string-table.h"

enum {
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
        BOND_ARP_TARGETS_15,
        _BOND_ARP_TARGETS_MAX,
};

assert_cc(_BOND_ARP_TARGETS_MAX == BOND_MAX_ARP_TARGETS);

static const NLTypeSystem rtnl_link_type_system;

static const NLType rtnl_link_info_data_bareudp_types[] = {
        [IFLA_BAREUDP_PORT]            = { .type = NETLINK_TYPE_U16 },
        [IFLA_BAREUDP_ETHERTYPE]       = { .type = NETLINK_TYPE_U16 },
        [IFLA_BAREUDP_SRCPORT_MIN]     = { .type = NETLINK_TYPE_U16 },
        [IFLA_BAREUDP_MULTIPROTO_MODE] = { .type = NETLINK_TYPE_FLAG },
};

static const NLType rtnl_link_info_data_batadv_types[] = {
        [IFLA_BATADV_ALGO_NAME] = { .type = NETLINK_TYPE_STRING, .size = 20 },
};

static const NLType rtnl_bond_arp_ip_target_types[] = {
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
        [BOND_ARP_TARGETS_15]       = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_bond_arp_ip_target);

static const NLType rtnl_bond_ad_info_types[] = {
        [IFLA_BOND_AD_INFO_AGGREGATOR]  = { .type = NETLINK_TYPE_U16 },
        [IFLA_BOND_AD_INFO_NUM_PORTS]   = { .type = NETLINK_TYPE_U16 },
        [IFLA_BOND_AD_INFO_ACTOR_KEY]   = { .type = NETLINK_TYPE_U16 },
        [IFLA_BOND_AD_INFO_PARTNER_KEY] = { .type = NETLINK_TYPE_U16 },
        [IFLA_BOND_AD_INFO_PARTNER_MAC] = { .type = NETLINK_TYPE_ETHER_ADDR, .size = ETH_ALEN },
};

DEFINE_TYPE_SYSTEM(rtnl_bond_ad_info);

static const NLType rtnl_link_info_data_bond_types[] = {
        [IFLA_BOND_MODE]                = { .type = NETLINK_TYPE_U8 },
        [IFLA_BOND_ACTIVE_SLAVE]        = { .type = NETLINK_TYPE_U32 },
        [IFLA_BOND_MIIMON]              = { .type = NETLINK_TYPE_U32 },
        [IFLA_BOND_UPDELAY]             = { .type = NETLINK_TYPE_U32 },
        [IFLA_BOND_DOWNDELAY]           = { .type = NETLINK_TYPE_U32 },
        [IFLA_BOND_USE_CARRIER]         = { .type = NETLINK_TYPE_U8 },
        [IFLA_BOND_ARP_INTERVAL]        = { .type = NETLINK_TYPE_U32 },
        [IFLA_BOND_ARP_IP_TARGET]       = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bond_arp_ip_target_type_system },
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
        [IFLA_BOND_AD_INFO]             = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bond_ad_info_type_system },
        [IFLA_BOND_AD_ACTOR_SYS_PRIO]   = { .type = NETLINK_TYPE_U16 },
        [IFLA_BOND_AD_USER_PORT_KEY]    = { .type = NETLINK_TYPE_U16 },
        [IFLA_BOND_AD_ACTOR_SYSTEM]     = { .type = NETLINK_TYPE_ETHER_ADDR, .size = ETH_ALEN },
        [IFLA_BOND_TLB_DYNAMIC_LB]      = { .type = NETLINK_TYPE_U8 },
        [IFLA_BOND_PEER_NOTIF_DELAY]    = { .type = NETLINK_TYPE_U32 },
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
        [IFLA_BR_ROOT_ID]                    = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_bridge_id) },
        [IFLA_BR_BRIDGE_ID]                  = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_bridge_id) },
        [IFLA_BR_ROOT_PORT]                  = { .type = NETLINK_TYPE_U16 },
        [IFLA_BR_ROOT_PATH_COST]             = { .type = NETLINK_TYPE_U32 },
        [IFLA_BR_TOPOLOGY_CHANGE]            = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_TOPOLOGY_CHANGE_DETECTED]   = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_HELLO_TIMER]                = { .type = NETLINK_TYPE_U64 },
        [IFLA_BR_TCN_TIMER]                  = { .type = NETLINK_TYPE_U64 },
        [IFLA_BR_TOPOLOGY_CHANGE_TIMER]      = { .type = NETLINK_TYPE_U64 },
        [IFLA_BR_GC_TIMER]                   = { .type = NETLINK_TYPE_U64 },
        [IFLA_BR_GROUP_ADDR]                 = { .type = NETLINK_TYPE_ETHER_ADDR, .size = ETH_ALEN },
        [IFLA_BR_FDB_FLUSH]                  = { .type = NETLINK_TYPE_FLAG },
        [IFLA_BR_MCAST_ROUTER]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_MCAST_SNOOPING]             = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_MCAST_QUERY_USE_IFADDR]     = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_MCAST_QUERIER]              = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_MCAST_HASH_ELASTICITY]      = { .type = NETLINK_TYPE_U32 },
        [IFLA_BR_MCAST_HASH_MAX]             = { .type = NETLINK_TYPE_U32 },
        [IFLA_BR_MCAST_LAST_MEMBER_CNT]      = { .type = NETLINK_TYPE_U32 },
        [IFLA_BR_MCAST_STARTUP_QUERY_CNT]    = { .type = NETLINK_TYPE_U32 },
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
        [IFLA_BR_VLAN_STATS_ENABLED]         = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_MCAST_STATS_ENABLED]        = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_MCAST_IGMP_VERSION]         = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_MCAST_MLD_VERSION]          = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_VLAN_STATS_PER_PORT]        = { .type = NETLINK_TYPE_U8 },
        [IFLA_BR_MULTI_BOOLOPT]              = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct br_boolopt_multi) },
};

static const NLType rtnl_link_info_data_can_types[] = {
        [IFLA_CAN_BITTIMING]            = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct can_bittiming) },
        [IFLA_CAN_BITTIMING_CONST]      = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct can_bittiming_const) },
        [IFLA_CAN_CLOCK]                = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct can_clock) },
        [IFLA_CAN_STATE]                = { .type = NETLINK_TYPE_U32 },
        [IFLA_CAN_CTRLMODE]             = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct can_ctrlmode) },
        [IFLA_CAN_RESTART_MS]           = { .type = NETLINK_TYPE_U32 },
        [IFLA_CAN_RESTART]              = { .type = NETLINK_TYPE_U32 },
        [IFLA_CAN_BERR_COUNTER]         = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct can_berr_counter) },
        [IFLA_CAN_DATA_BITTIMING]       = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct can_bittiming) },
        [IFLA_CAN_DATA_BITTIMING_CONST] = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct can_bittiming_const) },
        [IFLA_CAN_TERMINATION]          = { .type = NETLINK_TYPE_U16 },
        [IFLA_CAN_TERMINATION_CONST]    = { .type = NETLINK_TYPE_BINARY }, /* size = termination_const_cnt * sizeof(u16) */
        [IFLA_CAN_BITRATE_CONST]        = { .type = NETLINK_TYPE_BINARY }, /* size = bitrate_const_cnt * sizeof(u32) */
        [IFLA_CAN_DATA_BITRATE_CONST]   = { .type = NETLINK_TYPE_BINARY }, /* size = data_bitrate_const_cnt * sizeof(u32) */
        [IFLA_CAN_BITRATE_MAX]          = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_link_info_data_geneve_types[] = {
        [IFLA_GENEVE_ID]                = { .type = NETLINK_TYPE_U32 },
        [IFLA_GENEVE_REMOTE]            = { .type = NETLINK_TYPE_IN_ADDR, .size = sizeof(struct in_addr) },
        [IFLA_GENEVE_TTL]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_GENEVE_TOS]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_GENEVE_PORT]              = { .type = NETLINK_TYPE_U16 },
        [IFLA_GENEVE_COLLECT_METADATA]  = { .type = NETLINK_TYPE_FLAG },
        [IFLA_GENEVE_REMOTE6]           = { .type = NETLINK_TYPE_IN_ADDR, .size = sizeof(struct in6_addr) },
        [IFLA_GENEVE_UDP_CSUM]          = { .type = NETLINK_TYPE_U8 },
        [IFLA_GENEVE_UDP_ZERO_CSUM6_TX] = { .type = NETLINK_TYPE_U8 },
        [IFLA_GENEVE_UDP_ZERO_CSUM6_RX] = { .type = NETLINK_TYPE_U8 },
        [IFLA_GENEVE_LABEL]             = { .type = NETLINK_TYPE_U32 },
        [IFLA_GENEVE_TTL_INHERIT]       = { .type = NETLINK_TYPE_U8 },
        [IFLA_GENEVE_DF]                = { .type = NETLINK_TYPE_U8 },
};

static  const NLType rtnl_link_info_data_gre_types[] = {
        [IFLA_GRE_LINK]             = { .type = NETLINK_TYPE_U32 },
        [IFLA_GRE_IFLAGS]           = { .type = NETLINK_TYPE_U16 },
        [IFLA_GRE_OFLAGS]           = { .type = NETLINK_TYPE_U16 },
        [IFLA_GRE_IKEY]             = { .type = NETLINK_TYPE_U32 },
        [IFLA_GRE_OKEY]             = { .type = NETLINK_TYPE_U32 },
        [IFLA_GRE_LOCAL]            = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_GRE_REMOTE]           = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_GRE_TTL]              = { .type = NETLINK_TYPE_U8 },
        [IFLA_GRE_TOS]              = { .type = NETLINK_TYPE_U8 },
        [IFLA_GRE_PMTUDISC]         = { .type = NETLINK_TYPE_U8 },
        [IFLA_GRE_ENCAP_LIMIT]      = { .type = NETLINK_TYPE_U8 },
        [IFLA_GRE_FLOWINFO]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_GRE_FLAGS]            = { .type = NETLINK_TYPE_U32 },
        [IFLA_GRE_ENCAP_TYPE]       = { .type = NETLINK_TYPE_U16 },
        [IFLA_GRE_ENCAP_FLAGS]      = { .type = NETLINK_TYPE_U16 },
        [IFLA_GRE_ENCAP_SPORT]      = { .type = NETLINK_TYPE_U16 },
        [IFLA_GRE_ENCAP_DPORT]      = { .type = NETLINK_TYPE_U16 },
        [IFLA_GRE_COLLECT_METADATA] = { .type = NETLINK_TYPE_FLAG },
        [IFLA_GRE_IGNORE_DF]        = { .type = NETLINK_TYPE_U8 },
        [IFLA_GRE_FWMARK]           = { .type = NETLINK_TYPE_U32 },
        [IFLA_GRE_ERSPAN_INDEX]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_GRE_ERSPAN_VER]       = { .type = NETLINK_TYPE_U8 },
        [IFLA_GRE_ERSPAN_DIR]       = { .type = NETLINK_TYPE_U8 },
        [IFLA_GRE_ERSPAN_HWID]      = { .type = NETLINK_TYPE_U16 },
};

/* IFLA_IPTUN_ attributes are used in ipv4/ipip.c, ipv6/ip6_tunnel.c, and ipv6/sit.c. And unfortunately,
 * IFLA_IPTUN_FLAGS is used with different types, ugh... */
#define DEFINE_IPTUN_TYPES(name, flags_type)                                            \
        static const NLType rtnl_link_info_data_##name##_types[] = {                    \
                [IFLA_IPTUN_LINK]                = { .type = NETLINK_TYPE_U32 },        \
                [IFLA_IPTUN_LOCAL]               = { .type = NETLINK_TYPE_IN_ADDR },    \
                [IFLA_IPTUN_REMOTE]              = { .type = NETLINK_TYPE_IN_ADDR },    \
                [IFLA_IPTUN_TTL]                 = { .type = NETLINK_TYPE_U8 },         \
                [IFLA_IPTUN_TOS]                 = { .type = NETLINK_TYPE_U8 },         \
                [IFLA_IPTUN_ENCAP_LIMIT]         = { .type = NETLINK_TYPE_U8 },         \
                [IFLA_IPTUN_FLOWINFO]            = { .type = NETLINK_TYPE_U32 },        \
                [IFLA_IPTUN_FLAGS]               = { .type = flags_type },              \
                [IFLA_IPTUN_PROTO]               = { .type = NETLINK_TYPE_U8 },         \
                [IFLA_IPTUN_PMTUDISC]            = { .type = NETLINK_TYPE_U8 },         \
                [IFLA_IPTUN_6RD_PREFIX]          = { .type = NETLINK_TYPE_IN_ADDR,      \
                                                     .size = sizeof(struct in6_addr) }, \
                [IFLA_IPTUN_6RD_RELAY_PREFIX]    = { .type = NETLINK_TYPE_U32 },        \
                [IFLA_IPTUN_6RD_PREFIXLEN]       = { .type = NETLINK_TYPE_U16 },        \
                [IFLA_IPTUN_6RD_RELAY_PREFIXLEN] = { .type = NETLINK_TYPE_U16 },        \
                [IFLA_IPTUN_ENCAP_TYPE]          = { .type = NETLINK_TYPE_U16 },        \
                [IFLA_IPTUN_ENCAP_FLAGS]         = { .type = NETLINK_TYPE_U16 },        \
                [IFLA_IPTUN_ENCAP_SPORT]         = { .type = NETLINK_TYPE_U16 },        \
                [IFLA_IPTUN_ENCAP_DPORT]         = { .type = NETLINK_TYPE_U16 },        \
                [IFLA_IPTUN_COLLECT_METADATA]    = { .type = NETLINK_TYPE_FLAG },       \
                [IFLA_IPTUN_FWMARK]              = { .type = NETLINK_TYPE_U32 },        \
        }

DEFINE_IPTUN_TYPES(iptun, NETLINK_TYPE_U32); /* for ipip and ip6tnl */
DEFINE_IPTUN_TYPES(sit, NETLINK_TYPE_U16); /* for sit */

static const NLType rtnl_link_info_data_ipvlan_types[] = {
        [IFLA_IPVLAN_MODE]  = { .type = NETLINK_TYPE_U16 },
        [IFLA_IPVLAN_FLAGS] = { .type = NETLINK_TYPE_U16 },
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
        [IFLA_MACSEC_OFFLOAD]        = { .type = NETLINK_TYPE_U8 },
};

static const NLType rtnl_macvlan_macaddr_types[] = {
        [IFLA_MACVLAN_MACADDR] = { .type = NETLINK_TYPE_ETHER_ADDR, .size = ETH_ALEN },
};

DEFINE_TYPE_SYSTEM(rtnl_macvlan_macaddr);

static const NLType rtnl_link_info_data_macvlan_types[] = {
        [IFLA_MACVLAN_MODE]              = { .type = NETLINK_TYPE_U32 },
        [IFLA_MACVLAN_FLAGS]             = { .type = NETLINK_TYPE_U16 },
        [IFLA_MACVLAN_MACADDR_MODE]      = { .type = NETLINK_TYPE_U32 },
        [IFLA_MACVLAN_MACADDR_DATA]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_macvlan_macaddr_type_system },
        [IFLA_MACVLAN_MACADDR_COUNT]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_MACVLAN_BC_QUEUE_LEN]      = { .type = NETLINK_TYPE_U32 },
        [IFLA_MACVLAN_BC_QUEUE_LEN_USED] = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_link_info_data_tun_types[] = {
        [IFLA_TUN_OWNER]               = { .type = NETLINK_TYPE_U32 },
        [IFLA_TUN_GROUP]               = { .type = NETLINK_TYPE_U32 },
        [IFLA_TUN_TYPE]                = { .type = NETLINK_TYPE_U8 },
        [IFLA_TUN_PI]                  = { .type = NETLINK_TYPE_U8 },
        [IFLA_TUN_VNET_HDR]            = { .type = NETLINK_TYPE_U8 },
        [IFLA_TUN_PERSIST]             = { .type = NETLINK_TYPE_U8 },
        [IFLA_TUN_MULTI_QUEUE]         = { .type = NETLINK_TYPE_U8 },
        [IFLA_TUN_NUM_QUEUES]          = { .type = NETLINK_TYPE_U32 },
        [IFLA_TUN_NUM_DISABLED_QUEUES] = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_link_info_data_veth_types[] = {
        [VETH_INFO_PEER]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
};

static const NLType rtnl_vlan_qos_map_types[] = {
        [IFLA_VLAN_QOS_MAPPING]        = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_vlan_qos_mapping) },
};

DEFINE_TYPE_SYSTEM(rtnl_vlan_qos_map);

static const NLType rtnl_link_info_data_vlan_types[] = {
        [IFLA_VLAN_ID]          = { .type = NETLINK_TYPE_U16 },
        [IFLA_VLAN_FLAGS]       = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_vlan_flags) },
        [IFLA_VLAN_EGRESS_QOS]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_vlan_qos_map_type_system },
        [IFLA_VLAN_INGRESS_QOS] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_vlan_qos_map_type_system },
        [IFLA_VLAN_PROTOCOL]    = { .type = NETLINK_TYPE_U16 },
};

static const NLType rtnl_link_info_data_vrf_types[] = {
        [IFLA_VRF_TABLE]                 = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_link_info_data_vti_types[] = {
        [IFLA_VTI_LINK]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_VTI_IKEY]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_VTI_OKEY]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_VTI_LOCAL]        = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_VTI_REMOTE]       = { .type = NETLINK_TYPE_IN_ADDR },
        [IFLA_VTI_FWMARK]       = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_link_info_data_vxcan_types[] = {
        [VXCAN_INFO_PEER]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
};

static const NLType rtnl_link_info_data_vxlan_types[] = {
        [IFLA_VXLAN_ID]                = { .type = NETLINK_TYPE_U32 },
        [IFLA_VXLAN_GROUP]             = { .type = NETLINK_TYPE_IN_ADDR, .size = sizeof(struct in_addr) },
        [IFLA_VXLAN_LINK]              = { .type = NETLINK_TYPE_U32 },
        [IFLA_VXLAN_LOCAL]             = { .type = NETLINK_TYPE_IN_ADDR, .size = sizeof(struct in_addr) },
        [IFLA_VXLAN_TTL]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_TOS]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_LEARNING]          = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_AGEING]            = { .type = NETLINK_TYPE_U32 },
        [IFLA_VXLAN_LIMIT]             = { .type = NETLINK_TYPE_U32 },
        [IFLA_VXLAN_PORT_RANGE]        = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_vxlan_port_range) },
        [IFLA_VXLAN_PROXY]             = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_RSC]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_L2MISS]            = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_L3MISS]            = { .type = NETLINK_TYPE_U8 },
        [IFLA_VXLAN_PORT]              = { .type = NETLINK_TYPE_U16 },
        [IFLA_VXLAN_GROUP6]            = { .type = NETLINK_TYPE_IN_ADDR, .size = sizeof(struct in6_addr) },
        [IFLA_VXLAN_LOCAL6]            = { .type = NETLINK_TYPE_IN_ADDR, .size = sizeof(struct in6_addr) },
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

static const NLType rtnl_link_info_data_xfrm_types[] = {
        [IFLA_XFRM_LINK]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_XFRM_IF_ID]        = { .type = NETLINK_TYPE_U32 }
};

static const NLTypeSystemUnionElement rtnl_link_info_data_type_systems[] = {
        { .name = "bareudp",   .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_bareudp), },
        { .name = "batadv",    .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_batadv),  },
        { .name = "bond",      .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_bond),    },
        { .name = "bridge",    .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_bridge),  },
/*
        { .name = "caif",      .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_caif),    },
*/
        { .name = "can",       .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_can),     },
        { .name = "erspan",    .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_gre),     },
        { .name = "geneve",    .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_geneve),  },
        { .name = "gre",       .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_gre),     },
        { .name = "gretap",    .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_gre),     },
/*
        { .name = "gtp",       .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_gtp),     },
        { .name = "hsr",       .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_hsr),     },
*/
        { .name = "ip6erspan", .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_gre),     },
        { .name = "ip6gre",    .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_gre),     },
        { .name = "ip6gretap", .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_gre),     },
        { .name = "ip6tnl",    .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_iptun),   },
/*
        { .name = "ipoib",     .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_ipoib),   },
*/
        { .name = "ipip",      .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_iptun),   },
        { .name = "ipvlan",    .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_ipvlan),  },
        { .name = "ipvtap",    .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_ipvlan),  },
        { .name = "macsec",    .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_macsec),  },
        { .name = "macvlan",   .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_macvlan), },
        { .name = "macvtap",   .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_macvlan), },
/*
        { .name = "ppp",       .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_ppp),     },
        { .name = "rmnet",     .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_rmnet),   },
*/
        { .name = "sit",       .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_sit),     },
        { .name = "tun",       .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_tun),     },
        { .name = "veth",      .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_veth),    },
        { .name = "vlan",      .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_vlan),    },
        { .name = "vrf",       .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_vrf),     },
        { .name = "vti",       .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_vti),     },
        { .name = "vti6",      .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_vti),     },
        { .name = "vxcan",     .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_vxcan),   },
        { .name = "vxlan",     .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_vxlan),   },
/*
        { .name = "wwan",      .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_wwan),    },
*/
        { .name = "xfrm",      .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_link_info_data_xfrm),    },
};

DEFINE_TYPE_SYSTEM_UNION_MATCH_SIBLING(rtnl_link_info_data, IFLA_INFO_KIND);

static const struct NLType rtnl_bridge_port_types[] = {
        [IFLA_BRPORT_STATE]                 = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_COST]                  = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRPORT_PRIORITY]              = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRPORT_MODE]                  = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_GUARD]                 = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_PROTECT]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_FAST_LEAVE]            = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_LEARNING]              = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_UNICAST_FLOOD]         = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_PROXYARP]              = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_LEARNING_SYNC]         = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_PROXYARP_WIFI]         = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_ROOT_ID]               = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_BRIDGE_ID]             = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_DESIGNATED_PORT]       = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRPORT_DESIGNATED_COST]       = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRPORT_ID]                    = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRPORT_NO]                    = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRPORT_TOPOLOGY_CHANGE_ACK]   = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_CONFIG_PENDING]        = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_MESSAGE_AGE_TIMER]     = { .type = NETLINK_TYPE_U64 },
        [IFLA_BRPORT_FORWARD_DELAY_TIMER]   = { .type = NETLINK_TYPE_U64 },
        [IFLA_BRPORT_HOLD_TIMER]            = { .type = NETLINK_TYPE_U64 },
        [IFLA_BRPORT_FLUSH]                 = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_MULTICAST_ROUTER]      = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_PAD]                   = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_MCAST_FLOOD]           = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_MCAST_TO_UCAST]        = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_VLAN_TUNNEL]           = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_BCAST_FLOOD]           = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_GROUP_FWD_MASK]        = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRPORT_NEIGH_SUPPRESS]        = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_ISOLATED]              = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_BACKUP_PORT]           = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRPORT_MRP_RING_OPEN]         = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_MRP_IN_OPEN]           = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT] = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRPORT_MCAST_EHT_HOSTS_CNT]   = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystemUnionElement rtnl_link_info_slave_data_type_systems[] = {
        { .name = "bridge",    .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_bridge_port), },
};

DEFINE_TYPE_SYSTEM_UNION_MATCH_SIBLING(rtnl_link_info_slave_data, IFLA_INFO_SLAVE_KIND);

static const NLType rtnl_link_info_types[] = {
        [IFLA_INFO_KIND]        = { .type = NETLINK_TYPE_STRING },
        [IFLA_INFO_DATA]        = { .type = NETLINK_TYPE_UNION, .type_system_union = &rtnl_link_info_data_type_system_union },
        /* TODO: Currently IFLA_INFO_XSTATS is used only when IFLA_INFO_KIND is "can". In the future,
         * when multiple kinds of netdevs use this attribute, then convert its type to NETLINK_TYPE_UNION. */
        [IFLA_INFO_XSTATS]      = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct can_device_stats) },
        [IFLA_INFO_SLAVE_KIND]  = { .type = NETLINK_TYPE_STRING },
        [IFLA_INFO_SLAVE_DATA]  = { .type = NETLINK_TYPE_NESTED, .type_system_union = &rtnl_link_info_slave_data_type_system_union },
};

DEFINE_TYPE_SYSTEM(rtnl_link_info);

static const struct NLType rtnl_inet_types[] = {
        [IFLA_INET_CONF] = { .type = NETLINK_TYPE_BINARY }, /* size = IPV4_DEVCONF_MAX * 4 */
};

DEFINE_TYPE_SYSTEM(rtnl_inet);

static const struct NLType rtnl_inet6_types[] = {
        [IFLA_INET6_FLAGS]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_INET6_CONF]          = { .type = NETLINK_TYPE_BINARY }, /* size = DEVCONF_MAX * sizeof(s32) */
        [IFLA_INET6_STATS]         = { .type = NETLINK_TYPE_BINARY }, /* size = IPSTATS_MIB_MAX * sizeof(u64) */
        [IFLA_INET6_MCAST]         = {}, /* unused. */
        [IFLA_INET6_CACHEINFO]     = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_cacheinfo) },
        [IFLA_INET6_ICMP6STATS]    = { .type = NETLINK_TYPE_BINARY }, /* size = ICMP6_MIB_MAX * sizeof(u64) */
        [IFLA_INET6_TOKEN]         = { .type = NETLINK_TYPE_IN_ADDR, .size = sizeof(struct in6_addr) },
        [IFLA_INET6_ADDR_GEN_MODE] = { .type = NETLINK_TYPE_U8 },
};

DEFINE_TYPE_SYSTEM(rtnl_inet6);

static const NLTypeSystemUnionElement rtnl_prot_info_type_systems[] = {
        { .protocol = AF_BRIDGE, .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_bridge_port), },
        { .protocol = AF_INET6,  .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_inet6), },
};

DEFINE_TYPE_SYSTEM_UNION_MATCH_PROTOCOL(rtnl_prot_info);

static const NLType rtnl_af_spec_unspec_types[] = {
        [AF_INET]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_inet_type_system },
        [AF_INET6] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_inet6_type_system },
};

static const NLType rtnl_bridge_vlan_tunnel_info_types[] = {
        [IFLA_BRIDGE_VLAN_TUNNEL_ID]    = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_VLAN_TUNNEL_VID]   = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRIDGE_VLAN_TUNNEL_FLAGS] = { .type = NETLINK_TYPE_U16 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_vlan_tunnel_info);

static const NLType rtnl_bridge_mrp_instance_types[] = {
        [IFLA_BRIDGE_MRP_INSTANCE_RING_ID]      = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_INSTANCE_P_IFINDEX]    = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_INSTANCE_S_IFINDEX]    = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_INSTANCE_PRIO]         = { .type = NETLINK_TYPE_U16 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_mrp_instance);

static const NLType rtnl_bridge_mrp_port_state_types[] = {
        [IFLA_BRIDGE_MRP_PORT_STATE_STATE]      = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_mrp_port_state);

static const NLType rtnl_bridge_mrp_port_role_types[] = {
        [IFLA_BRIDGE_MRP_PORT_ROLE_ROLE]        = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_mrp_port_role);

static const NLType rtnl_bridge_mrp_ring_state_types[] = {
        [IFLA_BRIDGE_MRP_RING_STATE_RING_ID]    = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_RING_STATE_STATE]      = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_mrp_ring_state);

static const NLType rtnl_bridge_mrp_ring_role_types[] = {
        [IFLA_BRIDGE_MRP_RING_ROLE_RING_ID]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_RING_ROLE_ROLE]        = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_mrp_ring_role);

static const NLType rtnl_bridge_mrp_start_test_types[] = {
        [IFLA_BRIDGE_MRP_START_TEST_RING_ID]    = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_START_TEST_INTERVAL]   = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_START_TEST_MAX_MISS]   = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_START_TEST_PERIOD]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_START_TEST_MONITOR]    = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_mrp_start_test);

static const NLType rtnl_bridge_mrp_info_types[] = {
        [IFLA_BRIDGE_MRP_INFO_RING_ID]          = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_INFO_P_IFINDEX]        = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_INFO_S_IFINDEX]        = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_INFO_PRIO]             = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRIDGE_MRP_INFO_RING_STATE]       = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_INFO_RING_ROLE]        = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_INFO_TEST_INTERVAL]    = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_INFO_TEST_MAX_MISS]    = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_INFO_TEST_MONITOR]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_INFO_I_IFINDEX]        = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_INFO_IN_STATE]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_INFO_IN_ROLE]          = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_INFO_IN_TEST_INTERVAL] = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_INFO_IN_TEST_MAX_MISS] = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_mrp_info);

static const NLType rtnl_bridge_mrp_in_role_types[] = {
        [IFLA_BRIDGE_MRP_IN_ROLE_RING_ID]       = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_IN_ROLE_IN_ID]         = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRIDGE_MRP_IN_ROLE_ROLE]          = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_IN_ROLE_I_IFINDEX]     = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_mrp_in_role);

static const NLType rtnl_bridge_mrp_in_state_types[] = {
        [IFLA_BRIDGE_MRP_IN_STATE_IN_ID]        = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_IN_STATE_STATE]        = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_mrp_in_state);

static const NLType rtnl_bridge_mrp_start_in_test_types[] = {
        [IFLA_BRIDGE_MRP_START_IN_TEST_IN_ID]    = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_START_IN_TEST_INTERVAL] = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_START_IN_TEST_MAX_MISS] = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_MRP_START_IN_TEST_PERIOD]   = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_mrp_start_in_test);

static const NLType rtnl_bridge_mrp_types[] = {
        [IFLA_BRIDGE_MRP_INSTANCE]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_mrp_instance_type_system },
        [IFLA_BRIDGE_MRP_PORT_STATE]    = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_mrp_port_state_type_system },
        [IFLA_BRIDGE_MRP_PORT_ROLE]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_mrp_port_role_type_system },
        [IFLA_BRIDGE_MRP_RING_STATE]    = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_mrp_ring_state_type_system },
        [IFLA_BRIDGE_MRP_RING_ROLE]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_mrp_ring_role_type_system },
        [IFLA_BRIDGE_MRP_START_TEST]    = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_mrp_start_test_type_system },
        [IFLA_BRIDGE_MRP_INFO]          = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_mrp_info_type_system },
        [IFLA_BRIDGE_MRP_IN_ROLE]       = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_mrp_in_role_type_system },
        [IFLA_BRIDGE_MRP_IN_STATE]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_mrp_in_state_type_system },
        [IFLA_BRIDGE_MRP_START_IN_TEST] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_mrp_start_in_test_type_system },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_mrp);

static const NLType rtnl_bridge_cfm_mep_create_types[] = {
        [IFLA_BRIDGE_CFM_MEP_CREATE_INSTANCE]   = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_MEP_CREATE_DOMAIN]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_MEP_CREATE_DIRECTION]  = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_MEP_CREATE_IFINDEX]    = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_cfm_mep_create);

static const NLType rtnl_bridge_cfm_mep_delete_types[] = {
        [IFLA_BRIDGE_CFM_MEP_DELETE_INSTANCE]   = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_cfm_mep_delete);

static const NLType rtnl_bridge_cfm_mep_config_types[] = {
        [IFLA_BRIDGE_CFM_MEP_CONFIG_INSTANCE]    = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_MEP_CONFIG_UNICAST_MAC] = { .type = NETLINK_TYPE_ETHER_ADDR },
        [IFLA_BRIDGE_CFM_MEP_CONFIG_MDLEVEL]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_MEP_CONFIG_MEPID]       = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_cfm_mep_config);

static const NLType rtnl_bridge_cfm_cc_config_types[] = {
        [IFLA_BRIDGE_CFM_CC_CONFIG_INSTANCE]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_CC_CONFIG_ENABLE]       = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_CC_CONFIG_EXP_INTERVAL] = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_CC_CONFIG_EXP_MAID]     = { .type = NETLINK_TYPE_BINARY, .size = CFM_MAID_LENGTH },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_cfm_cc_config);

static const NLType rtnl_bridge_cfm_cc_peer_mep_types[] = {
        [IFLA_BRIDGE_CFM_CC_PEER_MEP_INSTANCE]  = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_CC_PEER_MEPID]         = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_cfm_cc_peer_mep);

static const NLType rtnl_bridge_cfm_cc_rdi_types[] = {
        [IFLA_BRIDGE_CFM_CC_RDI_INSTANCE]       = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_CC_RDI_RDI]            = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_cfm_cc_rdi);

static const NLType rtnl_bridge_cfm_cc_ccm_tx_types[] = {
        [IFLA_BRIDGE_CFM_CC_CCM_TX_INSTANCE]       = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_CC_CCM_TX_DMAC]           = { .type = NETLINK_TYPE_ETHER_ADDR },
        [IFLA_BRIDGE_CFM_CC_CCM_TX_SEQ_NO_UPDATE]  = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_CC_CCM_TX_PERIOD]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_CC_CCM_TX_IF_TLV]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_CC_CCM_TX_IF_TLV_VALUE]   = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRIDGE_CFM_CC_CCM_TX_PORT_TLV]       = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_CC_CCM_TX_PORT_TLV_VALUE] = { .type = NETLINK_TYPE_U8 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_cfm_cc_ccm_tx);

static const NLType rtnl_bridge_cfm_mep_status_types[] = {
        [IFLA_BRIDGE_CFM_MEP_STATUS_INSTANCE]           = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_MEP_STATUS_OPCODE_UNEXP_SEEN]  = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_MEP_STATUS_VERSION_UNEXP_SEEN] = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_MEP_STATUS_RX_LEVEL_LOW_SEEN]  = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_cfm_mep_status);

static const NLType rtnl_bridge_cfm_cc_peer_status_types[] = {
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_INSTANCE]       = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_PEER_MEPID]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_CCM_DEFECT]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_RDI]            = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_PORT_TLV_VALUE] = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_IF_TLV_VALUE]   = { .type = NETLINK_TYPE_U8 },
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_SEEN]           = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_TLV_SEEN]       = { .type = NETLINK_TYPE_U32 },
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_SEQ_UNEXP_SEEN] = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_cfm_cc_peer_status);

static const NLType rtnl_bridge_cfm_types[] = {
        [IFLA_BRIDGE_CFM_MEP_CREATE]          = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_cfm_mep_create_type_system },
        [IFLA_BRIDGE_CFM_MEP_DELETE]          = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_cfm_mep_delete_type_system },
        [IFLA_BRIDGE_CFM_MEP_CONFIG]          = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_cfm_mep_config_type_system },
        [IFLA_BRIDGE_CFM_CC_CONFIG]           = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_cfm_cc_config_type_system },
        [IFLA_BRIDGE_CFM_CC_PEER_MEP_ADD]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_cfm_cc_peer_mep_type_system },
        [IFLA_BRIDGE_CFM_CC_PEER_MEP_REMOVE]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_cfm_cc_peer_mep_type_system },
        [IFLA_BRIDGE_CFM_CC_RDI]              = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_cfm_cc_rdi_type_system },
        [IFLA_BRIDGE_CFM_CC_CCM_TX]           = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_cfm_cc_ccm_tx_type_system },
        [IFLA_BRIDGE_CFM_MEP_CREATE_INFO]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_cfm_mep_create_type_system },
        [IFLA_BRIDGE_CFM_MEP_CONFIG_INFO]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_cfm_mep_config_type_system },
        [IFLA_BRIDGE_CFM_CC_CONFIG_INFO]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_cfm_cc_config_type_system },
        [IFLA_BRIDGE_CFM_CC_RDI_INFO]         = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_cfm_cc_rdi_type_system },
        [IFLA_BRIDGE_CFM_CC_CCM_TX_INFO]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_cfm_cc_ccm_tx_type_system },
        [IFLA_BRIDGE_CFM_CC_PEER_MEP_INFO]    = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_cfm_cc_peer_mep_type_system },
        [IFLA_BRIDGE_CFM_MEP_STATUS_INFO]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_cfm_mep_status_type_system },
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_INFO] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_cfm_cc_peer_status_type_system },
};

DEFINE_TYPE_SYSTEM(rtnl_bridge_cfm);

static const NLType rtnl_af_spec_bridge_types[] = {
        [IFLA_BRIDGE_FLAGS]            = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRIDGE_MODE]             = { .type = NETLINK_TYPE_U16 },
        [IFLA_BRIDGE_VLAN_INFO]        = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct bridge_vlan_info) },
        [IFLA_BRIDGE_VLAN_TUNNEL_INFO] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_vlan_tunnel_info_type_system },
        [IFLA_BRIDGE_MRP]              = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_mrp_type_system },
        [IFLA_BRIDGE_CFM]              = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_bridge_cfm_type_system },
};

static const NLTypeSystemUnionElement rtnl_af_spec_type_systems[] = {
        { .protocol = AF_UNSPEC, .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_af_spec_unspec), },
        { .protocol = AF_BRIDGE, .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_af_spec_bridge), },
};

DEFINE_TYPE_SYSTEM_UNION_MATCH_PROTOCOL(rtnl_af_spec);

static const NLType rtnl_prop_list_types[] = {
        [IFLA_ALT_IFNAME]       = { .type = NETLINK_TYPE_STRING, .size = ALTIFNAMSIZ - 1 },
};

DEFINE_TYPE_SYSTEM(rtnl_prop_list);

static const NLType rtnl_vf_vlan_list_types[] = {
        [IFLA_VF_VLAN_INFO]  = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_vf_vlan_info) },
};

DEFINE_TYPE_SYSTEM(rtnl_vf_vlan_list);

static const NLType rtnl_vf_info_types[] = {
        [IFLA_VF_MAC]           = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_vf_mac) },
        [IFLA_VF_VLAN]          = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_vf_vlan) },
        [IFLA_VF_VLAN_LIST]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_vf_vlan_list_type_system },
        [IFLA_VF_TX_RATE]       = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_vf_tx_rate) },
        [IFLA_VF_SPOOFCHK]      = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_vf_spoofchk) },
        [IFLA_VF_RATE]          = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_vf_rate) },
        [IFLA_VF_LINK_STATE]    = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_vf_link_state) },
        [IFLA_VF_RSS_QUERY_EN]  = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_vf_rss_query_en) },
        [IFLA_VF_TRUST]         = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_vf_trust) },
        [IFLA_VF_IB_NODE_GUID]  = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_vf_guid) },
        [IFLA_VF_IB_PORT_GUID]  = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_vf_guid) },
};

DEFINE_TYPE_SYSTEM(rtnl_vf_info);

static const NLType rtnl_vfinfo_list_types[] = {
        [IFLA_VF_INFO] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_vf_info_type_system },
};

DEFINE_TYPE_SYSTEM(rtnl_vfinfo_list);

static const NLType rtnl_vf_port_types[] = {
        [IFLA_PORT_VF]            = { .type = NETLINK_TYPE_U32 },
        [IFLA_PORT_PROFILE]       = { .type = NETLINK_TYPE_STRING },
        [IFLA_PORT_VSI_TYPE]      = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct ifla_port_vsi) },
        [IFLA_PORT_INSTANCE_UUID] = { .type = NETLINK_TYPE_BINARY, .size = PORT_UUID_MAX },
        [IFLA_PORT_HOST_UUID]     = { .type = NETLINK_TYPE_BINARY, .size = PORT_UUID_MAX },
        [IFLA_PORT_REQUEST]       = { .type = NETLINK_TYPE_U8 },
        [IFLA_PORT_RESPONSE]      = { .type = NETLINK_TYPE_U16 },
};

DEFINE_TYPE_SYSTEM(rtnl_vf_port);

static const NLType rtnl_vf_ports_types[] = {
        [IFLA_VF_PORT] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_vf_port_type_system },
};

DEFINE_TYPE_SYSTEM(rtnl_vf_ports);

static const NLType rtnl_xdp_types[] = {
        [IFLA_XDP_FD]          = { .type = NETLINK_TYPE_S32 },
        [IFLA_XDP_ATTACHED]    = { .type = NETLINK_TYPE_U8 },
        [IFLA_XDP_FLAGS]       = { .type = NETLINK_TYPE_U32 },
        [IFLA_XDP_PROG_ID]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_XDP_DRV_PROG_ID] = { .type = NETLINK_TYPE_U32 },
        [IFLA_XDP_SKB_PROG_ID] = { .type = NETLINK_TYPE_U32 },
        [IFLA_XDP_HW_PROG_ID]  = { .type = NETLINK_TYPE_U32 },
        [IFLA_XDP_EXPECTED_FD] = { .type = NETLINK_TYPE_S32 },
};

DEFINE_TYPE_SYSTEM(rtnl_xdp);

static const NLType rtnl_proto_down_reason_types[] = {
        [IFLA_PROTO_DOWN_REASON_MASK]  = { .type = NETLINK_TYPE_U32 },
        [IFLA_PROTO_DOWN_REASON_VALUE] = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_proto_down_reason);

static const NLType rtnl_link_types[] = {
        [IFLA_ADDRESS]             = { .type = NETLINK_TYPE_ETHER_ADDR },
        [IFLA_BROADCAST]           = { .type = NETLINK_TYPE_ETHER_ADDR },
        [IFLA_IFNAME]              = { .type = NETLINK_TYPE_STRING, .size = IFNAMSIZ - 1 },
        [IFLA_MTU]                 = { .type = NETLINK_TYPE_U32 },
        [IFLA_LINK]                = { .type = NETLINK_TYPE_U32 },
        [IFLA_QDISC]               = { .type = NETLINK_TYPE_STRING },
        [IFLA_STATS]               = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct rtnl_link_stats) },
        [IFLA_COST]                = { /* Not used. */ },
        [IFLA_PRIORITY]            = { /* Not used. */ },
        [IFLA_MASTER]              = { .type = NETLINK_TYPE_U32 },
        [IFLA_WIRELESS]            = { /* Used only by wext. */ },
        [IFLA_PROTINFO]            = { .type = NETLINK_TYPE_UNION, .type_system_union = &rtnl_prot_info_type_system_union },
        [IFLA_TXQLEN]              = { .type = NETLINK_TYPE_U32 },
        [IFLA_MAP]                 = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct rtnl_link_ifmap) },
        [IFLA_WEIGHT]              = { .type = NETLINK_TYPE_U32 },
        [IFLA_OPERSTATE]           = { .type = NETLINK_TYPE_U8 },
        [IFLA_LINKMODE]            = { .type = NETLINK_TYPE_U8 },
        [IFLA_LINKINFO]            = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_info_type_system },
        [IFLA_NET_NS_PID]          = { .type = NETLINK_TYPE_U32 },
        [IFLA_IFALIAS]             = { .type = NETLINK_TYPE_STRING, .size = IFALIASZ - 1 },
        [IFLA_NUM_VF]              = { .type = NETLINK_TYPE_U32 },
        [IFLA_VFINFO_LIST]         = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_vfinfo_list_type_system },
        [IFLA_STATS64]             = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct rtnl_link_stats64) },
        [IFLA_VF_PORTS]            = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_vf_ports_type_system },
        [IFLA_PORT_SELF]           = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_vf_port_type_system },
        [IFLA_AF_SPEC]             = { .type = NETLINK_TYPE_UNION, .type_system_union = &rtnl_af_spec_type_system_union },
        [IFLA_GROUP]               = { .type = NETLINK_TYPE_U32 },
        [IFLA_NET_NS_FD]           = { .type = NETLINK_TYPE_U32 },
        [IFLA_EXT_MASK]            = { .type = NETLINK_TYPE_U32 },
        [IFLA_PROMISCUITY]         = { .type = NETLINK_TYPE_U32 },
        [IFLA_NUM_TX_QUEUES]       = { .type = NETLINK_TYPE_U32 },
        [IFLA_NUM_RX_QUEUES]       = { .type = NETLINK_TYPE_U32 },
        [IFLA_CARRIER]             = { .type = NETLINK_TYPE_U8 },
        [IFLA_PHYS_PORT_ID]        = { .type = NETLINK_TYPE_BINARY, .size = MAX_PHYS_ITEM_ID_LEN },
        [IFLA_CARRIER_CHANGES]     = { .type = NETLINK_TYPE_U32 },
        [IFLA_PHYS_SWITCH_ID]      = { .type = NETLINK_TYPE_BINARY, .size = MAX_PHYS_ITEM_ID_LEN },
        [IFLA_LINK_NETNSID]        = { .type = NETLINK_TYPE_S32 },
        [IFLA_PHYS_PORT_NAME]      = { .type = NETLINK_TYPE_STRING, .size = IFNAMSIZ - 1 },
        [IFLA_PROTO_DOWN]          = { .type = NETLINK_TYPE_U8 },
        [IFLA_GSO_MAX_SEGS]        = { .type = NETLINK_TYPE_U32 },
        [IFLA_GSO_MAX_SIZE]        = { .type = NETLINK_TYPE_U32 },
        [IFLA_XDP]                 = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_xdp_type_system },
        [IFLA_EVENT]               = { .type = NETLINK_TYPE_U32 },
        [IFLA_NEW_NETNSID]         = { .type = NETLINK_TYPE_S32 },
        [IFLA_TARGET_NETNSID]      = { .type = NETLINK_TYPE_S32 },
        [IFLA_CARRIER_UP_COUNT]    = { .type = NETLINK_TYPE_U32 },
        [IFLA_CARRIER_DOWN_COUNT]  = { .type = NETLINK_TYPE_U32 },
        [IFLA_NEW_IFINDEX]         = { .type = NETLINK_TYPE_S32 },
        [IFLA_MIN_MTU]             = { .type = NETLINK_TYPE_U32 },
        [IFLA_MAX_MTU]             = { .type = NETLINK_TYPE_U32 },
        [IFLA_PROP_LIST]           = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_prop_list_type_system },
        [IFLA_ALT_IFNAME]          = { .type = NETLINK_TYPE_STRING, .size = ALTIFNAMSIZ - 1 },
        [IFLA_PERM_ADDRESS]        = { .type = NETLINK_TYPE_ETHER_ADDR },
        [IFLA_PROTO_DOWN_REASON]   = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_proto_down_reason_type_system },
        [IFLA_PARENT_DEV_NAME]     = { .type = NETLINK_TYPE_STRING, },
        [IFLA_PARENT_DEV_BUS_NAME] = { .type = NETLINK_TYPE_STRING, },
};

DEFINE_TYPE_SYSTEM(rtnl_link);

/* IFA_FLAGS was defined in kernel 3.14, but we still support older
 * kernels where IFA_MAX is lower. */
static const NLType rtnl_address_types[] = {
        [IFA_ADDRESS]           = { .type = NETLINK_TYPE_IN_ADDR },
        [IFA_LOCAL]             = { .type = NETLINK_TYPE_IN_ADDR },
        [IFA_LABEL]             = { .type = NETLINK_TYPE_STRING, .size = IFNAMSIZ - 1 },
        [IFA_BROADCAST]         = { .type = NETLINK_TYPE_IN_ADDR },
        [IFA_ANYCAST]           = { .type = NETLINK_TYPE_IN_ADDR },
        [IFA_CACHEINFO]         = { .type = NETLINK_TYPE_CACHE_INFO, .size = sizeof(struct ifa_cacheinfo) },
        [IFA_MULTICAST]         = { .type = NETLINK_TYPE_IN_ADDR },
        [IFA_FLAGS]             = { .type = NETLINK_TYPE_U32 },
        [IFA_RT_PRIORITY]       = { .type = NETLINK_TYPE_U32 },
        [IFA_TARGET_NETNSID]    = { .type = NETLINK_TYPE_S32 },
};

DEFINE_TYPE_SYSTEM(rtnl_address);

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

DEFINE_TYPE_SYSTEM(rtnl_route_metrics);

static const NLType rtnl_route_types[] = {
        [RTA_DST]               = { .type = NETLINK_TYPE_IN_ADDR }, /* 6? */
        [RTA_SRC]               = { .type = NETLINK_TYPE_IN_ADDR }, /* 6? */
        [RTA_IIF]               = { .type = NETLINK_TYPE_U32 },
        [RTA_OIF]               = { .type = NETLINK_TYPE_U32 },
        [RTA_GATEWAY]           = { .type = NETLINK_TYPE_IN_ADDR },
        [RTA_PRIORITY]          = { .type = NETLINK_TYPE_U32 },
        [RTA_PREFSRC]           = { .type = NETLINK_TYPE_IN_ADDR }, /* 6? */
        [RTA_METRICS]           = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_route_metrics_type_system },
        [RTA_MULTIPATH]         = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct rtnexthop) },
        [RTA_FLOW]              = { .type = NETLINK_TYPE_U32 }, /* 6? */
        [RTA_CACHEINFO]         = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct rta_cacheinfo) },
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

DEFINE_TYPE_SYSTEM(rtnl_route);

static const NLType rtnl_neigh_types[] = {
        [NDA_DST]               = { .type = NETLINK_TYPE_IN_ADDR },
        [NDA_LLADDR]            = { .type = NETLINK_TYPE_ETHER_ADDR },
        [NDA_CACHEINFO]         = { .type = NETLINK_TYPE_CACHE_INFO, .size = sizeof(struct nda_cacheinfo) },
        [NDA_PROBES]            = { .type = NETLINK_TYPE_U32 },
        [NDA_VLAN]              = { .type = NETLINK_TYPE_U16 },
        [NDA_PORT]              = { .type = NETLINK_TYPE_U16 },
        [NDA_VNI]               = { .type = NETLINK_TYPE_U32 },
        [NDA_IFINDEX]           = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_neigh);

static const NLType rtnl_addrlabel_types[] = {
        [IFAL_ADDRESS]         = { .type = NETLINK_TYPE_IN_ADDR, .size = sizeof(struct in6_addr) },
        [IFAL_LABEL]           = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_addrlabel);

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
        [FRA_UID_RANGE]           = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct fib_rule_uid_range) },
        [FRA_PROTOCOL]            = { .type = NETLINK_TYPE_U8 },
        [FRA_IP_PROTO]            = { .type = NETLINK_TYPE_U8 },
        [FRA_SPORT_RANGE]         = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct fib_rule_port_range) },
        [FRA_DPORT_RANGE]         = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct fib_rule_port_range) },
};

DEFINE_TYPE_SYSTEM(rtnl_routing_policy_rule);

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

DEFINE_TYPE_SYSTEM(rtnl_nexthop);

static const NLType rtnl_tca_option_data_cake_types[] = {
        [TCA_CAKE_BASE_RATE64]   = { .type = NETLINK_TYPE_U64 },
        [TCA_CAKE_DIFFSERV_MODE] = { .type = NETLINK_TYPE_U32 },
        [TCA_CAKE_ATM]           = { .type = NETLINK_TYPE_U32 },
        [TCA_CAKE_FLOW_MODE]     = { .type = NETLINK_TYPE_U32 },
        [TCA_CAKE_OVERHEAD]      = { .type = NETLINK_TYPE_S32 },
        [TCA_CAKE_RTT]           = { .type = NETLINK_TYPE_U32 },
        [TCA_CAKE_TARGET]        = { .type = NETLINK_TYPE_U32 },
        [TCA_CAKE_AUTORATE]      = { .type = NETLINK_TYPE_U32 },
        [TCA_CAKE_MEMORY]        = { .type = NETLINK_TYPE_U32 },
        [TCA_CAKE_NAT]           = { .type = NETLINK_TYPE_U32 },
        [TCA_CAKE_RAW]           = { .type = NETLINK_TYPE_U32 },
        [TCA_CAKE_WASH]          = { .type = NETLINK_TYPE_U32 },
        [TCA_CAKE_MPU]           = { .type = NETLINK_TYPE_U32 },
        [TCA_CAKE_INGRESS]       = { .type = NETLINK_TYPE_U32 },
        [TCA_CAKE_ACK_FILTER]    = { .type = NETLINK_TYPE_U32 },
        [TCA_CAKE_SPLIT_GSO]     = { .type = NETLINK_TYPE_U32 },
        [TCA_CAKE_FWMARK]        = { .type = NETLINK_TYPE_U32 },
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

DEFINE_TYPE_SYSTEM(rtnl_tca_option_data_ets_quanta);

static const NLType rtnl_tca_option_data_ets_prio_types[] = {
        [TCA_ETS_PRIOMAP_BAND] = { .type = NETLINK_TYPE_U8, },
};

DEFINE_TYPE_SYSTEM(rtnl_tca_option_data_ets_prio);

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
        [TCA_GRED_DPS] = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct tc_gred_sopt) },
};

static const NLType rtnl_tca_option_data_hhf_types[] = {
        [TCA_HHF_BACKLOG_LIMIT] = { .type = NETLINK_TYPE_U32 },
};

static const NLType rtnl_tca_option_data_htb_types[] = {
        [TCA_HTB_PARMS]  = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct tc_htb_opt) },
        [TCA_HTB_INIT]   = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct tc_htb_glob) },
        [TCA_HTB_CTAB]   = { .type = NETLINK_TYPE_BINARY, .size = TC_RTAB_SIZE },
        [TCA_HTB_RTAB]   = { .type = NETLINK_TYPE_BINARY, .size = TC_RTAB_SIZE },
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
        [TCA_SFB_PARMS] = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct tc_sfb_qopt) },
};

static const NLType rtnl_tca_option_data_tbf_types[] = {
        [TCA_TBF_PARMS]   = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct tc_tbf_qopt) },
        [TCA_TBF_RTAB]    = { .type = NETLINK_TYPE_BINARY, .size = TC_RTAB_SIZE },
        [TCA_TBF_PTAB]    = { .type = NETLINK_TYPE_BINARY, .size = TC_RTAB_SIZE },
        [TCA_TBF_RATE64]  = { .type = NETLINK_TYPE_U64 },
        [TCA_TBF_PRATE64] = { .type = NETLINK_TYPE_U64 },
        [TCA_TBF_BURST]   = { .type = NETLINK_TYPE_U32 },
        [TCA_TBF_PBURST]  = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystemUnionElement rtnl_tca_option_data_type_systems[] = {
        { .name = "cake",     .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_tca_option_data_cake),     },
        { .name = "codel",    .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_tca_option_data_codel),    },
        { .name = "drr",      .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_tca_option_data_drr),      },
        { .name = "ets",      .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_tca_option_data_ets),      },
        { .name = "fq",       .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_tca_option_data_fq),       },
        { .name = "fq_codel", .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_tca_option_data_fq_codel), },
        { .name = "fq_pie",   .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_tca_option_data_fq_pie),   },
        { .name = "gred",     .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_tca_option_data_gred),     },
        { .name = "hhf",      .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_tca_option_data_hhf),      },
        { .name = "htb",      .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_tca_option_data_htb),      },
        { .name = "pie",      .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_tca_option_data_pie),      },
        { .name = "qfq",      .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_tca_option_data_qfq),      },
        { .name = "sfb",      .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_tca_option_data_sfb),      },
        { .name = "tbf",      .type_system = TYPE_SYSTEM_FROM_TYPE(rtnl_tca_option_data_tbf),      },
};

DEFINE_TYPE_SYSTEM_UNION_MATCH_SIBLING(rtnl_tca_option_data, TCA_KIND);

static const NLType rtnl_tca_types[] = {
        [TCA_KIND]           = { .type = NETLINK_TYPE_STRING },
        [TCA_OPTIONS]        = { .type = NETLINK_TYPE_UNION, .type_system_union = &rtnl_tca_option_data_type_system_union },
        [TCA_INGRESS_BLOCK]  = { .type = NETLINK_TYPE_U32 },
        [TCA_EGRESS_BLOCK]   = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(rtnl_tca);

static const NLType rtnl_mdb_types[] = {
        [MDBA_SET_ENTRY]     = { .type = NETLINK_TYPE_BINARY, .size = sizeof(struct br_port_msg) },
};

DEFINE_TYPE_SYSTEM(rtnl_mdb);

static const NLType rtnl_types[] = {
        [RTM_NEWLINK]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system,                .size = sizeof(struct ifinfomsg) },
        [RTM_DELLINK]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system,                .size = sizeof(struct ifinfomsg) },
        [RTM_GETLINK]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system,                .size = sizeof(struct ifinfomsg) },
        [RTM_SETLINK]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system,                .size = sizeof(struct ifinfomsg) },
        [RTM_NEWLINKPROP]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system,                .size = sizeof(struct ifinfomsg) },
        [RTM_DELLINKPROP]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system,                .size = sizeof(struct ifinfomsg) },
        [RTM_GETLINKPROP]  = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_link_type_system,                .size = sizeof(struct ifinfomsg) },
        [RTM_NEWADDR]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_address_type_system,             .size = sizeof(struct ifaddrmsg) },
        [RTM_DELADDR]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_address_type_system,             .size = sizeof(struct ifaddrmsg) },
        [RTM_GETADDR]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_address_type_system,             .size = sizeof(struct ifaddrmsg) },
        [RTM_NEWROUTE]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_route_type_system,               .size = sizeof(struct rtmsg) },
        [RTM_DELROUTE]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_route_type_system,               .size = sizeof(struct rtmsg) },
        [RTM_GETROUTE]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_route_type_system,               .size = sizeof(struct rtmsg) },
        [RTM_NEWNEIGH]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_neigh_type_system,               .size = sizeof(struct ndmsg) },
        [RTM_DELNEIGH]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_neigh_type_system,               .size = sizeof(struct ndmsg) },
        [RTM_GETNEIGH]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_neigh_type_system,               .size = sizeof(struct ndmsg) },
        [RTM_NEWADDRLABEL] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_addrlabel_type_system,           .size = sizeof(struct ifaddrlblmsg) },
        [RTM_DELADDRLABEL] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_addrlabel_type_system,           .size = sizeof(struct ifaddrlblmsg) },
        [RTM_GETADDRLABEL] = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_addrlabel_type_system,           .size = sizeof(struct ifaddrlblmsg) },
        [RTM_NEWRULE]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_routing_policy_rule_type_system, .size = sizeof(struct fib_rule_hdr) },
        [RTM_DELRULE]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_routing_policy_rule_type_system, .size = sizeof(struct fib_rule_hdr) },
        [RTM_GETRULE]      = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_routing_policy_rule_type_system, .size = sizeof(struct fib_rule_hdr) },
        [RTM_NEWNEXTHOP]   = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_nexthop_type_system,             .size = sizeof(struct nhmsg) },
        [RTM_DELNEXTHOP]   = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_nexthop_type_system,             .size = sizeof(struct nhmsg) },
        [RTM_GETNEXTHOP]   = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_nexthop_type_system,             .size = sizeof(struct nhmsg) },
        [RTM_NEWQDISC]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_tca_type_system,                 .size = sizeof(struct tcmsg) },
        [RTM_DELQDISC]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_tca_type_system,                 .size = sizeof(struct tcmsg) },
        [RTM_GETQDISC]     = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_tca_type_system,                 .size = sizeof(struct tcmsg) },
        [RTM_NEWTCLASS]    = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_tca_type_system,                 .size = sizeof(struct tcmsg) },
        [RTM_DELTCLASS]    = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_tca_type_system,                 .size = sizeof(struct tcmsg) },
        [RTM_GETTCLASS]    = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_tca_type_system,                 .size = sizeof(struct tcmsg) },
        [RTM_NEWMDB]       = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_mdb_type_system,                 .size = sizeof(struct br_port_msg) },
        [RTM_DELMDB]       = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_mdb_type_system,                 .size = sizeof(struct br_port_msg) },
        [RTM_GETMDB]       = { .type = NETLINK_TYPE_NESTED, .type_system = &rtnl_mdb_type_system,                 .size = sizeof(struct br_port_msg) },
};

DEFINE_TYPE_SYSTEM(rtnl);

const NLType *rtnl_get_type(uint16_t nlmsg_type) {
        return type_system_get_type(&rtnl_type_system, nlmsg_type);
}
