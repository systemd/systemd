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
#include <linux/net_namespace.h>
#include <linux/netlink.h>
#include <linux/nexthop.h>
#include <linux/nl80211.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <linux/wireguard.h>

#include "missing_network.h"
#include "netlink-types-internal.h"

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

static const NLAPolicySet rtnl_link_policy_set;

static const NLAPolicy rtnl_link_info_data_bareudp_policies[] = {
        [IFLA_BAREUDP_PORT]            = BUILD_POLICY(U16),
        [IFLA_BAREUDP_ETHERTYPE]       = BUILD_POLICY(U16),
        [IFLA_BAREUDP_SRCPORT_MIN]     = BUILD_POLICY(U16),
        [IFLA_BAREUDP_MULTIPROTO_MODE] = BUILD_POLICY(FLAG),
};

static const NLAPolicy rtnl_link_info_data_batadv_policies[] = {
        [IFLA_BATADV_ALGO_NAME] = BUILD_POLICY_WITH_SIZE(STRING, 20),
};

static const NLAPolicy rtnl_bond_arp_ip_target_policies[] = {
        [BOND_ARP_TARGETS_0]        = BUILD_POLICY(U32),
        [BOND_ARP_TARGETS_1]        = BUILD_POLICY(U32),
        [BOND_ARP_TARGETS_2]        = BUILD_POLICY(U32),
        [BOND_ARP_TARGETS_3]        = BUILD_POLICY(U32),
        [BOND_ARP_TARGETS_4]        = BUILD_POLICY(U32),
        [BOND_ARP_TARGETS_5]        = BUILD_POLICY(U32),
        [BOND_ARP_TARGETS_6]        = BUILD_POLICY(U32),
        [BOND_ARP_TARGETS_7]        = BUILD_POLICY(U32),
        [BOND_ARP_TARGETS_8]        = BUILD_POLICY(U32),
        [BOND_ARP_TARGETS_9]        = BUILD_POLICY(U32),
        [BOND_ARP_TARGETS_10]       = BUILD_POLICY(U32),
        [BOND_ARP_TARGETS_11]       = BUILD_POLICY(U32),
        [BOND_ARP_TARGETS_12]       = BUILD_POLICY(U32),
        [BOND_ARP_TARGETS_13]       = BUILD_POLICY(U32),
        [BOND_ARP_TARGETS_14]       = BUILD_POLICY(U32),
        [BOND_ARP_TARGETS_15]       = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_bond_arp_ip_target);

static const NLAPolicy rtnl_bond_ad_info_policies[] = {
        [IFLA_BOND_AD_INFO_AGGREGATOR]  = BUILD_POLICY(U16),
        [IFLA_BOND_AD_INFO_NUM_PORTS]   = BUILD_POLICY(U16),
        [IFLA_BOND_AD_INFO_ACTOR_KEY]   = BUILD_POLICY(U16),
        [IFLA_BOND_AD_INFO_PARTNER_KEY] = BUILD_POLICY(U16),
        [IFLA_BOND_AD_INFO_PARTNER_MAC] = BUILD_POLICY_WITH_SIZE(ETHER_ADDR, ETH_ALEN),
};

DEFINE_POLICY_SET(rtnl_bond_ad_info);

static const NLAPolicy rtnl_link_info_data_bond_policies[] = {
        [IFLA_BOND_MODE]                = BUILD_POLICY(U8),
        [IFLA_BOND_ACTIVE_SLAVE]        = BUILD_POLICY(U32),
        [IFLA_BOND_MIIMON]              = BUILD_POLICY(U32),
        [IFLA_BOND_UPDELAY]             = BUILD_POLICY(U32),
        [IFLA_BOND_DOWNDELAY]           = BUILD_POLICY(U32),
        [IFLA_BOND_USE_CARRIER]         = BUILD_POLICY(U8),
        [IFLA_BOND_ARP_INTERVAL]        = BUILD_POLICY(U32),
        [IFLA_BOND_ARP_IP_TARGET]       = BUILD_POLICY_NESTED(rtnl_bond_arp_ip_target),
        [IFLA_BOND_ARP_VALIDATE]        = BUILD_POLICY(U32),
        [IFLA_BOND_ARP_ALL_TARGETS]     = BUILD_POLICY(U32),
        [IFLA_BOND_PRIMARY]             = BUILD_POLICY(U32),
        [IFLA_BOND_PRIMARY_RESELECT]    = BUILD_POLICY(U8),
        [IFLA_BOND_FAIL_OVER_MAC]       = BUILD_POLICY(U8),
        [IFLA_BOND_XMIT_HASH_POLICY]    = BUILD_POLICY(U8),
        [IFLA_BOND_RESEND_IGMP]         = BUILD_POLICY(U32),
        [IFLA_BOND_NUM_PEER_NOTIF]      = BUILD_POLICY(U8),
        [IFLA_BOND_ALL_SLAVES_ACTIVE]   = BUILD_POLICY(U8),
        [IFLA_BOND_MIN_LINKS]           = BUILD_POLICY(U32),
        [IFLA_BOND_LP_INTERVAL]         = BUILD_POLICY(U32),
        [IFLA_BOND_PACKETS_PER_SLAVE]   = BUILD_POLICY(U32),
        [IFLA_BOND_AD_LACP_RATE]        = BUILD_POLICY(U8),
        [IFLA_BOND_AD_SELECT]           = BUILD_POLICY(U8),
        [IFLA_BOND_AD_INFO]             = BUILD_POLICY_NESTED(rtnl_bond_ad_info),
        [IFLA_BOND_AD_ACTOR_SYS_PRIO]   = BUILD_POLICY(U16),
        [IFLA_BOND_AD_USER_PORT_KEY]    = BUILD_POLICY(U16),
        [IFLA_BOND_AD_ACTOR_SYSTEM]     = BUILD_POLICY_WITH_SIZE(ETHER_ADDR, ETH_ALEN),
        [IFLA_BOND_TLB_DYNAMIC_LB]      = BUILD_POLICY(U8),
        [IFLA_BOND_PEER_NOTIF_DELAY]    = BUILD_POLICY(U32),
        [IFLA_BOND_MISSED_MAX]          = BUILD_POLICY(U8),
};

static const NLAPolicy rtnl_link_info_data_bridge_policies[] = {
        [IFLA_BR_FORWARD_DELAY]              = BUILD_POLICY(U32),
        [IFLA_BR_HELLO_TIME]                 = BUILD_POLICY(U32),
        [IFLA_BR_MAX_AGE]                    = BUILD_POLICY(U32),
        [IFLA_BR_AGEING_TIME]                = BUILD_POLICY(U32),
        [IFLA_BR_STP_STATE]                  = BUILD_POLICY(U32),
        [IFLA_BR_PRIORITY]                   = BUILD_POLICY(U16),
        [IFLA_BR_VLAN_FILTERING]             = BUILD_POLICY(U8),
        [IFLA_BR_VLAN_PROTOCOL]              = BUILD_POLICY(U16),
        [IFLA_BR_GROUP_FWD_MASK]             = BUILD_POLICY(U16),
        [IFLA_BR_ROOT_ID]                    = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_bridge_id)),
        [IFLA_BR_BRIDGE_ID]                  = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_bridge_id)),
        [IFLA_BR_ROOT_PORT]                  = BUILD_POLICY(U16),
        [IFLA_BR_ROOT_PATH_COST]             = BUILD_POLICY(U32),
        [IFLA_BR_TOPOLOGY_CHANGE]            = BUILD_POLICY(U8),
        [IFLA_BR_TOPOLOGY_CHANGE_DETECTED]   = BUILD_POLICY(U8),
        [IFLA_BR_HELLO_TIMER]                = BUILD_POLICY(U64),
        [IFLA_BR_TCN_TIMER]                  = BUILD_POLICY(U64),
        [IFLA_BR_TOPOLOGY_CHANGE_TIMER]      = BUILD_POLICY(U64),
        [IFLA_BR_GC_TIMER]                   = BUILD_POLICY(U64),
        [IFLA_BR_GROUP_ADDR]                 = BUILD_POLICY_WITH_SIZE(ETHER_ADDR, ETH_ALEN),
        [IFLA_BR_FDB_FLUSH]                  = BUILD_POLICY(FLAG),
        [IFLA_BR_MCAST_ROUTER]               = BUILD_POLICY(U8),
        [IFLA_BR_MCAST_SNOOPING]             = BUILD_POLICY(U8),
        [IFLA_BR_MCAST_QUERY_USE_IFADDR]     = BUILD_POLICY(U8),
        [IFLA_BR_MCAST_QUERIER]              = BUILD_POLICY(U8),
        [IFLA_BR_MCAST_HASH_ELASTICITY]      = BUILD_POLICY(U32),
        [IFLA_BR_MCAST_HASH_MAX]             = BUILD_POLICY(U32),
        [IFLA_BR_MCAST_LAST_MEMBER_CNT]      = BUILD_POLICY(U32),
        [IFLA_BR_MCAST_STARTUP_QUERY_CNT]    = BUILD_POLICY(U32),
        [IFLA_BR_MCAST_LAST_MEMBER_INTVL]    = BUILD_POLICY(U64),
        [IFLA_BR_MCAST_MEMBERSHIP_INTVL]     = BUILD_POLICY(U64),
        [IFLA_BR_MCAST_QUERIER_INTVL]        = BUILD_POLICY(U64),
        [IFLA_BR_MCAST_QUERY_INTVL]          = BUILD_POLICY(U64),
        [IFLA_BR_MCAST_QUERY_RESPONSE_INTVL] = BUILD_POLICY(U64),
        [IFLA_BR_MCAST_STARTUP_QUERY_INTVL]  = BUILD_POLICY(U64),
        [IFLA_BR_NF_CALL_IPTABLES]           = BUILD_POLICY(U8),
        [IFLA_BR_NF_CALL_IP6TABLES]          = BUILD_POLICY(U8),
        [IFLA_BR_NF_CALL_ARPTABLES]          = BUILD_POLICY(U8),
        [IFLA_BR_VLAN_DEFAULT_PVID]          = BUILD_POLICY(U16),
        [IFLA_BR_VLAN_STATS_ENABLED]         = BUILD_POLICY(U8),
        [IFLA_BR_MCAST_STATS_ENABLED]        = BUILD_POLICY(U8),
        [IFLA_BR_MCAST_IGMP_VERSION]         = BUILD_POLICY(U8),
        [IFLA_BR_MCAST_MLD_VERSION]          = BUILD_POLICY(U8),
        [IFLA_BR_VLAN_STATS_PER_PORT]        = BUILD_POLICY(U8),
        [IFLA_BR_MULTI_BOOLOPT]              = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct br_boolopt_multi)),
        [IFLA_BR_FDB_N_LEARNED]              = BUILD_POLICY(U32),
        [IFLA_BR_FDB_MAX_LEARNED]            = BUILD_POLICY(U32),
};

static const NLAPolicy rtnl_link_info_data_can_policies[] = {
        [IFLA_CAN_BITTIMING]            = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct can_bittiming)),
        [IFLA_CAN_BITTIMING_CONST]      = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct can_bittiming_const)),
        [IFLA_CAN_CLOCK]                = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct can_clock)),
        [IFLA_CAN_STATE]                = BUILD_POLICY(U32),
        [IFLA_CAN_CTRLMODE]             = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct can_ctrlmode)),
        [IFLA_CAN_RESTART_MS]           = BUILD_POLICY(U32),
        [IFLA_CAN_RESTART]              = BUILD_POLICY(U32),
        [IFLA_CAN_BERR_COUNTER]         = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct can_berr_counter)),
        [IFLA_CAN_DATA_BITTIMING]       = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct can_bittiming)),
        [IFLA_CAN_DATA_BITTIMING_CONST] = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct can_bittiming_const)),
        [IFLA_CAN_TERMINATION]          = BUILD_POLICY(U16),
        [IFLA_CAN_TERMINATION_CONST]    = BUILD_POLICY(BINARY), /* size = termination_const_cnt * sizeof(u16) */
        [IFLA_CAN_BITRATE_CONST]        = BUILD_POLICY(BINARY), /* size = bitrate_const_cnt * sizeof(u32) */
        [IFLA_CAN_DATA_BITRATE_CONST]   = BUILD_POLICY(BINARY), /* size = data_bitrate_const_cnt * sizeof(u32) */
        [IFLA_CAN_BITRATE_MAX]          = BUILD_POLICY(U32),
};

static const NLAPolicy rtnl_link_info_data_geneve_policies[] = {
        [IFLA_GENEVE_ID]                  = BUILD_POLICY(U32),
        [IFLA_GENEVE_REMOTE]              = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in_addr)),
        [IFLA_GENEVE_TTL]                 = BUILD_POLICY(U8),
        [IFLA_GENEVE_TOS]                 = BUILD_POLICY(U8),
        [IFLA_GENEVE_PORT]                = BUILD_POLICY(U16),
        [IFLA_GENEVE_COLLECT_METADATA]    = BUILD_POLICY(FLAG),
        [IFLA_GENEVE_REMOTE6]             = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in6_addr)),
        [IFLA_GENEVE_UDP_CSUM]            = BUILD_POLICY(U8),
        [IFLA_GENEVE_UDP_ZERO_CSUM6_TX]   = BUILD_POLICY(U8),
        [IFLA_GENEVE_UDP_ZERO_CSUM6_RX]   = BUILD_POLICY(U8),
        [IFLA_GENEVE_LABEL]               = BUILD_POLICY(U32),
        [IFLA_GENEVE_TTL_INHERIT]         = BUILD_POLICY(U8),
        [IFLA_GENEVE_DF]                  = BUILD_POLICY(U8),
        [IFLA_GENEVE_INNER_PROTO_INHERIT] = BUILD_POLICY(FLAG),
};

static const NLAPolicy rtnl_link_info_data_gre_policies[] = {
        [IFLA_GRE_LINK]             = BUILD_POLICY(U32),
        [IFLA_GRE_IFLAGS]           = BUILD_POLICY(U16),
        [IFLA_GRE_OFLAGS]           = BUILD_POLICY(U16),
        [IFLA_GRE_IKEY]             = BUILD_POLICY(U32),
        [IFLA_GRE_OKEY]             = BUILD_POLICY(U32),
        [IFLA_GRE_LOCAL]            = BUILD_POLICY(IN_ADDR),
        [IFLA_GRE_REMOTE]           = BUILD_POLICY(IN_ADDR),
        [IFLA_GRE_TTL]              = BUILD_POLICY(U8),
        [IFLA_GRE_TOS]              = BUILD_POLICY(U8),
        [IFLA_GRE_PMTUDISC]         = BUILD_POLICY(U8),
        [IFLA_GRE_ENCAP_LIMIT]      = BUILD_POLICY(U8),
        [IFLA_GRE_FLOWINFO]         = BUILD_POLICY(U32),
        [IFLA_GRE_FLAGS]            = BUILD_POLICY(U32),
        [IFLA_GRE_ENCAP_TYPE]       = BUILD_POLICY(U16),
        [IFLA_GRE_ENCAP_FLAGS]      = BUILD_POLICY(U16),
        [IFLA_GRE_ENCAP_SPORT]      = BUILD_POLICY(U16),
        [IFLA_GRE_ENCAP_DPORT]      = BUILD_POLICY(U16),
        [IFLA_GRE_COLLECT_METADATA] = BUILD_POLICY(FLAG),
        [IFLA_GRE_IGNORE_DF]        = BUILD_POLICY(U8),
        [IFLA_GRE_FWMARK]           = BUILD_POLICY(U32),
        [IFLA_GRE_ERSPAN_INDEX]     = BUILD_POLICY(U32),
        [IFLA_GRE_ERSPAN_VER]       = BUILD_POLICY(U8),
        [IFLA_GRE_ERSPAN_DIR]       = BUILD_POLICY(U8),
        [IFLA_GRE_ERSPAN_HWID]      = BUILD_POLICY(U16),
};

static const NLAPolicy rtnl_link_info_data_ipoib_policies[] = {
        [IFLA_IPOIB_PKEY]           = BUILD_POLICY(U16),
        [IFLA_IPOIB_MODE]           = BUILD_POLICY(U16),
        [IFLA_IPOIB_UMCAST]         = BUILD_POLICY(U16),
};

/* IFLA_IPTUN_ attributes are used in ipv4/ipip.c, ipv6/ip6_tunnel.c, and ipv6/sit.c. And unfortunately,
 * IFLA_IPTUN_FLAGS is used with different types, ugh... */
#define DEFINE_IPTUN_TYPES(name, flags_type)                            \
        static const NLAPolicy rtnl_link_info_data_##name##_policies[] = {    \
                [IFLA_IPTUN_LINK]                = BUILD_POLICY(U32),   \
                [IFLA_IPTUN_LOCAL]               = BUILD_POLICY(IN_ADDR), \
                [IFLA_IPTUN_REMOTE]              = BUILD_POLICY(IN_ADDR), \
                [IFLA_IPTUN_TTL]                 = BUILD_POLICY(U8),    \
                [IFLA_IPTUN_TOS]                 = BUILD_POLICY(U8),    \
                [IFLA_IPTUN_ENCAP_LIMIT]         = BUILD_POLICY(U8),    \
                [IFLA_IPTUN_FLOWINFO]            = BUILD_POLICY(U32),   \
                [IFLA_IPTUN_FLAGS]               = BUILD_POLICY(flags_type), \
                [IFLA_IPTUN_PROTO]               = BUILD_POLICY(U8),    \
                [IFLA_IPTUN_PMTUDISC]            = BUILD_POLICY(U8),    \
                [IFLA_IPTUN_6RD_PREFIX]          = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in6_addr)), \
                [IFLA_IPTUN_6RD_RELAY_PREFIX]    = BUILD_POLICY(U32),   \
                [IFLA_IPTUN_6RD_PREFIXLEN]       = BUILD_POLICY(U16),   \
                [IFLA_IPTUN_6RD_RELAY_PREFIXLEN] = BUILD_POLICY(U16),   \
                [IFLA_IPTUN_ENCAP_TYPE]          = BUILD_POLICY(U16),   \
                [IFLA_IPTUN_ENCAP_FLAGS]         = BUILD_POLICY(U16),   \
                [IFLA_IPTUN_ENCAP_SPORT]         = BUILD_POLICY(U16),   \
                [IFLA_IPTUN_ENCAP_DPORT]         = BUILD_POLICY(U16),   \
                [IFLA_IPTUN_COLLECT_METADATA]    = BUILD_POLICY(FLAG),  \
                [IFLA_IPTUN_FWMARK]              = BUILD_POLICY(U32),   \
        }

DEFINE_IPTUN_TYPES(iptun, U32); /* for ipip and ip6tnl */
DEFINE_IPTUN_TYPES(sit, U16); /* for sit */

static const NLAPolicy rtnl_link_info_data_ipvlan_policies[] = {
        [IFLA_IPVLAN_MODE]  = BUILD_POLICY(U16),
        [IFLA_IPVLAN_FLAGS] = BUILD_POLICY(U16),
};

static const NLAPolicy rtnl_link_info_data_macsec_policies[] = {
        [IFLA_MACSEC_SCI]            = BUILD_POLICY(U64),
        [IFLA_MACSEC_PORT]           = BUILD_POLICY(U16),
        [IFLA_MACSEC_ICV_LEN]        = BUILD_POLICY(U8),
        [IFLA_MACSEC_CIPHER_SUITE]   = BUILD_POLICY(U64),
        [IFLA_MACSEC_WINDOW]         = BUILD_POLICY(U32),
        [IFLA_MACSEC_ENCODING_SA]    = BUILD_POLICY(U8),
        [IFLA_MACSEC_ENCRYPT]        = BUILD_POLICY(U8),
        [IFLA_MACSEC_PROTECT]        = BUILD_POLICY(U8),
        [IFLA_MACSEC_INC_SCI]        = BUILD_POLICY(U8),
        [IFLA_MACSEC_ES]             = BUILD_POLICY(U8),
        [IFLA_MACSEC_SCB]            = BUILD_POLICY(U8),
        [IFLA_MACSEC_REPLAY_PROTECT] = BUILD_POLICY(U8),
        [IFLA_MACSEC_VALIDATION]     = BUILD_POLICY(U8),
        [IFLA_MACSEC_OFFLOAD]        = BUILD_POLICY(U8),
};

static const NLAPolicy rtnl_macvlan_macaddr_policies[] = {
        [IFLA_MACVLAN_MACADDR] = BUILD_POLICY_WITH_SIZE(ETHER_ADDR, ETH_ALEN),
};

DEFINE_POLICY_SET(rtnl_macvlan_macaddr);

static const NLAPolicy rtnl_link_info_data_macvlan_policies[] = {
        [IFLA_MACVLAN_MODE]              = BUILD_POLICY(U32),
        [IFLA_MACVLAN_FLAGS]             = BUILD_POLICY(U16),
        [IFLA_MACVLAN_MACADDR_MODE]      = BUILD_POLICY(U32),
        [IFLA_MACVLAN_MACADDR_DATA]      = BUILD_POLICY_NESTED(rtnl_macvlan_macaddr),
        [IFLA_MACVLAN_MACADDR_COUNT]     = BUILD_POLICY(U32),
        [IFLA_MACVLAN_BC_QUEUE_LEN]      = BUILD_POLICY(U32),
        [IFLA_MACVLAN_BC_QUEUE_LEN_USED] = BUILD_POLICY(U32),
        [IFLA_MACVLAN_BC_CUTOFF]         = BUILD_POLICY(S32),
};

static const NLAPolicy rtnl_link_info_data_tun_policies[] = {
        [IFLA_TUN_OWNER]               = BUILD_POLICY(U32),
        [IFLA_TUN_GROUP]               = BUILD_POLICY(U32),
        [IFLA_TUN_TYPE]                = BUILD_POLICY(U8),
        [IFLA_TUN_PI]                  = BUILD_POLICY(U8),
        [IFLA_TUN_VNET_HDR]            = BUILD_POLICY(U8),
        [IFLA_TUN_PERSIST]             = BUILD_POLICY(U8),
        [IFLA_TUN_MULTI_QUEUE]         = BUILD_POLICY(U8),
        [IFLA_TUN_NUM_QUEUES]          = BUILD_POLICY(U32),
        [IFLA_TUN_NUM_DISABLED_QUEUES] = BUILD_POLICY(U32),
};

static const NLAPolicy rtnl_link_info_data_veth_policies[] = {
        [VETH_INFO_PEER]  = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_link, sizeof(struct ifinfomsg)),
};

static const NLAPolicy rtnl_vlan_qos_map_policies[] = {
        [IFLA_VLAN_QOS_MAPPING]        = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_vlan_qos_mapping)),
};

DEFINE_POLICY_SET(rtnl_vlan_qos_map);

static const NLAPolicy rtnl_link_info_data_vlan_policies[] = {
        [IFLA_VLAN_ID]          = BUILD_POLICY(U16),
        [IFLA_VLAN_FLAGS]       = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_vlan_flags)),
        [IFLA_VLAN_EGRESS_QOS]  = BUILD_POLICY_NESTED(rtnl_vlan_qos_map),
        [IFLA_VLAN_INGRESS_QOS] = BUILD_POLICY_NESTED(rtnl_vlan_qos_map),
        [IFLA_VLAN_PROTOCOL]    = BUILD_POLICY(U16),
};

static const NLAPolicy rtnl_link_info_data_vrf_policies[] = {
        [IFLA_VRF_TABLE]                 = BUILD_POLICY(U32),
};

static const NLAPolicy rtnl_link_info_data_vti_policies[] = {
        [IFLA_VTI_LINK]         = BUILD_POLICY(U32),
        [IFLA_VTI_IKEY]         = BUILD_POLICY(U32),
        [IFLA_VTI_OKEY]         = BUILD_POLICY(U32),
        [IFLA_VTI_LOCAL]        = BUILD_POLICY(IN_ADDR),
        [IFLA_VTI_REMOTE]       = BUILD_POLICY(IN_ADDR),
        [IFLA_VTI_FWMARK]       = BUILD_POLICY(U32),
};

static const NLAPolicy rtnl_link_info_data_vxcan_policies[] = {
        [VXCAN_INFO_PEER]  = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_link, sizeof(struct ifinfomsg)),
};

static const NLAPolicy rtnl_link_info_data_vxlan_policies[] = {
        [IFLA_VXLAN_ID]                = BUILD_POLICY(U32),
        [IFLA_VXLAN_GROUP]             = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in_addr)),
        [IFLA_VXLAN_LINK]              = BUILD_POLICY(U32),
        [IFLA_VXLAN_LOCAL]             = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in_addr)),
        [IFLA_VXLAN_TTL]               = BUILD_POLICY(U8),
        [IFLA_VXLAN_TOS]               = BUILD_POLICY(U8),
        [IFLA_VXLAN_LEARNING]          = BUILD_POLICY(U8),
        [IFLA_VXLAN_AGEING]            = BUILD_POLICY(U32),
        [IFLA_VXLAN_LIMIT]             = BUILD_POLICY(U32),
        [IFLA_VXLAN_PORT_RANGE]        = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_vxlan_port_range)),
        [IFLA_VXLAN_PROXY]             = BUILD_POLICY(U8),
        [IFLA_VXLAN_RSC]               = BUILD_POLICY(U8),
        [IFLA_VXLAN_L2MISS]            = BUILD_POLICY(U8),
        [IFLA_VXLAN_L3MISS]            = BUILD_POLICY(U8),
        [IFLA_VXLAN_PORT]              = BUILD_POLICY(U16),
        [IFLA_VXLAN_GROUP6]            = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in6_addr)),
        [IFLA_VXLAN_LOCAL6]            = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in6_addr)),
        [IFLA_VXLAN_UDP_CSUM]          = BUILD_POLICY(U8),
        [IFLA_VXLAN_UDP_ZERO_CSUM6_TX] = BUILD_POLICY(U8),
        [IFLA_VXLAN_UDP_ZERO_CSUM6_RX] = BUILD_POLICY(U8),
        [IFLA_VXLAN_REMCSUM_TX]        = BUILD_POLICY(U8),
        [IFLA_VXLAN_REMCSUM_RX]        = BUILD_POLICY(U8),
        [IFLA_VXLAN_GBP]               = BUILD_POLICY(FLAG),
        [IFLA_VXLAN_REMCSUM_NOPARTIAL] = BUILD_POLICY(FLAG),
        [IFLA_VXLAN_COLLECT_METADATA]  = BUILD_POLICY(U8),
        [IFLA_VXLAN_LABEL]             = BUILD_POLICY(U32),
        [IFLA_VXLAN_GPE]               = BUILD_POLICY(FLAG),
        [IFLA_VXLAN_TTL_INHERIT]       = BUILD_POLICY(FLAG),
        [IFLA_VXLAN_DF]                = BUILD_POLICY(U8),
};

static const NLAPolicy rtnl_link_info_data_xfrm_policies[] = {
        [IFLA_XFRM_LINK]         = BUILD_POLICY(U32),
        [IFLA_XFRM_IF_ID]        = BUILD_POLICY(U32)
};

static const NLAPolicySetUnionElement rtnl_link_info_data_policy_set_union_elements[] = {
        BUILD_UNION_ELEMENT_BY_STRING("bareudp",   rtnl_link_info_data_bareudp),
        BUILD_UNION_ELEMENT_BY_STRING("batadv",    rtnl_link_info_data_batadv),
        BUILD_UNION_ELEMENT_BY_STRING("bond",      rtnl_link_info_data_bond),
        BUILD_UNION_ELEMENT_BY_STRING("bridge",    rtnl_link_info_data_bridge),
/*
        BUILD_UNION_ELEMENT_BY_STRING("caif",      rtnl_link_info_data_caif),
*/
        BUILD_UNION_ELEMENT_BY_STRING("can",       rtnl_link_info_data_can),
        BUILD_UNION_ELEMENT_BY_STRING("erspan",    rtnl_link_info_data_gre),
        BUILD_UNION_ELEMENT_BY_STRING("geneve",    rtnl_link_info_data_geneve),
        BUILD_UNION_ELEMENT_BY_STRING("gre",       rtnl_link_info_data_gre),
        BUILD_UNION_ELEMENT_BY_STRING("gretap",    rtnl_link_info_data_gre),
/*
        BUILD_UNION_ELEMENT_BY_STRING("gtp",       rtnl_link_info_data_gtp),
        BUILD_UNION_ELEMENT_BY_STRING("hsr",       rtnl_link_info_data_hsr),
*/
        BUILD_UNION_ELEMENT_BY_STRING("ip6erspan", rtnl_link_info_data_gre),
        BUILD_UNION_ELEMENT_BY_STRING("ip6gre",    rtnl_link_info_data_gre),
        BUILD_UNION_ELEMENT_BY_STRING("ip6gretap", rtnl_link_info_data_gre),
        BUILD_UNION_ELEMENT_BY_STRING("ip6tnl",    rtnl_link_info_data_iptun),
        BUILD_UNION_ELEMENT_BY_STRING("ipoib",     rtnl_link_info_data_ipoib),
        BUILD_UNION_ELEMENT_BY_STRING("ipip",      rtnl_link_info_data_iptun),
        BUILD_UNION_ELEMENT_BY_STRING("ipvlan",    rtnl_link_info_data_ipvlan),
        BUILD_UNION_ELEMENT_BY_STRING("ipvtap",    rtnl_link_info_data_ipvlan),
        BUILD_UNION_ELEMENT_BY_STRING("macsec",    rtnl_link_info_data_macsec),
        BUILD_UNION_ELEMENT_BY_STRING("macvlan",   rtnl_link_info_data_macvlan),
        BUILD_UNION_ELEMENT_BY_STRING("macvtap",   rtnl_link_info_data_macvlan),
/*
        BUILD_UNION_ELEMENT_BY_STRING("ppp",       rtnl_link_info_data_ppp),
        BUILD_UNION_ELEMENT_BY_STRING("rmnet",     rtnl_link_info_data_rmnet),
*/
        BUILD_UNION_ELEMENT_BY_STRING("sit",       rtnl_link_info_data_sit),
        BUILD_UNION_ELEMENT_BY_STRING("tun",       rtnl_link_info_data_tun),
        BUILD_UNION_ELEMENT_BY_STRING("veth",      rtnl_link_info_data_veth),
        BUILD_UNION_ELEMENT_BY_STRING("vlan",      rtnl_link_info_data_vlan),
        BUILD_UNION_ELEMENT_BY_STRING("vrf",       rtnl_link_info_data_vrf),
        BUILD_UNION_ELEMENT_BY_STRING("vti",       rtnl_link_info_data_vti),
        BUILD_UNION_ELEMENT_BY_STRING("vti6",      rtnl_link_info_data_vti),
        BUILD_UNION_ELEMENT_BY_STRING("vxcan",     rtnl_link_info_data_vxcan),
        BUILD_UNION_ELEMENT_BY_STRING("vxlan",     rtnl_link_info_data_vxlan),
/*
        BUILD_UNION_ELEMENT_BY_STRING("wwan",      rtnl_link_info_data_wwan),
*/
        BUILD_UNION_ELEMENT_BY_STRING("xfrm",      rtnl_link_info_data_xfrm),
};

DEFINE_POLICY_SET_UNION(rtnl_link_info_data, IFLA_INFO_KIND);

static const struct NLAPolicy rtnl_bridge_port_policies[] = {
        [IFLA_BRPORT_STATE]                 = BUILD_POLICY(U8),
        [IFLA_BRPORT_COST]                  = BUILD_POLICY(U32),
        [IFLA_BRPORT_PRIORITY]              = BUILD_POLICY(U16),
        [IFLA_BRPORT_MODE]                  = BUILD_POLICY(U8),
        [IFLA_BRPORT_GUARD]                 = BUILD_POLICY(U8),
        [IFLA_BRPORT_PROTECT]               = BUILD_POLICY(U8),
        [IFLA_BRPORT_FAST_LEAVE]            = BUILD_POLICY(U8),
        [IFLA_BRPORT_LEARNING]              = BUILD_POLICY(U8),
        [IFLA_BRPORT_UNICAST_FLOOD]         = BUILD_POLICY(U8),
        [IFLA_BRPORT_PROXYARP]              = BUILD_POLICY(U8),
        [IFLA_BRPORT_LEARNING_SYNC]         = BUILD_POLICY(U8),
        [IFLA_BRPORT_PROXYARP_WIFI]         = BUILD_POLICY(U8),
        [IFLA_BRPORT_ROOT_ID]               = BUILD_POLICY(U8),
        [IFLA_BRPORT_BRIDGE_ID]             = BUILD_POLICY(U8),
        [IFLA_BRPORT_DESIGNATED_PORT]       = BUILD_POLICY(U16),
        [IFLA_BRPORT_DESIGNATED_COST]       = BUILD_POLICY(U16),
        [IFLA_BRPORT_ID]                    = BUILD_POLICY(U16),
        [IFLA_BRPORT_NO]                    = BUILD_POLICY(U16),
        [IFLA_BRPORT_TOPOLOGY_CHANGE_ACK]   = BUILD_POLICY(U8),
        [IFLA_BRPORT_CONFIG_PENDING]        = BUILD_POLICY(U8),
        [IFLA_BRPORT_MESSAGE_AGE_TIMER]     = BUILD_POLICY(U64),
        [IFLA_BRPORT_FORWARD_DELAY_TIMER]   = BUILD_POLICY(U64),
        [IFLA_BRPORT_HOLD_TIMER]            = BUILD_POLICY(U64),
        [IFLA_BRPORT_FLUSH]                 = BUILD_POLICY(U8),
        [IFLA_BRPORT_MULTICAST_ROUTER]      = BUILD_POLICY(U8),
        [IFLA_BRPORT_PAD]                   = BUILD_POLICY(U8),
        [IFLA_BRPORT_MCAST_FLOOD]           = BUILD_POLICY(U8),
        [IFLA_BRPORT_MCAST_TO_UCAST]        = BUILD_POLICY(U8),
        [IFLA_BRPORT_VLAN_TUNNEL]           = BUILD_POLICY(U8),
        [IFLA_BRPORT_BCAST_FLOOD]           = BUILD_POLICY(U8),
        [IFLA_BRPORT_GROUP_FWD_MASK]        = BUILD_POLICY(U16),
        [IFLA_BRPORT_NEIGH_SUPPRESS]        = BUILD_POLICY(U8),
        [IFLA_BRPORT_ISOLATED]              = BUILD_POLICY(U8),
        [IFLA_BRPORT_BACKUP_PORT]           = BUILD_POLICY(U32),
        [IFLA_BRPORT_MRP_RING_OPEN]         = BUILD_POLICY(U8),
        [IFLA_BRPORT_MRP_IN_OPEN]           = BUILD_POLICY(U8),
        [IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT] = BUILD_POLICY(U32),
        [IFLA_BRPORT_MCAST_EHT_HOSTS_CNT]   = BUILD_POLICY(U32),
        [IFLA_BRPORT_LOCKED]                = BUILD_POLICY(U8),
        [IFLA_BRPORT_MAB]                   = BUILD_POLICY(U8),
};

static const NLAPolicySetUnionElement rtnl_link_info_slave_data_policy_set_union_elements[] = {
        BUILD_UNION_ELEMENT_BY_STRING("bridge",    rtnl_bridge_port),
};

DEFINE_POLICY_SET_UNION(rtnl_link_info_slave_data, IFLA_INFO_SLAVE_KIND);

static const NLAPolicy rtnl_link_info_policies[] = {
        [IFLA_INFO_KIND]        = BUILD_POLICY(STRING),
        [IFLA_INFO_DATA]        = BUILD_POLICY_NESTED_UNION_BY_STRING(rtnl_link_info_data),
        /* TODO: Currently IFLA_INFO_XSTATS is used only when IFLA_INFO_KIND is "can". In the future,
         * when multiple kinds of netdevs use this attribute, convert its type to NETLINK_TYPE_UNION. */
        [IFLA_INFO_XSTATS]      = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct can_device_stats)),
        [IFLA_INFO_SLAVE_KIND]  = BUILD_POLICY(STRING),
        [IFLA_INFO_SLAVE_DATA]  = BUILD_POLICY_NESTED_UNION_BY_STRING(rtnl_link_info_slave_data),
};

DEFINE_POLICY_SET(rtnl_link_info);

static const struct NLAPolicy rtnl_inet_policies[] = {
        [IFLA_INET_CONF] = BUILD_POLICY(BINARY), /* size = IPV4_DEVCONF_MAX * 4 */
};

DEFINE_POLICY_SET(rtnl_inet);

static const struct NLAPolicy rtnl_inet6_policies[] = {
        [IFLA_INET6_FLAGS]         = BUILD_POLICY(U32),
        [IFLA_INET6_CONF]          = BUILD_POLICY(BINARY), /* size = DEVCONF_MAX * sizeof(s32) */
        [IFLA_INET6_STATS]         = BUILD_POLICY(BINARY), /* size = IPSTATS_MIB_MAX * sizeof(u64) */
        [IFLA_INET6_MCAST]         = {}, /* unused. */
        [IFLA_INET6_CACHEINFO]     = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_cacheinfo)),
        [IFLA_INET6_ICMP6STATS]    = BUILD_POLICY(BINARY), /* size = ICMP6_MIB_MAX * sizeof(u64) */
        [IFLA_INET6_TOKEN]         = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in6_addr)),
        [IFLA_INET6_ADDR_GEN_MODE] = BUILD_POLICY(U8),
};

DEFINE_POLICY_SET(rtnl_inet6);

static const NLAPolicySetUnionElement rtnl_prot_info_policy_set_union_elements[] = {
        BUILD_UNION_ELEMENT_BY_FAMILY(AF_BRIDGE, rtnl_bridge_port),
        BUILD_UNION_ELEMENT_BY_FAMILY(AF_INET6,  rtnl_inet6),
};

DEFINE_POLICY_SET_UNION(rtnl_prot_info, 0);

static const NLAPolicy rtnl_af_spec_unspec_policies[] = {
        [AF_INET]  = BUILD_POLICY_NESTED(rtnl_inet),
        [AF_INET6] = BUILD_POLICY_NESTED(rtnl_inet6),
};

static const NLAPolicy rtnl_bridge_vlan_tunnel_info_policies[] = {
        [IFLA_BRIDGE_VLAN_TUNNEL_ID]    = BUILD_POLICY(U32),
        [IFLA_BRIDGE_VLAN_TUNNEL_VID]   = BUILD_POLICY(U16),
        [IFLA_BRIDGE_VLAN_TUNNEL_FLAGS] = BUILD_POLICY(U16),
};

DEFINE_POLICY_SET(rtnl_bridge_vlan_tunnel_info);

static const NLAPolicy rtnl_bridge_mrp_instance_policies[] = {
        [IFLA_BRIDGE_MRP_INSTANCE_RING_ID]      = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_INSTANCE_P_IFINDEX]    = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_INSTANCE_S_IFINDEX]    = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_INSTANCE_PRIO]         = BUILD_POLICY(U16),
};

DEFINE_POLICY_SET(rtnl_bridge_mrp_instance);

static const NLAPolicy rtnl_bridge_mrp_port_state_policies[] = {
        [IFLA_BRIDGE_MRP_PORT_STATE_STATE]      = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_bridge_mrp_port_state);

static const NLAPolicy rtnl_bridge_mrp_port_role_policies[] = {
        [IFLA_BRIDGE_MRP_PORT_ROLE_ROLE]        = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_bridge_mrp_port_role);

static const NLAPolicy rtnl_bridge_mrp_ring_state_policies[] = {
        [IFLA_BRIDGE_MRP_RING_STATE_RING_ID]    = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_RING_STATE_STATE]      = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_bridge_mrp_ring_state);

static const NLAPolicy rtnl_bridge_mrp_ring_role_policies[] = {
        [IFLA_BRIDGE_MRP_RING_ROLE_RING_ID]     = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_RING_ROLE_ROLE]        = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_bridge_mrp_ring_role);

static const NLAPolicy rtnl_bridge_mrp_start_test_policies[] = {
        [IFLA_BRIDGE_MRP_START_TEST_RING_ID]    = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_START_TEST_INTERVAL]   = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_START_TEST_MAX_MISS]   = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_START_TEST_PERIOD]     = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_START_TEST_MONITOR]    = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_bridge_mrp_start_test);

static const NLAPolicy rtnl_bridge_mrp_info_policies[] = {
        [IFLA_BRIDGE_MRP_INFO_RING_ID]          = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_INFO_P_IFINDEX]        = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_INFO_S_IFINDEX]        = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_INFO_PRIO]             = BUILD_POLICY(U16),
        [IFLA_BRIDGE_MRP_INFO_RING_STATE]       = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_INFO_RING_ROLE]        = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_INFO_TEST_INTERVAL]    = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_INFO_TEST_MAX_MISS]    = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_INFO_TEST_MONITOR]     = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_INFO_I_IFINDEX]        = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_INFO_IN_STATE]         = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_INFO_IN_ROLE]          = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_INFO_IN_TEST_INTERVAL] = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_INFO_IN_TEST_MAX_MISS] = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_bridge_mrp_info);

static const NLAPolicy rtnl_bridge_mrp_in_role_policies[] = {
        [IFLA_BRIDGE_MRP_IN_ROLE_RING_ID]       = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_IN_ROLE_IN_ID]         = BUILD_POLICY(U16),
        [IFLA_BRIDGE_MRP_IN_ROLE_ROLE]          = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_IN_ROLE_I_IFINDEX]     = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_bridge_mrp_in_role);

static const NLAPolicy rtnl_bridge_mrp_in_state_policies[] = {
        [IFLA_BRIDGE_MRP_IN_STATE_IN_ID]        = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_IN_STATE_STATE]        = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_bridge_mrp_in_state);

static const NLAPolicy rtnl_bridge_mrp_start_in_test_policies[] = {
        [IFLA_BRIDGE_MRP_START_IN_TEST_IN_ID]    = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_START_IN_TEST_INTERVAL] = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_START_IN_TEST_MAX_MISS] = BUILD_POLICY(U32),
        [IFLA_BRIDGE_MRP_START_IN_TEST_PERIOD]   = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_bridge_mrp_start_in_test);

static const NLAPolicy rtnl_bridge_mrp_policies[] = {
        [IFLA_BRIDGE_MRP_INSTANCE]      = BUILD_POLICY_NESTED(rtnl_bridge_mrp_instance),
        [IFLA_BRIDGE_MRP_PORT_STATE]    = BUILD_POLICY_NESTED(rtnl_bridge_mrp_port_state),
        [IFLA_BRIDGE_MRP_PORT_ROLE]     = BUILD_POLICY_NESTED(rtnl_bridge_mrp_port_role),
        [IFLA_BRIDGE_MRP_RING_STATE]    = BUILD_POLICY_NESTED(rtnl_bridge_mrp_ring_state),
        [IFLA_BRIDGE_MRP_RING_ROLE]     = BUILD_POLICY_NESTED(rtnl_bridge_mrp_ring_role),
        [IFLA_BRIDGE_MRP_START_TEST]    = BUILD_POLICY_NESTED(rtnl_bridge_mrp_start_test),
        [IFLA_BRIDGE_MRP_INFO]          = BUILD_POLICY_NESTED(rtnl_bridge_mrp_info),
        [IFLA_BRIDGE_MRP_IN_ROLE]       = BUILD_POLICY_NESTED(rtnl_bridge_mrp_in_role),
        [IFLA_BRIDGE_MRP_IN_STATE]      = BUILD_POLICY_NESTED(rtnl_bridge_mrp_in_state),
        [IFLA_BRIDGE_MRP_START_IN_TEST] = BUILD_POLICY_NESTED(rtnl_bridge_mrp_start_in_test),
};

DEFINE_POLICY_SET(rtnl_bridge_mrp);

static const NLAPolicy rtnl_bridge_cfm_mep_create_policies[] = {
        [IFLA_BRIDGE_CFM_MEP_CREATE_INSTANCE]   = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_MEP_CREATE_DOMAIN]     = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_MEP_CREATE_DIRECTION]  = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_MEP_CREATE_IFINDEX]    = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_bridge_cfm_mep_create);

static const NLAPolicy rtnl_bridge_cfm_mep_delete_policies[] = {
        [IFLA_BRIDGE_CFM_MEP_DELETE_INSTANCE]   = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_bridge_cfm_mep_delete);

static const NLAPolicy rtnl_bridge_cfm_mep_config_policies[] = {
        [IFLA_BRIDGE_CFM_MEP_CONFIG_INSTANCE]    = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_MEP_CONFIG_UNICAST_MAC] = BUILD_POLICY_WITH_SIZE(ETHER_ADDR, ETH_ALEN),
        [IFLA_BRIDGE_CFM_MEP_CONFIG_MDLEVEL]     = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_MEP_CONFIG_MEPID]       = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_bridge_cfm_mep_config);

static const NLAPolicy rtnl_bridge_cfm_cc_config_policies[] = {
        [IFLA_BRIDGE_CFM_CC_CONFIG_INSTANCE]     = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_CC_CONFIG_ENABLE]       = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_CC_CONFIG_EXP_INTERVAL] = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_CC_CONFIG_EXP_MAID]     = BUILD_POLICY_WITH_SIZE(BINARY, CFM_MAID_LENGTH),
};

DEFINE_POLICY_SET(rtnl_bridge_cfm_cc_config);

static const NLAPolicy rtnl_bridge_cfm_cc_peer_mep_policies[] = {
        [IFLA_BRIDGE_CFM_CC_PEER_MEP_INSTANCE]  = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_CC_PEER_MEPID]         = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_bridge_cfm_cc_peer_mep);

static const NLAPolicy rtnl_bridge_cfm_cc_rdi_policies[] = {
        [IFLA_BRIDGE_CFM_CC_RDI_INSTANCE]       = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_CC_RDI_RDI]            = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_bridge_cfm_cc_rdi);

static const NLAPolicy rtnl_bridge_cfm_cc_ccm_tx_policies[] = {
        [IFLA_BRIDGE_CFM_CC_CCM_TX_INSTANCE]       = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_CC_CCM_TX_DMAC]           = BUILD_POLICY_WITH_SIZE(ETHER_ADDR, ETH_ALEN),
        [IFLA_BRIDGE_CFM_CC_CCM_TX_SEQ_NO_UPDATE]  = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_CC_CCM_TX_PERIOD]         = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_CC_CCM_TX_IF_TLV]         = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_CC_CCM_TX_IF_TLV_VALUE]   = BUILD_POLICY(U8),
        [IFLA_BRIDGE_CFM_CC_CCM_TX_PORT_TLV]       = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_CC_CCM_TX_PORT_TLV_VALUE] = BUILD_POLICY(U8),
};

DEFINE_POLICY_SET(rtnl_bridge_cfm_cc_ccm_tx);

static const NLAPolicy rtnl_bridge_cfm_mep_status_policies[] = {
        [IFLA_BRIDGE_CFM_MEP_STATUS_INSTANCE]           = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_MEP_STATUS_OPCODE_UNEXP_SEEN]  = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_MEP_STATUS_VERSION_UNEXP_SEEN] = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_MEP_STATUS_RX_LEVEL_LOW_SEEN]  = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_bridge_cfm_mep_status);

static const NLAPolicy rtnl_bridge_cfm_cc_peer_status_policies[] = {
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_INSTANCE]       = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_PEER_MEPID]     = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_CCM_DEFECT]     = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_RDI]            = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_PORT_TLV_VALUE] = BUILD_POLICY(U8),
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_IF_TLV_VALUE]   = BUILD_POLICY(U8),
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_SEEN]           = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_TLV_SEEN]       = BUILD_POLICY(U32),
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_SEQ_UNEXP_SEEN] = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_bridge_cfm_cc_peer_status);

static const NLAPolicy rtnl_bridge_cfm_policies[] = {
        [IFLA_BRIDGE_CFM_MEP_CREATE]          = BUILD_POLICY_NESTED(rtnl_bridge_cfm_mep_create),
        [IFLA_BRIDGE_CFM_MEP_DELETE]          = BUILD_POLICY_NESTED(rtnl_bridge_cfm_mep_delete),
        [IFLA_BRIDGE_CFM_MEP_CONFIG]          = BUILD_POLICY_NESTED(rtnl_bridge_cfm_mep_config),
        [IFLA_BRIDGE_CFM_CC_CONFIG]           = BUILD_POLICY_NESTED(rtnl_bridge_cfm_cc_config),
        [IFLA_BRIDGE_CFM_CC_PEER_MEP_ADD]     = BUILD_POLICY_NESTED(rtnl_bridge_cfm_cc_peer_mep),
        [IFLA_BRIDGE_CFM_CC_PEER_MEP_REMOVE]  = BUILD_POLICY_NESTED(rtnl_bridge_cfm_cc_peer_mep),
        [IFLA_BRIDGE_CFM_CC_RDI]              = BUILD_POLICY_NESTED(rtnl_bridge_cfm_cc_rdi),
        [IFLA_BRIDGE_CFM_CC_CCM_TX]           = BUILD_POLICY_NESTED(rtnl_bridge_cfm_cc_ccm_tx),
        [IFLA_BRIDGE_CFM_MEP_CREATE_INFO]     = BUILD_POLICY_NESTED(rtnl_bridge_cfm_mep_create),
        [IFLA_BRIDGE_CFM_MEP_CONFIG_INFO]     = BUILD_POLICY_NESTED(rtnl_bridge_cfm_mep_config),
        [IFLA_BRIDGE_CFM_CC_CONFIG_INFO]      = BUILD_POLICY_NESTED(rtnl_bridge_cfm_cc_config),
        [IFLA_BRIDGE_CFM_CC_RDI_INFO]         = BUILD_POLICY_NESTED(rtnl_bridge_cfm_cc_rdi),
        [IFLA_BRIDGE_CFM_CC_CCM_TX_INFO]      = BUILD_POLICY_NESTED(rtnl_bridge_cfm_cc_ccm_tx),
        [IFLA_BRIDGE_CFM_CC_PEER_MEP_INFO]    = BUILD_POLICY_NESTED(rtnl_bridge_cfm_cc_peer_mep),
        [IFLA_BRIDGE_CFM_MEP_STATUS_INFO]     = BUILD_POLICY_NESTED(rtnl_bridge_cfm_mep_status),
        [IFLA_BRIDGE_CFM_CC_PEER_STATUS_INFO] = BUILD_POLICY_NESTED(rtnl_bridge_cfm_cc_peer_status),
};

DEFINE_POLICY_SET(rtnl_bridge_cfm);

static const NLAPolicy rtnl_af_spec_bridge_policies[] = {
        [IFLA_BRIDGE_FLAGS]            = BUILD_POLICY(U16),
        [IFLA_BRIDGE_MODE]             = BUILD_POLICY(U16),
        [IFLA_BRIDGE_VLAN_INFO]        = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct bridge_vlan_info)),
        [IFLA_BRIDGE_VLAN_TUNNEL_INFO] = BUILD_POLICY_NESTED(rtnl_bridge_vlan_tunnel_info),
        [IFLA_BRIDGE_MRP]              = BUILD_POLICY_NESTED(rtnl_bridge_mrp),
        [IFLA_BRIDGE_CFM]              = BUILD_POLICY_NESTED(rtnl_bridge_cfm),
};

static const NLAPolicySetUnionElement rtnl_af_spec_policy_set_union_elements[] = {
        BUILD_UNION_ELEMENT_BY_FAMILY(AF_UNSPEC, rtnl_af_spec_unspec),
        BUILD_UNION_ELEMENT_BY_FAMILY(AF_BRIDGE, rtnl_af_spec_bridge),
};

DEFINE_POLICY_SET_UNION(rtnl_af_spec, 0);

static const NLAPolicy rtnl_prop_list_policies[] = {
        [IFLA_ALT_IFNAME]       = BUILD_POLICY_WITH_SIZE(STRING, ALTIFNAMSIZ - 1),
};

DEFINE_POLICY_SET(rtnl_prop_list);

static const NLAPolicy rtnl_vf_vlan_list_policies[] = {
        [IFLA_VF_VLAN_INFO]  = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_vf_vlan_info)),
};

DEFINE_POLICY_SET(rtnl_vf_vlan_list);

static const NLAPolicy rtnl_vf_info_policies[] = {
        [IFLA_VF_MAC]           = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_vf_mac)),
        [IFLA_VF_VLAN]          = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_vf_vlan)),
        [IFLA_VF_VLAN_LIST]     = BUILD_POLICY_NESTED(rtnl_vf_vlan_list),
        [IFLA_VF_TX_RATE]       = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_vf_tx_rate)),
        [IFLA_VF_SPOOFCHK]      = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_vf_spoofchk)),
        [IFLA_VF_RATE]          = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_vf_rate)),
        [IFLA_VF_LINK_STATE]    = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_vf_link_state)),
        [IFLA_VF_RSS_QUERY_EN]  = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_vf_rss_query_en)),
        [IFLA_VF_TRUST]         = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_vf_trust)),
        [IFLA_VF_IB_NODE_GUID]  = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_vf_guid)),
        [IFLA_VF_IB_PORT_GUID]  = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_vf_guid)),
};

DEFINE_POLICY_SET(rtnl_vf_info);

static const NLAPolicy rtnl_vfinfo_list_policies[] = {
        [IFLA_VF_INFO] = BUILD_POLICY_NESTED(rtnl_vf_info),
};

DEFINE_POLICY_SET(rtnl_vfinfo_list);

static const NLAPolicy rtnl_vf_port_policies[] = {
        [IFLA_PORT_VF]            = BUILD_POLICY(U32),
        [IFLA_PORT_PROFILE]       = BUILD_POLICY(STRING),
        [IFLA_PORT_VSI_TYPE]      = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct ifla_port_vsi)),
        [IFLA_PORT_INSTANCE_UUID] = BUILD_POLICY_WITH_SIZE(BINARY, PORT_UUID_MAX),
        [IFLA_PORT_HOST_UUID]     = BUILD_POLICY_WITH_SIZE(BINARY, PORT_UUID_MAX),
        [IFLA_PORT_REQUEST]       = BUILD_POLICY(U8),
        [IFLA_PORT_RESPONSE]      = BUILD_POLICY(U16),
};

DEFINE_POLICY_SET(rtnl_vf_port);

static const NLAPolicy rtnl_vf_ports_policies[] = {
        [IFLA_VF_PORT] = BUILD_POLICY_NESTED(rtnl_vf_port),
};

DEFINE_POLICY_SET(rtnl_vf_ports);

static const NLAPolicy rtnl_xdp_policies[] = {
        [IFLA_XDP_FD]          = BUILD_POLICY(S32),
        [IFLA_XDP_ATTACHED]    = BUILD_POLICY(U8),
        [IFLA_XDP_FLAGS]       = BUILD_POLICY(U32),
        [IFLA_XDP_PROG_ID]     = BUILD_POLICY(U32),
        [IFLA_XDP_DRV_PROG_ID] = BUILD_POLICY(U32),
        [IFLA_XDP_SKB_PROG_ID] = BUILD_POLICY(U32),
        [IFLA_XDP_HW_PROG_ID]  = BUILD_POLICY(U32),
        [IFLA_XDP_EXPECTED_FD] = BUILD_POLICY(S32),
};

DEFINE_POLICY_SET(rtnl_xdp);

static const NLAPolicy rtnl_proto_down_reason_policies[] = {
        [IFLA_PROTO_DOWN_REASON_MASK]  = BUILD_POLICY(U32),
        [IFLA_PROTO_DOWN_REASON_VALUE] = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_proto_down_reason);

static const NLAPolicy rtnl_link_policies[] = {
        [IFLA_ADDRESS]             = BUILD_POLICY(ETHER_ADDR),
        [IFLA_BROADCAST]           = BUILD_POLICY(ETHER_ADDR),
        [IFLA_IFNAME]              = BUILD_POLICY_WITH_SIZE(STRING, IFNAMSIZ - 1),
        [IFLA_MTU]                 = BUILD_POLICY(U32),
        [IFLA_LINK]                = BUILD_POLICY(U32),
        [IFLA_QDISC]               = BUILD_POLICY(STRING),
        [IFLA_STATS]               = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct rtnl_link_stats)),
        [IFLA_COST]                = { /* Not used. */ },
        [IFLA_PRIORITY]            = { /* Not used. */ },
        [IFLA_MASTER]              = BUILD_POLICY(U32),
        [IFLA_WIRELESS]            = { /* Used only by wext. */ },
        [IFLA_PROTINFO]            = BUILD_POLICY_NESTED_UNION_BY_FAMILY(rtnl_prot_info),
        [IFLA_TXQLEN]              = BUILD_POLICY(U32),
        [IFLA_MAP]                 = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct rtnl_link_ifmap)),
        [IFLA_WEIGHT]              = BUILD_POLICY(U32),
        [IFLA_OPERSTATE]           = BUILD_POLICY(U8),
        [IFLA_LINKMODE]            = BUILD_POLICY(U8),
        [IFLA_LINKINFO]            = BUILD_POLICY_NESTED(rtnl_link_info),
        [IFLA_NET_NS_PID]          = BUILD_POLICY(U32),
        [IFLA_IFALIAS]             = BUILD_POLICY_WITH_SIZE(STRING, IFALIASZ - 1),
        [IFLA_NUM_VF]              = BUILD_POLICY(U32),
        [IFLA_VFINFO_LIST]         = BUILD_POLICY_NESTED(rtnl_vfinfo_list),
        [IFLA_STATS64]             = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct rtnl_link_stats64)),
        [IFLA_VF_PORTS]            = BUILD_POLICY_NESTED(rtnl_vf_ports),
        [IFLA_PORT_SELF]           = BUILD_POLICY_NESTED(rtnl_vf_port),
        [IFLA_AF_SPEC]             = BUILD_POLICY_NESTED_UNION_BY_FAMILY(rtnl_af_spec),
        [IFLA_GROUP]               = BUILD_POLICY(U32),
        [IFLA_NET_NS_FD]           = BUILD_POLICY(U32),
        [IFLA_EXT_MASK]            = BUILD_POLICY(U32),
        [IFLA_PROMISCUITY]         = BUILD_POLICY(U32),
        [IFLA_NUM_TX_QUEUES]       = BUILD_POLICY(U32),
        [IFLA_NUM_RX_QUEUES]       = BUILD_POLICY(U32),
        [IFLA_CARRIER]             = BUILD_POLICY(U8),
        [IFLA_PHYS_PORT_ID]        = BUILD_POLICY_WITH_SIZE(BINARY, MAX_PHYS_ITEM_ID_LEN),
        [IFLA_CARRIER_CHANGES]     = BUILD_POLICY(U32),
        [IFLA_PHYS_SWITCH_ID]      = BUILD_POLICY_WITH_SIZE(BINARY, MAX_PHYS_ITEM_ID_LEN),
        [IFLA_LINK_NETNSID]        = BUILD_POLICY(S32),
        [IFLA_PHYS_PORT_NAME]      = BUILD_POLICY_WITH_SIZE(STRING, IFNAMSIZ - 1),
        [IFLA_PROTO_DOWN]          = BUILD_POLICY(U8),
        [IFLA_GSO_MAX_SEGS]        = BUILD_POLICY(U32),
        [IFLA_GSO_MAX_SIZE]        = BUILD_POLICY(U32),
        [IFLA_XDP]                 = BUILD_POLICY_NESTED(rtnl_xdp),
        [IFLA_EVENT]               = BUILD_POLICY(U32),
        [IFLA_NEW_NETNSID]         = BUILD_POLICY(S32),
        [IFLA_TARGET_NETNSID]      = BUILD_POLICY(S32),
        [IFLA_CARRIER_UP_COUNT]    = BUILD_POLICY(U32),
        [IFLA_CARRIER_DOWN_COUNT]  = BUILD_POLICY(U32),
        [IFLA_NEW_IFINDEX]         = BUILD_POLICY(S32),
        [IFLA_MIN_MTU]             = BUILD_POLICY(U32),
        [IFLA_MAX_MTU]             = BUILD_POLICY(U32),
        [IFLA_PROP_LIST]           = BUILD_POLICY_NESTED(rtnl_prop_list),
        [IFLA_ALT_IFNAME]          = BUILD_POLICY_WITH_SIZE(STRING, ALTIFNAMSIZ - 1),
        [IFLA_PERM_ADDRESS]        = BUILD_POLICY(ETHER_ADDR),
        [IFLA_PROTO_DOWN_REASON]   = BUILD_POLICY_NESTED(rtnl_proto_down_reason),
        [IFLA_PARENT_DEV_NAME]     = BUILD_POLICY(STRING),
        [IFLA_PARENT_DEV_BUS_NAME] = BUILD_POLICY(STRING),
};

DEFINE_POLICY_SET(rtnl_link);

/* IFA_FLAGS was defined in kernel 3.14, but we still support older
 * kernels where IFA_MAX is lower. */
static const NLAPolicy rtnl_address_policies[] = {
        [IFA_ADDRESS]           = BUILD_POLICY(IN_ADDR),
        [IFA_LOCAL]             = BUILD_POLICY(IN_ADDR),
        [IFA_LABEL]             = BUILD_POLICY_WITH_SIZE(STRING, IFNAMSIZ - 1),
        [IFA_BROADCAST]         = BUILD_POLICY(IN_ADDR),
        [IFA_ANYCAST]           = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in6_addr)),
        [IFA_CACHEINFO]         = BUILD_POLICY_WITH_SIZE(CACHE_INFO, sizeof(struct ifa_cacheinfo)),
        [IFA_MULTICAST]         = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in6_addr)),
        [IFA_FLAGS]             = BUILD_POLICY(U32),
        [IFA_RT_PRIORITY]       = BUILD_POLICY(U32),
        [IFA_TARGET_NETNSID]    = BUILD_POLICY(S32),
};

DEFINE_POLICY_SET(rtnl_address);

/* RTM_METRICS --- array of struct rtattr with types of RTAX_* */

static const NLAPolicy rtnl_route_metrics_policies[] = {
        [RTAX_MTU]                = BUILD_POLICY(U32),
        [RTAX_WINDOW]             = BUILD_POLICY(U32),
        [RTAX_RTT]                = BUILD_POLICY(U32),
        [RTAX_RTTVAR]             = BUILD_POLICY(U32),
        [RTAX_SSTHRESH]           = BUILD_POLICY(U32),
        [RTAX_CWND]               = BUILD_POLICY(U32),
        [RTAX_ADVMSS]             = BUILD_POLICY(U32),
        [RTAX_REORDERING]         = BUILD_POLICY(U32),
        [RTAX_HOPLIMIT]           = BUILD_POLICY(U32),
        [RTAX_INITCWND]           = BUILD_POLICY(U32),
        [RTAX_FEATURES]           = BUILD_POLICY(U32),
        [RTAX_RTO_MIN]            = BUILD_POLICY(U32),
        [RTAX_INITRWND]           = BUILD_POLICY(U32),
        [RTAX_QUICKACK]           = BUILD_POLICY(U32),
        [RTAX_CC_ALGO]            = BUILD_POLICY(STRING),
        [RTAX_FASTOPEN_NO_COOKIE] = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_route_metrics);

static const NLAPolicy rtnl_route_policies[] = {
        [RTA_DST]               = BUILD_POLICY(IN_ADDR),
        [RTA_SRC]               = BUILD_POLICY(IN_ADDR),
        [RTA_IIF]               = BUILD_POLICY(U32),
        [RTA_OIF]               = BUILD_POLICY(U32),
        [RTA_GATEWAY]           = BUILD_POLICY(IN_ADDR),
        [RTA_PRIORITY]          = BUILD_POLICY(U32),
        [RTA_PREFSRC]           = BUILD_POLICY(IN_ADDR),
        [RTA_METRICS]           = BUILD_POLICY_NESTED(rtnl_route_metrics),
        [RTA_MULTIPATH]         = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct rtnexthop)),
        [RTA_FLOW]              = BUILD_POLICY(U32),
        [RTA_CACHEINFO]         = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct rta_cacheinfo)),
        [RTA_TABLE]             = BUILD_POLICY(U32),
        [RTA_MARK]              = BUILD_POLICY(U32),
        [RTA_MFC_STATS]         = BUILD_POLICY(U64),
        [RTA_VIA]               = BUILD_POLICY(BINARY), /* See struct rtvia */
        [RTA_NEWDST]            = BUILD_POLICY(U32),
        [RTA_PREF]              = BUILD_POLICY(U8),
        [RTA_ENCAP_TYPE]        = BUILD_POLICY(U16),
        [RTA_ENCAP]             = { .type = NETLINK_TYPE_NESTED }, /* Multiple type systems i.e. LWTUNNEL_ENCAP_MPLS/LWTUNNEL_ENCAP_IP/LWTUNNEL_ENCAP_ILA etc... */
        [RTA_EXPIRES]           = BUILD_POLICY(U32),
        [RTA_UID]               = BUILD_POLICY(U32),
        [RTA_TTL_PROPAGATE]     = BUILD_POLICY(U8),
        [RTA_IP_PROTO]          = BUILD_POLICY(U8),
        [RTA_SPORT]             = BUILD_POLICY(U16),
        [RTA_DPORT]             = BUILD_POLICY(U16),
        [RTA_NH_ID]             = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_route);

static const NLAPolicy rtnl_neigh_policies[] = {
        [NDA_DST]               = BUILD_POLICY(IN_ADDR),
        [NDA_LLADDR]            = BUILD_POLICY(ETHER_ADDR),
        [NDA_CACHEINFO]         = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct nda_cacheinfo)),
        [NDA_PROBES]            = BUILD_POLICY(U32),
        [NDA_VLAN]              = BUILD_POLICY(U16),
        [NDA_PORT]              = BUILD_POLICY(U16),
        [NDA_VNI]               = BUILD_POLICY(U32),
        [NDA_IFINDEX]           = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_neigh);

static const NLAPolicy rtnl_addrlabel_policies[] = {
        [IFAL_ADDRESS]         = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in6_addr)),
        [IFAL_LABEL]           = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_addrlabel);

static const NLAPolicy rtnl_routing_policy_rule_policies[] = {
        [FRA_DST]                 = BUILD_POLICY(IN_ADDR),
        [FRA_SRC]                 = BUILD_POLICY(IN_ADDR),
        [FRA_IIFNAME]             = BUILD_POLICY(STRING),
        [FRA_GOTO]                = BUILD_POLICY(U32),
        [FRA_PRIORITY]            = BUILD_POLICY(U32),
        [FRA_FWMARK]              = BUILD_POLICY(U32),
        [FRA_FLOW]                = BUILD_POLICY(U32),
        [FRA_TUN_ID]              = BUILD_POLICY(U64),
        [FRA_SUPPRESS_IFGROUP]    = BUILD_POLICY(U32),
        [FRA_SUPPRESS_PREFIXLEN]  = BUILD_POLICY(U32),
        [FRA_TABLE]               = BUILD_POLICY(U32),
        [FRA_FWMASK]              = BUILD_POLICY(U32),
        [FRA_OIFNAME]             = BUILD_POLICY(STRING),
        [FRA_PAD]                 = BUILD_POLICY(U32),
        [FRA_L3MDEV]              = BUILD_POLICY(U8),
        [FRA_UID_RANGE]           = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct fib_rule_uid_range)),
        [FRA_PROTOCOL]            = BUILD_POLICY(U8),
        [FRA_IP_PROTO]            = BUILD_POLICY(U8),
        [FRA_SPORT_RANGE]         = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct fib_rule_port_range)),
        [FRA_DPORT_RANGE]         = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct fib_rule_port_range)),
};

DEFINE_POLICY_SET(rtnl_routing_policy_rule);

static const NLAPolicy rtnl_nexthop_policies[] = {
        [NHA_ID]                  = BUILD_POLICY(U32),
        [NHA_GROUP]               = { /* array of struct nexthop_grp */ },
        [NHA_GROUP_TYPE]          = BUILD_POLICY(U16),
        [NHA_BLACKHOLE]           = BUILD_POLICY(FLAG),
        [NHA_OIF]                 = BUILD_POLICY(U32),
        [NHA_GATEWAY]             = BUILD_POLICY(IN_ADDR),
        [NHA_ENCAP_TYPE]          = BUILD_POLICY(U16),
        [NHA_ENCAP]               = { .type = NETLINK_TYPE_NESTED },
        [NHA_GROUPS]              = BUILD_POLICY(FLAG),
        [NHA_MASTER]              = BUILD_POLICY(U32),
        [NHA_FDB]                 = BUILD_POLICY(FLAG),
};

DEFINE_POLICY_SET(rtnl_nexthop);

static const NLAPolicy rtnl_tca_option_data_cake_policies[] = {
        [TCA_CAKE_BASE_RATE64]   = BUILD_POLICY(U64),
        [TCA_CAKE_DIFFSERV_MODE] = BUILD_POLICY(U32),
        [TCA_CAKE_ATM]           = BUILD_POLICY(U32),
        [TCA_CAKE_FLOW_MODE]     = BUILD_POLICY(U32),
        [TCA_CAKE_OVERHEAD]      = BUILD_POLICY(S32),
        [TCA_CAKE_RTT]           = BUILD_POLICY(U32),
        [TCA_CAKE_TARGET]        = BUILD_POLICY(U32),
        [TCA_CAKE_AUTORATE]      = BUILD_POLICY(U32),
        [TCA_CAKE_MEMORY]        = BUILD_POLICY(U32),
        [TCA_CAKE_NAT]           = BUILD_POLICY(U32),
        [TCA_CAKE_RAW]           = BUILD_POLICY(U32),
        [TCA_CAKE_WASH]          = BUILD_POLICY(U32),
        [TCA_CAKE_MPU]           = BUILD_POLICY(U32),
        [TCA_CAKE_INGRESS]       = BUILD_POLICY(U32),
        [TCA_CAKE_ACK_FILTER]    = BUILD_POLICY(U32),
        [TCA_CAKE_SPLIT_GSO]     = BUILD_POLICY(U32),
        [TCA_CAKE_FWMARK]        = BUILD_POLICY(U32),
};

static const NLAPolicy rtnl_tca_option_data_codel_policies[] = {
        [TCA_CODEL_TARGET]        = BUILD_POLICY(U32),
        [TCA_CODEL_LIMIT]         = BUILD_POLICY(U32),
        [TCA_CODEL_INTERVAL]      = BUILD_POLICY(U32),
        [TCA_CODEL_ECN]           = BUILD_POLICY(U32),
        [TCA_CODEL_CE_THRESHOLD]  = BUILD_POLICY(U32),
};

static const NLAPolicy rtnl_tca_option_data_drr_policies[] = {
        [TCA_DRR_QUANTUM] = BUILD_POLICY(U32),
};

static const NLAPolicy rtnl_tca_option_data_ets_quanta_policies[] = {
        [TCA_ETS_QUANTA_BAND] = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_tca_option_data_ets_quanta);

static const NLAPolicy rtnl_tca_option_data_ets_prio_policies[] = {
        [TCA_ETS_PRIOMAP_BAND] = BUILD_POLICY(U8),
};

DEFINE_POLICY_SET(rtnl_tca_option_data_ets_prio);

static const NLAPolicy rtnl_tca_option_data_ets_policies[] = {
        [TCA_ETS_NBANDS]      = BUILD_POLICY(U8),
        [TCA_ETS_NSTRICT]     = BUILD_POLICY(U8),
        [TCA_ETS_QUANTA]      = BUILD_POLICY_NESTED(rtnl_tca_option_data_ets_quanta),
        [TCA_ETS_PRIOMAP]     = BUILD_POLICY_NESTED(rtnl_tca_option_data_ets_prio),
        [TCA_ETS_QUANTA_BAND] = BUILD_POLICY(U32),
};

static const NLAPolicy rtnl_tca_option_data_fq_policies[] = {
        [TCA_FQ_PLIMIT]             = BUILD_POLICY(U32),
        [TCA_FQ_FLOW_PLIMIT]        = BUILD_POLICY(U32),
        [TCA_FQ_QUANTUM]            = BUILD_POLICY(U32),
        [TCA_FQ_INITIAL_QUANTUM]    = BUILD_POLICY(U32),
        [TCA_FQ_RATE_ENABLE]        = BUILD_POLICY(U32),
        [TCA_FQ_FLOW_DEFAULT_RATE]  = BUILD_POLICY(U32),
        [TCA_FQ_FLOW_MAX_RATE]      = BUILD_POLICY(U32),
        [TCA_FQ_BUCKETS_LOG]        = BUILD_POLICY(U32),
        [TCA_FQ_FLOW_REFILL_DELAY]  = BUILD_POLICY(U32),
        [TCA_FQ_LOW_RATE_THRESHOLD] = BUILD_POLICY(U32),
        [TCA_FQ_CE_THRESHOLD]       = BUILD_POLICY(U32),
        [TCA_FQ_ORPHAN_MASK]        = BUILD_POLICY(U32),
};

static const NLAPolicy rtnl_tca_option_data_fq_codel_policies[] = {
        [TCA_FQ_CODEL_TARGET]          = BUILD_POLICY(U32),
        [TCA_FQ_CODEL_LIMIT]           = BUILD_POLICY(U32),
        [TCA_FQ_CODEL_INTERVAL]        = BUILD_POLICY(U32),
        [TCA_FQ_CODEL_ECN]             = BUILD_POLICY(U32),
        [TCA_FQ_CODEL_FLOWS]           = BUILD_POLICY(U32),
        [TCA_FQ_CODEL_QUANTUM]         = BUILD_POLICY(U32),
        [TCA_FQ_CODEL_CE_THRESHOLD]    = BUILD_POLICY(U32),
        [TCA_FQ_CODEL_DROP_BATCH_SIZE] = BUILD_POLICY(U32),
        [TCA_FQ_CODEL_MEMORY_LIMIT]    = BUILD_POLICY(U32),
};

static const NLAPolicy rtnl_tca_option_data_fq_pie_policies[] = {
        [TCA_FQ_PIE_LIMIT]   = BUILD_POLICY(U32),
};

static const NLAPolicy rtnl_tca_option_data_gred_policies[] = {
        [TCA_GRED_DPS] = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct tc_gred_sopt)),
};

static const NLAPolicy rtnl_tca_option_data_hhf_policies[] = {
        [TCA_HHF_BACKLOG_LIMIT] = BUILD_POLICY(U32),
};

static const NLAPolicy rtnl_tca_option_data_htb_policies[] = {
        [TCA_HTB_PARMS]  = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct tc_htb_opt)),
        [TCA_HTB_INIT]   = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct tc_htb_glob)),
        [TCA_HTB_CTAB]   = BUILD_POLICY_WITH_SIZE(BINARY, TC_RTAB_SIZE),
        [TCA_HTB_RTAB]   = BUILD_POLICY_WITH_SIZE(BINARY, TC_RTAB_SIZE),
        [TCA_HTB_RATE64] = BUILD_POLICY(U64),
        [TCA_HTB_CEIL64] = BUILD_POLICY(U64),
};

static const NLAPolicy rtnl_tca_option_data_pie_policies[] = {
        [TCA_PIE_LIMIT]   = BUILD_POLICY(U32),
};

static const NLAPolicy rtnl_tca_option_data_qfq_policies[] = {
        [TCA_QFQ_WEIGHT] = BUILD_POLICY(U32),
        [TCA_QFQ_LMAX]   = BUILD_POLICY(U32),
};

static const NLAPolicy rtnl_tca_option_data_sfb_policies[] = {
        [TCA_SFB_PARMS] = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct tc_sfb_qopt)),
};

static const NLAPolicy rtnl_tca_option_data_tbf_policies[] = {
        [TCA_TBF_PARMS]   = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct tc_tbf_qopt)),
        [TCA_TBF_RTAB]    = BUILD_POLICY_WITH_SIZE(BINARY, TC_RTAB_SIZE),
        [TCA_TBF_PTAB]    = BUILD_POLICY_WITH_SIZE(BINARY, TC_RTAB_SIZE),
        [TCA_TBF_RATE64]  = BUILD_POLICY(U64),
        [TCA_TBF_PRATE64] = BUILD_POLICY(U64),
        [TCA_TBF_BURST]   = BUILD_POLICY(U32),
        [TCA_TBF_PBURST]  = BUILD_POLICY(U32),
};

static const NLAPolicySetUnionElement rtnl_tca_option_data_policy_set_union_elements[] = {
        BUILD_UNION_ELEMENT_BY_STRING("cake",     rtnl_tca_option_data_cake),
        BUILD_UNION_ELEMENT_BY_STRING("codel",    rtnl_tca_option_data_codel),
        BUILD_UNION_ELEMENT_BY_STRING("drr",      rtnl_tca_option_data_drr),
        BUILD_UNION_ELEMENT_BY_STRING("ets",      rtnl_tca_option_data_ets),
        BUILD_UNION_ELEMENT_BY_STRING("fq",       rtnl_tca_option_data_fq),
        BUILD_UNION_ELEMENT_BY_STRING("fq_codel", rtnl_tca_option_data_fq_codel),
        BUILD_UNION_ELEMENT_BY_STRING("fq_pie",   rtnl_tca_option_data_fq_pie),
        BUILD_UNION_ELEMENT_BY_STRING("gred",     rtnl_tca_option_data_gred),
        BUILD_UNION_ELEMENT_BY_STRING("hhf",      rtnl_tca_option_data_hhf),
        BUILD_UNION_ELEMENT_BY_STRING("htb",      rtnl_tca_option_data_htb),
        BUILD_UNION_ELEMENT_BY_STRING("pie",      rtnl_tca_option_data_pie),
        BUILD_UNION_ELEMENT_BY_STRING("qfq",      rtnl_tca_option_data_qfq),
        BUILD_UNION_ELEMENT_BY_STRING("sfb",      rtnl_tca_option_data_sfb),
        BUILD_UNION_ELEMENT_BY_STRING("tbf",      rtnl_tca_option_data_tbf),
};

DEFINE_POLICY_SET_UNION(rtnl_tca_option_data, TCA_KIND);

static const NLAPolicy rtnl_tca_policies[] = {
        [TCA_KIND]           = BUILD_POLICY(STRING),
        [TCA_OPTIONS]        = BUILD_POLICY_NESTED_UNION_BY_STRING(rtnl_tca_option_data),
        [TCA_INGRESS_BLOCK]  = BUILD_POLICY(U32),
        [TCA_EGRESS_BLOCK]   = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_tca);

static const NLAPolicy rtnl_mdb_policies[] = {
        [MDBA_SET_ENTRY]     = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct br_port_msg)),
};

DEFINE_POLICY_SET(rtnl_mdb);

static const NLAPolicy rtnl_nsid_policies[] = {
        [NETNSA_FD]         = BUILD_POLICY(S32),
        [NETNSA_NSID]       = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(rtnl_nsid);

static const NLAPolicy rtnl_policies[] = {
        [RTM_NEWLINK]      = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_link, sizeof(struct ifinfomsg)),
        [RTM_DELLINK]      = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_link, sizeof(struct ifinfomsg)),
        [RTM_GETLINK]      = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_link, sizeof(struct ifinfomsg)),
        [RTM_SETLINK]      = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_link, sizeof(struct ifinfomsg)),
        [RTM_NEWLINKPROP]  = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_link, sizeof(struct ifinfomsg)),
        [RTM_DELLINKPROP]  = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_link, sizeof(struct ifinfomsg)),
        [RTM_GETLINKPROP]  = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_link, sizeof(struct ifinfomsg)),
        [RTM_NEWADDR]      = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_address, sizeof(struct ifaddrmsg)),
        [RTM_DELADDR]      = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_address, sizeof(struct ifaddrmsg)),
        [RTM_GETADDR]      = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_address, sizeof(struct ifaddrmsg)),
        [RTM_NEWROUTE]     = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_route, sizeof(struct rtmsg)),
        [RTM_DELROUTE]     = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_route, sizeof(struct rtmsg)),
        [RTM_GETROUTE]     = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_route, sizeof(struct rtmsg)),
        [RTM_NEWNEIGH]     = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_neigh, sizeof(struct ndmsg)),
        [RTM_DELNEIGH]     = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_neigh, sizeof(struct ndmsg)),
        [RTM_GETNEIGH]     = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_neigh, sizeof(struct ndmsg)),
        [RTM_NEWADDRLABEL] = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_addrlabel, sizeof(struct ifaddrlblmsg)),
        [RTM_DELADDRLABEL] = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_addrlabel, sizeof(struct ifaddrlblmsg)),
        [RTM_GETADDRLABEL] = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_addrlabel, sizeof(struct ifaddrlblmsg)),
        [RTM_NEWRULE]      = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_routing_policy_rule, sizeof(struct fib_rule_hdr)),
        [RTM_DELRULE]      = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_routing_policy_rule, sizeof(struct fib_rule_hdr)),
        [RTM_GETRULE]      = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_routing_policy_rule, sizeof(struct fib_rule_hdr)),
        [RTM_NEWNEXTHOP]   = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_nexthop, sizeof(struct nhmsg)),
        [RTM_DELNEXTHOP]   = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_nexthop, sizeof(struct nhmsg)),
        [RTM_GETNEXTHOP]   = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_nexthop, sizeof(struct nhmsg)),
        [RTM_NEWQDISC]     = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_tca, sizeof(struct tcmsg)),
        [RTM_DELQDISC]     = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_tca, sizeof(struct tcmsg)),
        [RTM_GETQDISC]     = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_tca, sizeof(struct tcmsg)),
        [RTM_NEWTCLASS]    = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_tca, sizeof(struct tcmsg)),
        [RTM_DELTCLASS]    = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_tca, sizeof(struct tcmsg)),
        [RTM_GETTCLASS]    = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_tca, sizeof(struct tcmsg)),
        [RTM_NEWMDB]       = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_mdb, sizeof(struct br_port_msg)),
        [RTM_DELMDB]       = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_mdb, sizeof(struct br_port_msg)),
        [RTM_GETMDB]       = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_mdb, sizeof(struct br_port_msg)),
        [RTM_NEWNSID]      = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_nsid, sizeof(struct rtgenmsg)),
        [RTM_DELNSID]      = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_nsid, sizeof(struct rtgenmsg)),
        [RTM_GETNSID]      = BUILD_POLICY_NESTED_WITH_SIZE(rtnl_nsid, sizeof(struct rtgenmsg)),
};

DEFINE_POLICY_SET(rtnl);

const NLAPolicy *rtnl_get_policy(uint16_t nlmsg_type) {
        return policy_set_get_policy(&rtnl_policy_set, nlmsg_type);
}
