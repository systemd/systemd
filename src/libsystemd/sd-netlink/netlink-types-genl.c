/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/batman_adv.h>
#include <linux/fou.h>
#include <linux/genetlink.h>
#include <linux/if.h>
#include <linux/if_macsec.h>
#include <linux/l2tp.h>
#include <linux/nl80211.h>
#include <linux/wireguard.h>

#include "missing_network.h"
#include "netlink-genl.h"
#include "netlink-types-internal.h"

/***************** genl ctrl type systems *****************/
static const NLAPolicy genl_ctrl_mcast_group_policies[] = {
        [CTRL_ATTR_MCAST_GRP_NAME]  = BUILD_POLICY(STRING),
        [CTRL_ATTR_MCAST_GRP_ID]    = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(genl_ctrl_mcast_group);

static const NLAPolicy genl_ctrl_ops_policies[] = {
        [CTRL_ATTR_OP_ID]           = BUILD_POLICY(U32),
        [CTRL_ATTR_OP_FLAGS]        = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(genl_ctrl_ops);

static const NLAPolicy genl_ctrl_policies[] = {
        [CTRL_ATTR_FAMILY_ID]    = BUILD_POLICY(U16),
        [CTRL_ATTR_FAMILY_NAME]  = BUILD_POLICY(STRING),
        [CTRL_ATTR_VERSION]      = BUILD_POLICY(U32),
        [CTRL_ATTR_HDRSIZE]      = BUILD_POLICY(U32),
        [CTRL_ATTR_MAXATTR]      = BUILD_POLICY(U32),
        [CTRL_ATTR_OPS]          = BUILD_POLICY_NESTED(genl_ctrl_ops),
        [CTRL_ATTR_MCAST_GROUPS] = BUILD_POLICY_NESTED(genl_ctrl_mcast_group),
        /*
        [CTRL_ATTR_POLICY]       = { .type = NETLINK_TYPE_NESTED, },
        [CTRL_ATTR_OP_POLICY]    = { .type = NETLINK_TYPE_NESTED, }
        */
        [CTRL_ATTR_OP]           = BUILD_POLICY(U32),
};

/***************** genl batadv type systems *****************/
static const NLAPolicy genl_batadv_policies[] = {
        [BATADV_ATTR_VERSION]                       = BUILD_POLICY(STRING),
        [BATADV_ATTR_ALGO_NAME]                     = BUILD_POLICY(STRING),
        [BATADV_ATTR_MESH_IFINDEX]                  = BUILD_POLICY(U32),
        [BATADV_ATTR_MESH_IFNAME]                   = BUILD_POLICY_WITH_SIZE(STRING, IFNAMSIZ),
        [BATADV_ATTR_MESH_ADDRESS]                  = BUILD_POLICY_WITH_SIZE(ETHER_ADDR, ETH_ALEN),
        [BATADV_ATTR_HARD_IFINDEX]                  = BUILD_POLICY(U32),
        [BATADV_ATTR_HARD_IFNAME]                   = BUILD_POLICY_WITH_SIZE(STRING, IFNAMSIZ),
        [BATADV_ATTR_HARD_ADDRESS]                  = BUILD_POLICY_WITH_SIZE(ETHER_ADDR, ETH_ALEN),
        [BATADV_ATTR_ORIG_ADDRESS]                  = BUILD_POLICY_WITH_SIZE(ETHER_ADDR, ETH_ALEN),
        [BATADV_ATTR_TPMETER_RESULT]                = BUILD_POLICY(U8),
        [BATADV_ATTR_TPMETER_TEST_TIME]             = BUILD_POLICY(U32),
        [BATADV_ATTR_TPMETER_BYTES]                 = BUILD_POLICY(U64),
        [BATADV_ATTR_TPMETER_COOKIE]                = BUILD_POLICY(U32),
        [BATADV_ATTR_PAD]                           = BUILD_POLICY(UNSPEC),
        [BATADV_ATTR_ACTIVE]                        = BUILD_POLICY(FLAG),
        [BATADV_ATTR_TT_ADDRESS]                    = BUILD_POLICY_WITH_SIZE(ETHER_ADDR, ETH_ALEN),
        [BATADV_ATTR_TT_TTVN]                       = BUILD_POLICY(U8),
        [BATADV_ATTR_TT_LAST_TTVN]                  = BUILD_POLICY(U8),
        [BATADV_ATTR_TT_CRC32]                      = BUILD_POLICY(U32),
        [BATADV_ATTR_TT_VID]                        = BUILD_POLICY(U16),
        [BATADV_ATTR_TT_FLAGS]                      = BUILD_POLICY(U32),
        [BATADV_ATTR_FLAG_BEST]                     = BUILD_POLICY(FLAG),
        [BATADV_ATTR_LAST_SEEN_MSECS]               = BUILD_POLICY(U32),
        [BATADV_ATTR_NEIGH_ADDRESS]                 = BUILD_POLICY_WITH_SIZE(ETHER_ADDR, ETH_ALEN),
        [BATADV_ATTR_TQ]                            = BUILD_POLICY(U8),
        [BATADV_ATTR_THROUGHPUT]                    = BUILD_POLICY(U32),
        [BATADV_ATTR_BANDWIDTH_UP]                  = BUILD_POLICY(U32),
        [BATADV_ATTR_BANDWIDTH_DOWN]                = BUILD_POLICY(U32),
        [BATADV_ATTR_ROUTER]                        = BUILD_POLICY_WITH_SIZE(ETHER_ADDR, ETH_ALEN),
        [BATADV_ATTR_BLA_OWN]                       = BUILD_POLICY(FLAG),
        [BATADV_ATTR_BLA_ADDRESS]                   = BUILD_POLICY_WITH_SIZE(ETHER_ADDR, ETH_ALEN),
        [BATADV_ATTR_BLA_VID]                       = BUILD_POLICY(U16),
        [BATADV_ATTR_BLA_BACKBONE]                  = BUILD_POLICY_WITH_SIZE(ETHER_ADDR, ETH_ALEN),
        [BATADV_ATTR_BLA_CRC]                       = BUILD_POLICY(U16),
        [BATADV_ATTR_DAT_CACHE_IP4ADDRESS]          = BUILD_POLICY(U32),
        [BATADV_ATTR_DAT_CACHE_HWADDRESS]           = BUILD_POLICY_WITH_SIZE(ETHER_ADDR, ETH_ALEN),
        [BATADV_ATTR_DAT_CACHE_VID]                 = BUILD_POLICY(U16),
        [BATADV_ATTR_MCAST_FLAGS]                   = BUILD_POLICY(U32),
        [BATADV_ATTR_MCAST_FLAGS_PRIV]              = BUILD_POLICY(U32),
        [BATADV_ATTR_VLANID]                        = BUILD_POLICY(U16),
        [BATADV_ATTR_AGGREGATED_OGMS_ENABLED]       = BUILD_POLICY(U8),
        [BATADV_ATTR_AP_ISOLATION_ENABLED]          = BUILD_POLICY(U8),
        [BATADV_ATTR_ISOLATION_MARK]                = BUILD_POLICY(U32),
        [BATADV_ATTR_ISOLATION_MASK]                = BUILD_POLICY(U32),
        [BATADV_ATTR_BONDING_ENABLED]               = BUILD_POLICY(U8),
        [BATADV_ATTR_BRIDGE_LOOP_AVOIDANCE_ENABLED] = BUILD_POLICY(U8),
        [BATADV_ATTR_DISTRIBUTED_ARP_TABLE_ENABLED] = BUILD_POLICY(U8),
        [BATADV_ATTR_FRAGMENTATION_ENABLED]         = BUILD_POLICY(U8),
        [BATADV_ATTR_GW_BANDWIDTH_DOWN]             = BUILD_POLICY(U32),
        [BATADV_ATTR_GW_BANDWIDTH_UP]               = BUILD_POLICY(U32),
        [BATADV_ATTR_GW_MODE]                       = BUILD_POLICY(U8),
        [BATADV_ATTR_GW_SEL_CLASS]                  = BUILD_POLICY(U32),
        [BATADV_ATTR_HOP_PENALTY]                   = BUILD_POLICY(U8),
        [BATADV_ATTR_LOG_LEVEL]                     = BUILD_POLICY(U32),
        [BATADV_ATTR_MULTICAST_FORCEFLOOD_ENABLED]  = BUILD_POLICY(U8),
        [BATADV_ATTR_MULTICAST_FANOUT]              = BUILD_POLICY(U32),
        [BATADV_ATTR_NETWORK_CODING_ENABLED]        = BUILD_POLICY(U8),
        [BATADV_ATTR_ORIG_INTERVAL]                 = BUILD_POLICY(U32),
        [BATADV_ATTR_ELP_INTERVAL]                  = BUILD_POLICY(U32),
        [BATADV_ATTR_THROUGHPUT_OVERRIDE]           = BUILD_POLICY(U32),
};

/***************** genl fou type systems *****************/
static const NLAPolicy genl_fou_policies[] = {
        [FOU_ATTR_PORT]              = BUILD_POLICY(U16),
        [FOU_ATTR_AF]                = BUILD_POLICY(U8),
        [FOU_ATTR_IPPROTO]           = BUILD_POLICY(U8),
        [FOU_ATTR_TYPE]              = BUILD_POLICY(U8),
        [FOU_ATTR_REMCSUM_NOPARTIAL] = BUILD_POLICY(FLAG),
        [FOU_ATTR_LOCAL_V4]          = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in_addr)),
        [FOU_ATTR_PEER_V4]           = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in_addr)),
        [FOU_ATTR_LOCAL_V6]          = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in6_addr)),
        [FOU_ATTR_PEER_V6]           = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in6_addr)),
        [FOU_ATTR_PEER_PORT]         = BUILD_POLICY(U16),
        [FOU_ATTR_IFINDEX]           = BUILD_POLICY(U32),
};

/***************** genl l2tp type systems *****************/
static const NLAPolicy genl_l2tp_policies[] = {
        [L2TP_ATTR_PW_TYPE]           = BUILD_POLICY(U16),
        [L2TP_ATTR_ENCAP_TYPE]        = BUILD_POLICY(U16),
        [L2TP_ATTR_OFFSET]            = BUILD_POLICY(U16),
        [L2TP_ATTR_DATA_SEQ]          = BUILD_POLICY(U16),
        [L2TP_ATTR_L2SPEC_TYPE]       = BUILD_POLICY(U8),
        [L2TP_ATTR_L2SPEC_LEN]        = BUILD_POLICY(U8),
        [L2TP_ATTR_PROTO_VERSION]     = BUILD_POLICY(U8),
        [L2TP_ATTR_IFNAME]            = BUILD_POLICY(STRING),
        [L2TP_ATTR_CONN_ID]           = BUILD_POLICY(U32),
        [L2TP_ATTR_PEER_CONN_ID]      = BUILD_POLICY(U32),
        [L2TP_ATTR_SESSION_ID]        = BUILD_POLICY(U32),
        [L2TP_ATTR_PEER_SESSION_ID]   = BUILD_POLICY(U32),
        [L2TP_ATTR_UDP_CSUM]          = BUILD_POLICY(U8),
        [L2TP_ATTR_VLAN_ID]           = BUILD_POLICY(U16),
        [L2TP_ATTR_RECV_SEQ]          = BUILD_POLICY(U8),
        [L2TP_ATTR_SEND_SEQ]          = BUILD_POLICY(U8),
        [L2TP_ATTR_LNS_MODE]          = BUILD_POLICY(U8),
        [L2TP_ATTR_USING_IPSEC]       = BUILD_POLICY(U8),
        [L2TP_ATTR_FD]                = BUILD_POLICY(U32),
        [L2TP_ATTR_IP_SADDR]          = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in_addr)),
        [L2TP_ATTR_IP_DADDR]          = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in_addr)),
        [L2TP_ATTR_UDP_SPORT]         = BUILD_POLICY(U16),
        [L2TP_ATTR_UDP_DPORT]         = BUILD_POLICY(U16),
        [L2TP_ATTR_IP6_SADDR]         = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in6_addr)),
        [L2TP_ATTR_IP6_DADDR]         = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in6_addr)),
        [L2TP_ATTR_UDP_ZERO_CSUM6_TX] = BUILD_POLICY(FLAG),
        [L2TP_ATTR_UDP_ZERO_CSUM6_RX] = BUILD_POLICY(FLAG),
};

/***************** genl macsec type systems *****************/
static const NLAPolicy genl_macsec_rxsc_policies[] = {
        [MACSEC_RXSC_ATTR_SCI] = BUILD_POLICY(U64),
};

DEFINE_POLICY_SET(genl_macsec_rxsc);

static const NLAPolicy genl_macsec_sa_policies[] = {
        [MACSEC_SA_ATTR_AN]     = BUILD_POLICY(U8),
        [MACSEC_SA_ATTR_ACTIVE] = BUILD_POLICY(U8),
        [MACSEC_SA_ATTR_PN]     = BUILD_POLICY(U32),
        [MACSEC_SA_ATTR_KEYID]  = BUILD_POLICY_WITH_SIZE(BINARY, MACSEC_KEYID_LEN),
        [MACSEC_SA_ATTR_KEY]    = BUILD_POLICY_WITH_SIZE(BINARY, MACSEC_MAX_KEY_LEN),
};

DEFINE_POLICY_SET(genl_macsec_sa);

static const NLAPolicy genl_macsec_policies[] = {
        [MACSEC_ATTR_IFINDEX]     = BUILD_POLICY(U32),
        [MACSEC_ATTR_RXSC_CONFIG] = BUILD_POLICY_NESTED(genl_macsec_rxsc),
        [MACSEC_ATTR_SA_CONFIG]   = BUILD_POLICY_NESTED(genl_macsec_sa),
};

/***************** genl NetLabel type systems *****************/
static const NLAPolicy genl_netlabel_policies[] = {
        [NLBL_UNLABEL_A_IPV4ADDR] = BUILD_POLICY(IN_ADDR),
        [NLBL_UNLABEL_A_IPV4MASK] = BUILD_POLICY(IN_ADDR),
        [NLBL_UNLABEL_A_IPV6ADDR] = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in6_addr)),
        [NLBL_UNLABEL_A_IPV6MASK] = BUILD_POLICY_WITH_SIZE(IN_ADDR, sizeof(struct in6_addr)),
        [NLBL_UNLABEL_A_IFACE]    = BUILD_POLICY_WITH_SIZE(STRING, IFNAMSIZ-1),
        [NLBL_UNLABEL_A_SECCTX]   = BUILD_POLICY(STRING),
};

/***************** genl nl80211 type systems *****************/
static const NLAPolicy genl_nl80211_policies[] = {
        [NL80211_ATTR_WIPHY]       = BUILD_POLICY(U32),
        [NL80211_ATTR_WIPHY_NAME]  = BUILD_POLICY(STRING),
        [NL80211_ATTR_IFINDEX]     = BUILD_POLICY(U32),
        [NL80211_ATTR_IFNAME]      = BUILD_POLICY_WITH_SIZE(STRING, IFNAMSIZ-1),
        [NL80211_ATTR_IFTYPE]      = BUILD_POLICY(U32),
        [NL80211_ATTR_MAC]         = BUILD_POLICY_WITH_SIZE(ETHER_ADDR, ETH_ALEN),
        [NL80211_ATTR_SSID]        = BUILD_POLICY_WITH_SIZE(BINARY, IEEE80211_MAX_SSID_LEN),
        [NL80211_ATTR_STATUS_CODE] = BUILD_POLICY(U16),
        [NL80211_ATTR_4ADDR]       = BUILD_POLICY(U8),
};

/***************** genl wireguard type systems *****************/
static const NLAPolicy genl_wireguard_allowedip_policies[] = {
        [WGALLOWEDIP_A_FAMILY]    = BUILD_POLICY(U16),
        [WGALLOWEDIP_A_IPADDR]    = BUILD_POLICY(IN_ADDR),
        [WGALLOWEDIP_A_CIDR_MASK] = BUILD_POLICY(U8),
};

DEFINE_POLICY_SET(genl_wireguard_allowedip);

static const NLAPolicy genl_wireguard_peer_policies[] = {
        [WGPEER_A_PUBLIC_KEY]                    = BUILD_POLICY_WITH_SIZE(BINARY, WG_KEY_LEN),
        [WGPEER_A_FLAGS]                         = BUILD_POLICY(U32),
        [WGPEER_A_PRESHARED_KEY]                 = BUILD_POLICY_WITH_SIZE(BINARY, WG_KEY_LEN),
        [WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL] = BUILD_POLICY(U16),
        [WGPEER_A_ENDPOINT]                      = BUILD_POLICY(SOCKADDR),
        [WGPEER_A_ALLOWEDIPS]                    = BUILD_POLICY_NESTED(genl_wireguard_allowedip),
};

DEFINE_POLICY_SET(genl_wireguard_peer);

static const NLAPolicy genl_wireguard_policies[] = {
        [WGDEVICE_A_IFINDEX]     = BUILD_POLICY(U32),
        [WGDEVICE_A_IFNAME]      = BUILD_POLICY_WITH_SIZE(STRING, IFNAMSIZ-1),
        [WGDEVICE_A_FLAGS]       = BUILD_POLICY(U32),
        [WGDEVICE_A_PRIVATE_KEY] = BUILD_POLICY_WITH_SIZE(BINARY, WG_KEY_LEN),
        [WGDEVICE_A_LISTEN_PORT] = BUILD_POLICY(U16),
        [WGDEVICE_A_FWMARK]      = BUILD_POLICY(U32),
        [WGDEVICE_A_PEERS]       = BUILD_POLICY_NESTED(genl_wireguard_peer),
};

/***************** genl families *****************/
static const NLAPolicySetUnionElement genl_policy_set_union_elements[] = {
        BUILD_UNION_ELEMENT_BY_STRING(CTRL_GENL_NAME,               genl_ctrl),
        BUILD_UNION_ELEMENT_BY_STRING(BATADV_NL_NAME,               genl_batadv),
        BUILD_UNION_ELEMENT_BY_STRING(FOU_GENL_NAME,                genl_fou),
        BUILD_UNION_ELEMENT_BY_STRING(L2TP_GENL_NAME,               genl_l2tp),
        BUILD_UNION_ELEMENT_BY_STRING(MACSEC_GENL_NAME,             genl_macsec),
        BUILD_UNION_ELEMENT_BY_STRING(NETLBL_NLTYPE_UNLABELED_NAME, genl_netlabel),
        BUILD_UNION_ELEMENT_BY_STRING(NL80211_GENL_NAME,            genl_nl80211),
        BUILD_UNION_ELEMENT_BY_STRING(WG_GENL_NAME,                 genl_wireguard),
};

/* This is the root type system union, so match_attribute is not necessary. */
DEFINE_POLICY_SET_UNION(genl, 0);

const NLAPolicySet *genl_get_policy_set_by_name(const char *name) {
        return policy_set_union_get_policy_set_by_string(&genl_policy_set_union, name);
}
