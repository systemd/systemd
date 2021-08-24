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

#include "netlink-genl.h"
#include "netlink-types-internal.h"

/***************** genl ctrl type systems *****************/
static const NLType genl_ctrl_mcast_group_types[] = {
        [CTRL_ATTR_MCAST_GRP_NAME]  = { .type = NETLINK_TYPE_STRING },
        [CTRL_ATTR_MCAST_GRP_ID]    = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystem genl_ctrl_mcast_group_type_system = {
        .count = ELEMENTSOF(genl_ctrl_mcast_group_types),
        .types = genl_ctrl_mcast_group_types,
};

static const NLType genl_ctrl_types[] = {
        [CTRL_ATTR_FAMILY_ID]    = { .type = NETLINK_TYPE_U16 },
        [CTRL_ATTR_FAMILY_NAME]  = { .type = NETLINK_TYPE_STRING },
        [CTRL_ATTR_MCAST_GROUPS] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_ctrl_mcast_group_type_system },
};

static const NLTypeSystem genl_ctrl_type_system = {
        .count = ELEMENTSOF(genl_ctrl_types),
        .types = genl_ctrl_types,
};

/***************** genl batadv type systems *****************/
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

/***************** genl fou type systems *****************/
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

/***************** genl l2tp type systems *****************/
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

/***************** genl macsec type systems *****************/
static const NLType genl_macsec_rxsc_types[] = {
        [MACSEC_RXSC_ATTR_SCI] = { .type = NETLINK_TYPE_U64 },
};

static const NLTypeSystem genl_macsec_rxsc_type_system = {
        .count = ELEMENTSOF(genl_macsec_rxsc_types),
        .types = genl_macsec_rxsc_types,
};

static const NLType genl_macsec_sa_types[] = {
        [MACSEC_SA_ATTR_AN]     = { .type = NETLINK_TYPE_U8 },
        [MACSEC_SA_ATTR_ACTIVE] = { .type = NETLINK_TYPE_U8 },
        [MACSEC_SA_ATTR_PN]     = { .type = NETLINK_TYPE_U32 },
        [MACSEC_SA_ATTR_KEYID]  = { .size = MACSEC_KEYID_LEN },
        [MACSEC_SA_ATTR_KEY]    = { .size = MACSEC_MAX_KEY_LEN },
};

static const NLTypeSystem genl_macsec_sa_type_system = {
        .count = ELEMENTSOF(genl_macsec_sa_types),
        .types = genl_macsec_sa_types,
};

static const NLType genl_macsec_types[] = {
        [MACSEC_ATTR_IFINDEX]     = { .type = NETLINK_TYPE_U32 },
        [MACSEC_ATTR_RXSC_CONFIG] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_macsec_rxsc_type_system },
        [MACSEC_ATTR_SA_CONFIG]   = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_macsec_sa_type_system },
};

static const NLTypeSystem genl_macsec_type_system = {
        .count = ELEMENTSOF(genl_macsec_types),
        .types = genl_macsec_types,
};

/***************** genl nl80211 type systems *****************/
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

/***************** genl wireguard type systems *****************/
static const NLType genl_wireguard_allowedip_types[] = {
        [WGALLOWEDIP_A_FAMILY]    = { .type = NETLINK_TYPE_U16 },
        [WGALLOWEDIP_A_IPADDR]    = { .type = NETLINK_TYPE_IN_ADDR },
        [WGALLOWEDIP_A_CIDR_MASK] = { .type = NETLINK_TYPE_U8 },
};

static const NLTypeSystem genl_wireguard_allowedip_type_system = {
        .count = ELEMENTSOF(genl_wireguard_allowedip_types),
        .types = genl_wireguard_allowedip_types,
};

static const NLType genl_wireguard_peer_types[] = {
        [WGPEER_A_PUBLIC_KEY]                    = { .size = WG_KEY_LEN },
        [WGPEER_A_FLAGS]                         = { .type = NETLINK_TYPE_U32 },
        [WGPEER_A_PRESHARED_KEY]                 = { .size = WG_KEY_LEN },
        [WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL] = { .type = NETLINK_TYPE_U16 },
        [WGPEER_A_ENDPOINT]                      = { .type = NETLINK_TYPE_SOCKADDR },
        [WGPEER_A_ALLOWEDIPS]                    = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_wireguard_allowedip_type_system },
};

static const NLTypeSystem genl_wireguard_peer_type_system = {
        .count = ELEMENTSOF(genl_wireguard_peer_types),
        .types = genl_wireguard_peer_types,
};

static const NLType genl_wireguard_types[] = {
        [WGDEVICE_A_IFINDEX]     = { .type = NETLINK_TYPE_U32 },
        [WGDEVICE_A_IFNAME]      = { .type = NETLINK_TYPE_STRING, .size = IFNAMSIZ-1 },
        [WGDEVICE_A_FLAGS]       = { .type = NETLINK_TYPE_U32 },
        [WGDEVICE_A_PRIVATE_KEY] = { .size = WG_KEY_LEN },
        [WGDEVICE_A_LISTEN_PORT] = { .type = NETLINK_TYPE_U16 },
        [WGDEVICE_A_FWMARK]      = { .type = NETLINK_TYPE_U32 },
        [WGDEVICE_A_PEERS]       = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_wireguard_peer_type_system },
};

static const NLTypeSystem genl_wireguard_type_system = {
        .count = ELEMENTSOF(genl_wireguard_types),
        .types = genl_wireguard_types,
};

/***************** genl families *****************/
static const NLType genl_types[] = {
        [SD_GENL_DONE]      = { .type = NETLINK_TYPE_NESTED, .type_system = &empty_type_system },
        [SD_GENL_ERROR]     = { .type = NETLINK_TYPE_NESTED, .type_system = &error_type_system, .size = sizeof(struct nlmsgerr) },
        [SD_GENL_ID_CTRL]   = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_ctrl_type_system, .size = sizeof(struct genlmsghdr) },
        [SD_GENL_WIREGUARD] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_wireguard_type_system, .size = sizeof(struct genlmsghdr) },
        [SD_GENL_FOU]       = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_fou_type_system, .size = sizeof(struct genlmsghdr) },
        [SD_GENL_L2TP]      = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_l2tp_type_system, .size = sizeof(struct genlmsghdr) },
        [SD_GENL_MACSEC]    = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_macsec_type_system, .size = sizeof(struct genlmsghdr) },
        [SD_GENL_NL80211]   = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_nl80211_type_system, .size = sizeof(struct genlmsghdr) },
        [SD_GENL_BATADV]    = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_batadv_type_system, .size = sizeof(struct genlmsghdr) },
};

static const NLTypeSystem genl_type_system = {
        .count = ELEMENTSOF(genl_types),
        .types = genl_types,
};

int genl_get_type(sd_netlink *genl, uint16_t nlmsg_type, const NLType **ret) {
        sd_genl_family_t family;
        int r;

        r = nlmsg_type_to_genl_family(genl, nlmsg_type, &family);
        if (r < 0)
                return r;

        return type_system_get_type(&genl_type_system, ret, family);
}
