/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/in.h>
#include <linux/l2tp.h>

#include "in-addr-util.h"
#include "netdev.h"
#include "networkd-util.h"

typedef enum L2tpL2specType {
        NETDEV_L2TP_L2SPECTYPE_NONE = L2TP_L2SPECTYPE_NONE,
        NETDEV_L2TP_L2SPECTYPE_DEFAULT = L2TP_L2SPECTYPE_DEFAULT,
        _NETDEV_L2TP_L2SPECTYPE_MAX,
        _NETDEV_L2TP_L2SPECTYPE_INVALID = -EINVAL,
} L2tpL2specType;

typedef enum L2tpEncapType {
        NETDEV_L2TP_ENCAPTYPE_UDP = L2TP_ENCAPTYPE_UDP,
        NETDEV_L2TP_ENCAPTYPE_IP = L2TP_ENCAPTYPE_IP,
        _NETDEV_L2TP_ENCAPTYPE_MAX,
        _NETDEV_L2TP_ENCAPTYPE_INVALID = -EINVAL,
} L2tpEncapType;

typedef enum L2tpLocalAddressType {
        NETDEV_L2TP_LOCAL_ADDRESS_AUTO,
        NETDEV_L2TP_LOCAL_ADDRESS_STATIC,
        NETDEV_L2TP_LOCAL_ADDRESS_DYNAMIC,
        _NETDEV_L2TP_LOCAL_ADDRESS_MAX,
        _NETDEV_L2TP_LOCAL_ADDRESS_INVALID = -EINVAL,
} L2tpLocalAddressType;

typedef struct L2tpTunnel L2tpTunnel;

typedef struct L2tpSession {
        L2tpTunnel *tunnel;
        ConfigSection *section;

        char *name;
        int ifindex;

        uint32_t session_id;
        uint32_t peer_session_id;
        L2tpL2specType l2tp_l2spec_type;
} L2tpSession;

struct L2tpTunnel {
        NetDev meta;

        uint16_t l2tp_udp_sport;
        uint16_t l2tp_udp_dport;

        uint32_t tunnel_id;
        uint32_t peer_tunnel_id;

        int family;

        bool udp_csum;
        bool udp6_csum_rx;
        bool udp6_csum_tx;

        char *local_ifname;
        L2tpLocalAddressType local_address_type;
        union in_addr_union local;
        union in_addr_union remote;

        L2tpEncapType l2tp_encap_type;

        OrderedHashmap *sessions_by_section;
};

DEFINE_NETDEV_CAST(L2TP, L2tpTunnel);
extern const NetDevVTable l2tptnl_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_l2tp_tunnel_local_address);
CONFIG_PARSER_PROTOTYPE(config_parse_l2tp_tunnel_remote_address);
CONFIG_PARSER_PROTOTYPE(config_parse_l2tp_tunnel_id);
CONFIG_PARSER_PROTOTYPE(config_parse_l2tp_encap_type);
CONFIG_PARSER_PROTOTYPE(config_parse_l2tp_session_l2spec);
CONFIG_PARSER_PROTOTYPE(config_parse_l2tp_session_id);
CONFIG_PARSER_PROTOTYPE(config_parse_l2tp_session_name);
