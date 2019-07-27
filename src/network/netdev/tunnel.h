/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "in-addr-util.h"

#include "conf-parser.h"
#include "netdev/netdev.h"
#include "netdev/fou-tunnel.h"

typedef enum Ip6TnlMode {
        NETDEV_IP6_TNL_MODE_IP6IP6,
        NETDEV_IP6_TNL_MODE_IPIP6,
        NETDEV_IP6_TNL_MODE_ANYIP6,
        _NETDEV_IP6_TNL_MODE_MAX,
        _NETDEV_IP6_TNL_MODE_INVALID = -1,
} Ip6TnlMode;

typedef enum IPv6FlowLabel {
        NETDEV_IPV6_FLOWLABEL_INHERIT = 0xFFFFF + 1,
        _NETDEV_IPV6_FLOWLABEL_MAX,
        _NETDEV_IPV6_FLOWLABEL_INVALID = -1,
} IPv6FlowLabel;

typedef struct Tunnel {
        NetDev meta;

        uint8_t encap_limit;

        int family;
        int ipv6_flowlabel;
        int allow_localremote;
        int gre_erspan_sequence;
        int isatap;

        unsigned ttl;
        unsigned tos;
        unsigned flags;

        uint32_t key;
        uint32_t ikey;
        uint32_t okey;
        uint32_t erspan_index;

        union in_addr_union local;
        union in_addr_union remote;

        Ip6TnlMode ip6tnl_mode;
        FooOverUDPEncapType fou_encap_type;

        bool pmtudisc;
        bool copy_dscp;
        bool independent;
        bool fou_tunnel;
        bool assign_to_loopback;

        uint16_t encap_src_port;
        uint16_t fou_destination_port;

        struct in6_addr sixrd_prefix;
        uint8_t sixrd_prefixlen;
} Tunnel;

DEFINE_NETDEV_CAST(IPIP, Tunnel);
DEFINE_NETDEV_CAST(GRE, Tunnel);
DEFINE_NETDEV_CAST(GRETAP, Tunnel);
DEFINE_NETDEV_CAST(IP6GRE, Tunnel);
DEFINE_NETDEV_CAST(IP6GRETAP, Tunnel);
DEFINE_NETDEV_CAST(SIT, Tunnel);
DEFINE_NETDEV_CAST(VTI, Tunnel);
DEFINE_NETDEV_CAST(VTI6, Tunnel);
DEFINE_NETDEV_CAST(IP6TNL, Tunnel);
DEFINE_NETDEV_CAST(ERSPAN, Tunnel);
extern const NetDevVTable ipip_vtable;
extern const NetDevVTable sit_vtable;
extern const NetDevVTable vti_vtable;
extern const NetDevVTable vti6_vtable;
extern const NetDevVTable gre_vtable;
extern const NetDevVTable gretap_vtable;
extern const NetDevVTable ip6gre_vtable;
extern const NetDevVTable ip6gretap_vtable;
extern const NetDevVTable ip6tnl_vtable;
extern const NetDevVTable erspan_vtable;

const char *ip6tnl_mode_to_string(Ip6TnlMode d) _const_;
Ip6TnlMode ip6tnl_mode_from_string(const char *d) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_ip6tnl_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_tunnel_address);
CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_flowlabel);
CONFIG_PARSER_PROTOTYPE(config_parse_encap_limit);
CONFIG_PARSER_PROTOTYPE(config_parse_tunnel_key);
CONFIG_PARSER_PROTOTYPE(config_parse_6rd_prefix);
