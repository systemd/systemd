/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/in.h>
#include <linux/fou.h>

#include "in-addr-util.h"
#include "netdev.h"

typedef enum FooOverUDPEncapType {
        NETDEV_FOO_OVER_UDP_ENCAP_UNSPEC = FOU_ENCAP_UNSPEC,
        NETDEV_FOO_OVER_UDP_ENCAP_DIRECT = FOU_ENCAP_DIRECT,
        NETDEV_FOO_OVER_UDP_ENCAP_GUE = FOU_ENCAP_GUE,
        _NETDEV_FOO_OVER_UDP_ENCAP_MAX,
        _NETDEV_FOO_OVER_UDP_ENCAP_INVALID = -EINVAL,
} FooOverUDPEncapType;

typedef struct FouTunnel {
        NetDev meta;

        uint8_t fou_protocol;

        uint16_t port;
        uint16_t peer_port;

        int local_family;
        int peer_family;

        FooOverUDPEncapType fou_encap_type;
        union in_addr_union local;
        union in_addr_union peer;
} FouTunnel;

DEFINE_NETDEV_CAST(FOU, FouTunnel);
extern const NetDevVTable foutnl_vtable;

const char* fou_encap_type_to_string(FooOverUDPEncapType d) _const_;
FooOverUDPEncapType fou_encap_type_from_string(const char *d) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_fou_encap_type);
CONFIG_PARSER_PROTOTYPE(config_parse_fou_tunnel_address);
