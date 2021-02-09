/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */
#pragma once

typedef struct BareUDP BareUDP;

#include <linux/if_ether.h>

#include "conf-parser.h"
#include "netdev.h"

typedef enum BareUDPProtocol {
        BARE_UDP_PROTOCOL_IPV4    = ETH_P_IP,
        BARE_UDP_PROTOCOL_IPV6    = ETH_P_IPV6,
        BARE_UDP_PROTOCOL_MPLS_UC = ETH_P_MPLS_UC,
        BARE_UDP_PROTOCOL_MPLS_MC = ETH_P_MPLS_MC,
        _BARE_UDP_PROTOCOL_MAX,
        _BARE_UDP_PROTOCOL_INVALID = -EINVAL,
} BareUDPProtocol;

struct BareUDP {
        NetDev meta;

        BareUDPProtocol iftype;
        uint16_t dest_port;
};

DEFINE_NETDEV_CAST(BAREUDP, BareUDP);
extern const NetDevVTable bare_udp_vtable;

const char *bare_udp_protocol_to_string(BareUDPProtocol d) _const_;
BareUDPProtocol bare_udp_protocol_from_string(const char *d) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_bare_udp_iftype);
