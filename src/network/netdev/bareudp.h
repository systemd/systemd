/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "netdev.h"
#include "shared-forward.h"

typedef enum BareUDPProtocol {
        BARE_UDP_PROTOCOL_IPV4    = ETH_P_IP,
        BARE_UDP_PROTOCOL_IPV6    = ETH_P_IPV6,
        BARE_UDP_PROTOCOL_MPLS_UC = ETH_P_MPLS_UC,
        BARE_UDP_PROTOCOL_MPLS_MC = ETH_P_MPLS_MC,
        _BARE_UDP_PROTOCOL_MAX,
        _BARE_UDP_PROTOCOL_INVALID = -EINVAL,
} BareUDPProtocol;

typedef struct BareUDP {
        NetDev meta;

        BareUDPProtocol iftype;
        uint16_t dest_port;
        uint16_t min_port;
} BareUDP;

DEFINE_NETDEV_CAST(BAREUDP, BareUDP);
extern const NetDevVTable bare_udp_vtable;

DECLARE_STRING_TABLE_LOOKUP(bare_udp_protocol, BareUDPProtocol);

CONFIG_PARSER_PROTOTYPE(config_parse_bare_udp_iftype);
