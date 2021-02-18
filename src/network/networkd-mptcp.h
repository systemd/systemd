/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "networkd-util.h"

typedef struct MPTCP {
        NetworkConfigSection *section;
        Network *network;

        int family;
        uint8_t id;

        bool id_is_set;

        union in_addr_union address;
} MPTCP;

MPTCP *mp_tcp_free(MPTCP *mp_tcp);

int mp_tcp_configure_address(Link *link, MPTCP *mp_tcp);
int mp_tcp_configure_limit(Manager *m);

int network_drop_invalid_mp_tcp(Network *network);
int link_configure_mp_tcp(Link *link);

DEFINE_NETWORK_SECTION_FUNCTIONS(MPTCP, mp_tcp_free);

CONFIG_PARSER_PROTOTYPE(config_parse_mp_tcp_id);
CONFIG_PARSER_PROTOTYPE(config_parse_mp_tcp_address);
CONFIG_PARSER_PROTOTYPE(config_parse_mp_tcp_uint32);
