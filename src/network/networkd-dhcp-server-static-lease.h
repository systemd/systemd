/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <netinet/in.h>

#include "networkd-forward.h"

typedef struct DHCPStaticLease {
        Network *network;
        ConfigSection *section;

        struct in_addr address;
        uint8_t *client_id;
        size_t client_id_size;
} DHCPStaticLease;

void network_drop_invalid_static_leases(Network *network);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_static_lease_address);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_static_lease_hwaddr);
