/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <inttypes.h>

#include "conf-parser.h"
#include "in-addr-util.h"

typedef struct Network Network;
typedef struct ConfigSection ConfigSection;

typedef struct DHCPStaticLease {
        Network *network;
        ConfigSection *section;

        struct in_addr address;
        uint8_t *client_id;
        size_t client_id_size;
} DHCPStaticLease;

DHCPStaticLease *dhcp_static_lease_free(DHCPStaticLease *lease);
void network_drop_invalid_static_leases(Network *network);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_static_lease_address);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_static_lease_hwaddr);
