/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <net/ethernet.h>
#include <netinet/in.h>

#include "dhcp-client-id-internal.h"
#include "networkd-forward.h"

typedef struct DHCPStaticLease {
        Network *network;
        ConfigSection *section;

        struct in_addr address;
        struct ether_addr hw_addr;
        sd_dhcp_client_id client_id;
        char *hostname;
} DHCPStaticLease;

void network_drop_invalid_static_leases(Network *network);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_static_lease_address);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_static_lease_hwaddr);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_static_lease_client_id);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_static_lease_hostname);
