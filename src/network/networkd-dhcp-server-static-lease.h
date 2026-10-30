/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <net/ethernet.h>
#include <netinet/in.h>

#include "dhcp-client-id-internal.h"
#include "networkd-dhcp-common.h"
#include "networkd-dhcp4.h"
#include "networkd-forward.h"

typedef struct DHCPStaticLease {
        Network *network;
        ConfigSection *section;

        struct in_addr address;
        struct ether_addr hw_addr;
        DHCPClientIdentifier client_identifier;
        uint32_t iaid;
        bool iaid_set;
        DUID duid;
        sd_dhcp_client_id client_id;
        char *hostname;
} DHCPStaticLease;

typedef enum DHCPStaticLeaseConfParser {
        DHCP_STATIC_LEASE_CLIENT_IDENTIFIER,
        DHCP_STATIC_LEASE_IAID,
        DHCP_STATIC_LEASE_DUID_TYPE,
        DHCP_STATIC_LEASE_DUID_RAW_DATA,
        _DHCP_STATIC_LEASE_CONF_PARSER_MAX,
        _DHCP_STATIC_LEASE_CONF_PARSER_INVALID = -EINVAL,
} DHCPStaticLeaseConfParser;

void network_drop_invalid_static_leases(Network *network);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_static_lease_address);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_static_lease_hwaddr);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_static_lease_section);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_static_lease_hostname);
