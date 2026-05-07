/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

typedef enum DHCPRelayInterfaceMode {
        DHCP_RELAY_INTERFACE_UPSTREAM,
        DHCP_RELAY_INTERFACE_DOWNSTREAM,
        _DHCP_RELAY_INTERFACE_MAX,
        _DHCP_RELAY_INTERFACE_INVALID = -EINVAL,
} DHCPRelayInterfaceMode;

void network_adjust_dhcp_relay(Network *network);

int link_request_dhcp_relay(Link *link);
int link_start_dhcp_relay(Link *link);
int link_dhcp_relay_address_dropped(Link *link, const Address *address);

DECLARE_STRING_TABLE_LOOKUP(dhcp_relay_interface_mode, DHCPRelayInterfaceMode);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_relay_interface_mode);
