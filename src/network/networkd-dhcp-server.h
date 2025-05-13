/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

int network_adjust_dhcp_server(Network *network, Set **addresses);
int address_acquire_from_dhcp_server_leases_file(Link *link, const Address *address, union in_addr_union *ret);
int link_request_dhcp_server(Link *link);

int link_start_dhcp4_server(Link *link);
void manager_toggle_dhcp4_server_state(Manager *manager, bool start);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_relay_agent_suboption);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_emit);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_address);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_ipv6_only_preferred);
