/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

int link_request_dhcp6_server(Link *link);
int link_start_dhcp6_server(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp6_server_address);
