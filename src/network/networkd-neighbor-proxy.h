/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

bool network_has_neighbor_proxy_address(const Network *network, int family);

void network_adjust_neighbor_proxy(Network *network);

int link_request_static_neighbor_proxy_addresses(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_proxy_address);
