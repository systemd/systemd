/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

void network_adjust_ipv6_proxy_ndp(Network *network);

int link_request_static_ipv6_proxy_ndp_addresses(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_proxy_ndp_address);
