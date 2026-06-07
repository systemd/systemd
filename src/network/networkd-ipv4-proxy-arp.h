/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

int link_request_static_ipv4_proxy_arp_addresses(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_ipv4_proxy_arp_address);
