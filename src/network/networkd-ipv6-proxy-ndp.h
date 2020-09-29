/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"

typedef struct Link Link;

int ipv6_proxy_ndp_addresses_configure(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_proxy_ndp_address);
