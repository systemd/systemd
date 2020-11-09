/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "networkd-link.h"
#include "networkd-util.h"

typedef struct Link Link;

int dhcp4_server_configure(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_emit);
