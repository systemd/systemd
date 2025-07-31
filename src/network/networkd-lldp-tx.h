/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

int link_lldp_tx_configure(Link *link);
int link_lldp_tx_update_capabilities(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_lldp_multicast_mode);
