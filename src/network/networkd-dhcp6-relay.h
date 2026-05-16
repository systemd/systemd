/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

int dhcp6_relay_configure(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp6_relay_interface_id);
