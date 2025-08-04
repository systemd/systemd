/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

bool link_get_use_ntp(Link *link, NetworkConfigSource proto);

CONFIG_PARSER_PROTOTYPE(config_parse_ntp);
