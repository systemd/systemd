/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

int xlat_start(Link *link);
void xlat_stop(Link *link);
void xlat_done(Link *link);
int xlat_check_address(Link *link);
int xlat_pref64_removed(Link *link, const struct in6_addr *prefix, uint8_t prefix_len);
int xlat_check_route(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_clat_pref64_prefix);
