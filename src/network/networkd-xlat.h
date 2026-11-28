/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser-forward.h"
#include "networkd-forward.h"

/* CLAT (464XLAT, RFC 6877) */

void xlat_start(Link *link);
void xlat_stop(Link *link);

/* Events CLAT depends on */
void xlat_address_changed(Link *link, const Address *address);
void xlat_address_dropped(Link *link, const Address *address);
void xlat_route_changed(Link *link, const Route *route, bool removed);
void xlat_pref64_removed(Link *link, const struct in6_addr *prefix, uint8_t prefix_len);
void xlat_mtu_changed(Link *link);

bool xlat_manager_owns_ifindex(Manager *manager, int ifindex);

CONFIG_PARSER_PROTOTYPE(config_parse_clat_pref64_prefix);
