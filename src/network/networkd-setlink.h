/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

int link_request_to_set_addrgen_mode(Link *link);
int link_request_to_set_bond(Link *link);
int link_request_to_set_bridge(Link *link);
int link_request_to_set_bridge_vlan(Link *link);
int link_request_to_set_can(Link *link);
int link_request_to_set_flags(Link *link);
int link_request_to_set_group(Link *link);
int link_request_to_set_mac(Link *link, bool allow_retry);
int link_request_to_set_ipoib(Link *link);
int link_request_to_set_master(Link *link);
int link_request_to_set_mtu(Link *link, uint32_t mtu);

int link_configure_mtu(Link *link);

int link_request_to_activate(Link *link);

int link_request_to_bring_up_or_down(Link *link, bool up);

int link_up_or_down_now(Link *link, bool up);
static inline int link_up_now(Link *link) {
        return link_up_or_down_now(link, true);
}
static inline int link_down_now(Link *link) {
        return link_up_or_down_now(link, false);
}

int link_down_slave_links(Link *link);
int link_remove(Link *link);
