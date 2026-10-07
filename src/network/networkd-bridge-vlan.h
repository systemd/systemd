/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2016 BISDN GmbH. All rights reserved.
***/

#include "networkd-forward.h"
#include "vlan-util.h"

#define BRIDGE_VLAN_BITMAP_MAX 4096
#define BRIDGE_VLAN_BITMAP_LEN (BRIDGE_VLAN_BITMAP_MAX / 32)

#define BRIDGE_VLAN_KEEP_PVID   UINT16_MAX
#define BRIDGE_VLAN_REMOVE_PVID (UINT16_MAX - 1)
assert_cc(BRIDGE_VLAN_REMOVE_PVID > VLANID_MAX);

static inline bool is_bit_set(unsigned nr, const uint32_t *addr) {
        assert(nr < BRIDGE_VLAN_BITMAP_MAX);
        return addr[nr / 32] & (UINT32_C(1) << (nr % 32));
}

static inline void set_bit(unsigned nr, uint32_t *addr) {
        assert(nr < BRIDGE_VLAN_BITMAP_MAX);
        addr[nr / 32] |= (UINT32_C(1) << (nr % 32));
}

void network_adjust_bridge_vlan(Network *network);

int bridge_vlan_set_message(Link *link, sd_netlink_message *m, bool is_set);

int link_update_bridge_vlan(Link *link, sd_netlink_message *m);

CONFIG_PARSER_PROTOTYPE(config_parse_bridge_vlan_id);
CONFIG_PARSER_PROTOTYPE(config_parse_bridge_vlan_id_range);
CONFIG_PARSER_PROTOTYPE(config_parse_ovs_trunks);
