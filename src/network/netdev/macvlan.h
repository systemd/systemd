/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef struct MacVlan MacVlan;

#include "netdev/netdev.h"

typedef enum MacVlanMode {
        NETDEV_MACVLAN_MODE_PRIVATE = MACVLAN_MODE_PRIVATE,
        NETDEV_MACVLAN_MODE_VEPA = MACVLAN_MODE_VEPA,
        NETDEV_MACVLAN_MODE_BRIDGE = MACVLAN_MODE_BRIDGE,
        NETDEV_MACVLAN_MODE_PASSTHRU = MACVLAN_MODE_PASSTHRU,
        _NETDEV_MACVLAN_MODE_MAX,
        _NETDEV_MACVLAN_MODE_INVALID = -1
} MacVlanMode;

struct MacVlan {
        NetDev meta;

        MacVlanMode mode;
};

DEFINE_NETDEV_CAST(MACVLAN, MacVlan);
DEFINE_NETDEV_CAST(MACVTAP, MacVlan);
extern const NetDevVTable macvlan_vtable;
extern const NetDevVTable macvtap_vtable;

const char *macvlan_mode_to_string(MacVlanMode d) _const_;
MacVlanMode macvlan_mode_from_string(const char *d) _pure_;

int config_parse_macvlan_mode(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
