/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "macvlan-util.h"
#include "string-table.h"

static const char* const macvlan_mode_table[_NETDEV_MACVLAN_MODE_MAX] = {
        [NETDEV_MACVLAN_MODE_PRIVATE] = "private",
        [NETDEV_MACVLAN_MODE_VEPA] = "vepa",
        [NETDEV_MACVLAN_MODE_BRIDGE] = "bridge",
        [NETDEV_MACVLAN_MODE_PASSTHRU] = "passthru",
        [NETDEV_MACVLAN_MODE_SOURCE] = "source",
};

DEFINE_STRING_TABLE_LOOKUP(macvlan_mode, MacVlanMode);
