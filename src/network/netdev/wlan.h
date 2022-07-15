/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/nl80211.h>

#include "conf-parser.h"
#include "netdev.h"

typedef struct WLan {
        NetDev meta;

        char *wiphy_name;
        uint32_t wiphy_index;
        enum nl80211_iftype iftype;
        int wds; /* tristate */
} WLan;

DEFINE_NETDEV_CAST(WLAN, WLan);
extern const NetDevVTable wlan_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_wiphy);
CONFIG_PARSER_PROTOTYPE(config_parse_wlan_iftype);
