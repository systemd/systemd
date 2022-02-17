/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/nl80211.h>
#include <stdbool.h>

#include "sd-device.h"

#include "conf-parser.h"
#include "ether-addr-util.h"
#include "set.h"

typedef struct NetMatch {
        Set *hw_addr;
        Set *permanent_hw_addr;
        char **path;
        char **driver;
        char **iftype; /* udev's DEVTYPE field or ARPHRD_XXX, e.g. ether, wlan. */
        char **kind;   /* IFLA_INFO_KIND attribute, e.g. gre, gretap, erspan. */
        char **ifname;
        char **property;
        char **wlan_iftype;
        char **ssid;
        Set *bssid;
} NetMatch;

void net_match_clear(NetMatch *match);
bool net_match_is_empty(const NetMatch *match);

int net_match_config(
                const NetMatch *match,
                sd_device *device,
                const struct hw_addr_data *hw_addr,
                const struct hw_addr_data *permanent_hw_addr,
                const char *driver,
                unsigned short iftype,
                const char *kind,
                const char *ifname,
                char * const *alternative_names,
                enum nl80211_iftype wlan_iftype,
                const char *ssid,
                const struct ether_addr *bssid);

CONFIG_PARSER_PROTOTYPE(config_parse_net_condition);
CONFIG_PARSER_PROTOTYPE(config_parse_match_strv);
CONFIG_PARSER_PROTOTYPE(config_parse_match_ifnames);
CONFIG_PARSER_PROTOTYPE(config_parse_match_property);
