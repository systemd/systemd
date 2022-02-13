/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/nl80211.h>

#include "conf-parser.h"
#include "link-config.h"

typedef struct WLANInterface {
        LinkConfig *config;
        ConfigSection *section;

        char *ifname;
        enum nl80211_iftype iftype;
        struct ether_addr mac;
        int wds; /* tristate */
} WLANInterface;

WLANInterface *wlan_interface_free(WLANInterface *w);
DEFINE_SECTION_CLEANUP_FUNCTIONS(WLANInterface, wlan_interface_free);

int link_apply_wlan_interface_config(Link *link);

void link_config_drop_invalid_wlan_interfaces(LinkConfig *config);

CONFIG_PARSER_PROTOTYPE(config_parse_wlan_interface_name);
CONFIG_PARSER_PROTOTYPE(config_parse_wlan_interface_type);
CONFIG_PARSER_PROTOTYPE(config_parse_wlan_interface_mac);
CONFIG_PARSER_PROTOTYPE(config_parse_wlan_interface_wds);
