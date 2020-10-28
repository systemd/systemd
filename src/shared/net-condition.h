/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <linux/nl80211.h>
#include <stdbool.h>

#include "sd-device.h"

#include "conf-parser.h"
#include "ether-addr-util.h"
#include "set.h"

bool net_match_config(
                Set *match_mac,
                Set *match_permanent_mac,
                char * const *match_paths,
                char * const *match_drivers,
                char * const *match_iftypes,
                char * const *match_names,
                char * const *match_property,
                char * const *match_wifi_iftype,
                char * const *match_ssid,
                Set *match_bssid,
                sd_device *device,
                const struct ether_addr *dev_mac,
                const struct ether_addr *dev_permanent_mac,
                const char *dev_driver,
                unsigned short dev_iftype,
                const char *dev_name,
                char * const *alternative_names,
                enum nl80211_iftype dev_wifi_iftype,
                const char *dev_ssid,
                const struct ether_addr *dev_bssid);

CONFIG_PARSER_PROTOTYPE(config_parse_net_condition);
CONFIG_PARSER_PROTOTYPE(config_parse_match_strv);
CONFIG_PARSER_PROTOTYPE(config_parse_match_ifnames);
CONFIG_PARSER_PROTOTYPE(config_parse_match_property);
