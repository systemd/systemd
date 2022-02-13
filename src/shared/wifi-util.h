/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <linux/nl80211.h>

#include "sd-netlink.h"

#include "ether-addr-util.h"

int wifi_get_interface(sd_netlink *genl, int ifindex, enum nl80211_iftype *ret_iftype, char **ret_ssid);
int wifi_get_station(sd_netlink *genl, int ifindex, struct ether_addr *ret_bssid);

const char *nl80211_iftype_to_string(enum nl80211_iftype iftype) _const_;
enum nl80211_iftype nl80211_iftype_from_string(const char *s) _pure_;
const char *nl80211_cmd_to_string(int cmd) _const_;
