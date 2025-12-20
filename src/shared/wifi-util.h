/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <linux/nl80211.h>

#include "shared-forward.h"

int wifi_get_interface(sd_netlink *genl, int ifindex, enum nl80211_iftype *ret_iftype, char **ret_ssid);
int wifi_get_station(sd_netlink *genl, int ifindex, struct ether_addr *ret_bssid);

DECLARE_STRING_TABLE_LOOKUP(nl80211_iftype, enum nl80211_iftype);
DECLARE_STRING_TABLE_LOOKUP_TO_STRING(nl80211_cmd, int);
