/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <linux/nl80211.h>
#include <net/ethernet.h>

#include "sd-netlink.h"

int wifi_get_interface(sd_netlink *genl, int ifindex, enum nl80211_iftype *iftype, char **ssid);
int wifi_get_station(sd_netlink *genl, int ifindex, struct ether_addr *bssid);
