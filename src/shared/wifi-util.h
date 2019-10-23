/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include "netlink-util.h"

int wifi_get_ssid(sd_netlink *genl, int ifindex, char **ssid);
int wifi_get_bssid(sd_netlink *genl, int ifindex, struct ether_addr *bssid);
