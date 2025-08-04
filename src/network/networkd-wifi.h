/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

int manager_genl_process_nl80211_config(sd_netlink *genl, sd_netlink_message *message, Manager *manager);
int manager_genl_process_nl80211_mlme(sd_netlink *genl, sd_netlink_message *message, Manager *manager);
int link_get_wlan_interface(Link *link);
