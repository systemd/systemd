/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

typedef struct Link Link;
typedef struct Manager Manager;

/* The following values are different from the ones defined in linux/rfkill.h. */
typedef enum RFKillState {
        RFKILL_UNKNOWN,
        RFKILL_UNBLOCKED,
        RFKILL_SOFT,
        RFKILL_HARD,
        _RFKILL_STATE_MAX,
        _RFKILL_STATE_INVALID = -EINVAL,
} RFKillState;

int link_rfkilled(Link *link);

int manager_genl_process_nl80211_config(sd_netlink *genl, sd_netlink_message *message, Manager *manager);
int manager_genl_process_nl80211_mlme(sd_netlink *genl, sd_netlink_message *message, Manager *manager);
