/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

int netlink_slot_allocate(
                sd_netlink *nl,
                bool floating,
                NetlinkSlotType type,
                size_t extra,
                void *userdata,
                const char *description,
                sd_netlink_slot **ret);
void netlink_slot_disconnect(sd_netlink_slot *slot, bool unref);
