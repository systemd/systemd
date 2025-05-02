/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "netlink-util.h"

#include "devlink.h"
#include "devlinkd-manager.h"

int devlink_ifname_tracker_add(Devlink *devlink);
void devlink_ifname_tracker_del(Devlink *devlink);
int devlink_ifname_tracker_query(Manager *m, uint64_t ifindex, char **ifname);
int devlink_ifname_tracker_ifindex_update(Manager *m, uint64_t ifindex, sd_netlink_message *message);
void devlink_ifname_tracker_ifindex_remove(Manager *m, uint64_t ifindex);
