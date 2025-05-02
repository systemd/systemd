/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-event.h"
#include "sd-netlink.h"

#include "hashmap.h"

#include "devlink-key.h"

typedef struct Manager Manager;

struct Manager {
        sd_netlink *genl;
        sd_netlink *rtnl;
        sd_event *event;
        sd_event_source *periodic_enumeration_event_source;
        Hashmap *devlink_objs;
        Hashmap *ifname_tracker_by_ifindex;
        Hashmap *ifname_tracker_by_ifname;
        Hashmap *port_cache_by_ifindex;
        Hashmap *reload;
};

int manager_rtnl_query_one(Manager *m, uint32_t ifindex);
int manager_setup(Manager *m);
int manager_new(Manager **ret);
Manager* manager_free(Manager *m);

int manager_start(Manager *m);
int manager_load_config(Manager *m);
int manager_enumerate(Manager *m);
void manager_enumerate_by_key(Manager *m, DevlinkKey *key);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager *, manager_free);
