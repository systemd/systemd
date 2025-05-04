/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"
#include "sd-netlink.h"
#include "hashmap.h"

#include "devlink-key.h"

#include <stdbool.h>

typedef struct KindInfo {
        unsigned count;
        bool dirty;
} KindInfo;

typedef struct Manager Manager;

struct Manager {
        sd_netlink *genl;
        sd_netlink *rtnl;
        sd_event *event;
        sd_event_source *periodic_enumeration_event_source;
        sd_bus *bus;
        Hashmap *devlink_objs;
        KindInfo kind_info[_DEVLINK_KIND_MAX];
        Hashmap *reload;
};

int manager_rtnl_query_one(Manager *m, uint32_t ifindex);
int manager_setup(Manager *m);
int manager_new(Manager **ret);
Manager* manager_free(Manager *m);

int manager_start(Manager *m);
int manager_config_load(Manager *m);

void manager_kind_inc(Manager *m, DevlinkKind kind);
void manager_kind_dec(Manager *m, DevlinkKind kind);

int manager_enumerate(Manager *m);
void manager_enumerate_by_key(Manager *m, DevlinkKey *key);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager *, manager_free);
