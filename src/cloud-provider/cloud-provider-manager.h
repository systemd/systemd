/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-network.h"
#include "sd-netlink.h"

#include "cloud-provider-manager.h"
#include "network-cloud-util.h"
#include "time-util.h"

typedef struct Manager Manager;

struct Manager {
        Hashmap *links;

        NetworkCloudProvider *cloud_manager;

        sd_event *event;

        /* network */
        sd_event_source *network_event_source;
        sd_network_monitor *network_monitor;

        sd_netlink *rtnl;
        sd_event_source *rtnl_event_source;
};

int manager_new(Manager **ret);
void manager_free(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(Manager*, manager_free, NULL);

int manager_connect(Manager *m);
void manager_disconnect(Manager *m);
