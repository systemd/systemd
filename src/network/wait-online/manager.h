/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"
#include "sd-netlink.h"
#include "sd-network.h"

#include "hashmap.h"
#include "network-util.h"
#include "time-util.h"

typedef struct Manager Manager;
typedef struct Link Link;

struct Manager {
        Hashmap *links_by_index;
        Hashmap *links_by_name;

        /* Do not free the two members below. */
        Hashmap *command_line_interfaces_by_name;
        char **ignored_interfaces;

        LinkOperationalStateRange required_operstate;
        AddressFamily required_family;
        bool any;

        sd_netlink *rtnl;
        sd_event_source *rtnl_event_source;

        sd_network_monitor *network_monitor;
        sd_event_source *network_monitor_event_source;

        sd_event *event;
};

Manager* manager_free(Manager *m);
int manager_new(Manager **ret, Hashmap *command_line_interfaces_by_name, char **ignored_interfaces,
                LinkOperationalStateRange required_operstate,
                AddressFamily required_family,
                bool any, usec_t timeout);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

bool manager_configured(Manager *m);
