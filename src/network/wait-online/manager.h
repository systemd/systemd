/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"
#include "sd-netlink.h"
#include "sd-network.h"
#include "sd-varlink.h"

#include "dns-configuration.h"
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
        bool requires_dns;

        sd_netlink *rtnl;
        sd_event_source *rtnl_event_source;

        sd_network_monitor *network_monitor;
        sd_event_source *network_monitor_event_source;

        sd_event *event;

        sd_varlink *varlink_client;
        DNSConfiguration *dns_configuration;
        Hashmap *dns_configuration_by_link_index;
};

Manager* manager_free(Manager *m);
int manager_new(Manager **ret, Hashmap *command_line_interfaces_by_name, char **ignored_interfaces,
                LinkOperationalStateRange required_operstate,
                AddressFamily required_family,
                bool any, usec_t timeout, bool requires_dns);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

bool manager_configured(Manager *m);
