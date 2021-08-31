/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"
#include "sd-device.h"
#include "sd-event.h"
#include "sd-id128.h"
#include "sd-netlink.h"
#include "sd-resolve.h"

#include "dhcp-identifier.h"
#include "firewall-util.h"
#include "hashmap.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "ordered-set.h"
#include "set.h"
#include "time-util.h"

struct Manager {
        sd_netlink *rtnl;
        /* lazy initialized */
        sd_netlink *genl;
        sd_event *event;
        sd_resolve *resolve;
        sd_bus *bus;
        sd_device_monitor *device_monitor;
        Hashmap *polkit_registry;
        int ethtool_fd;

        bool enumerating;
        bool dirty;
        bool restarting;
        bool manage_foreign_routes;
        bool manage_foreign_rules;

        Set *dirty_links;

        char *state_file;
        LinkOperationalState operational_state;
        LinkCarrierState carrier_state;
        LinkAddressState address_state;
        LinkAddressState ipv4_address_state;
        LinkAddressState ipv6_address_state;
        LinkOnlineState online_state;

        Hashmap *links_by_index;
        Hashmap *links_by_name;
        Hashmap *links_by_hw_addr;
        Hashmap *netdevs;
        OrderedHashmap *networks;
        Hashmap *dhcp6_prefixes;
        Set *dhcp6_pd_prefixes;
        OrderedSet *address_pools;

        usec_t network_dirs_ts_usec;

        DUID dhcp_duid;
        DUID dhcp6_duid;
        DUID duid_product_uuid;
        bool has_product_uuid;
        bool product_uuid_requested;

        char* dynamic_hostname;
        char* dynamic_timezone;

        Set *rules;

        /* Manage nexthops by id. */
        Hashmap *nexthops_by_id;

        /* Manager stores nexthops without RTA_OIF attribute. */
        unsigned nexthop_remove_messages;
        Set *nexthops;
        Set *nexthops_foreign;

        /* Manager stores routes without RTA_OIF attribute. */
        unsigned route_remove_messages;
        Set *routes;
        Set *routes_foreign;

        /* Route table name */
        Hashmap *route_table_numbers_by_name;
        Hashmap *route_table_names_by_number;

        /* For link speed meter */
        bool use_speed_meter;
        sd_event_source *speed_meter_event_source;
        usec_t speed_meter_interval_usec;
        usec_t speed_meter_usec_new;
        usec_t speed_meter_usec_old;

        bool dhcp4_prefix_root_cannot_set_table;
        bool bridge_mdb_on_master_not_supported;

        FirewallContext *fw_ctx;

        OrderedSet *request_queue;
};

int manager_new(Manager **ret);
Manager* manager_free(Manager *m);

int manager_connect_bus(Manager *m);
int manager_start(Manager *m);

int manager_load_config(Manager *m);
bool manager_should_reload(Manager *m);

int manager_enumerate(Manager *m);

int manager_set_hostname(Manager *m, const char *hostname);
int manager_set_timezone(Manager *m, const char *timezone);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);
