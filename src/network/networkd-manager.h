/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"
#include "sd-device.h"
#include "sd-event.h"
#include "sd-id128.h"
#include "sd-netlink.h"
#include "sd-resolve.h"

#include "dhcp-identifier.h"
#include "hashmap.h"
#include "list.h"
#include "time-util.h"

#include "networkd-address-pool.h"
#include "networkd-link.h"
#include "networkd-network.h"

struct Manager {
        sd_netlink *rtnl;
        /* lazy initialized */
        sd_netlink *genl;
        sd_event *event;
        sd_resolve *resolve;
        sd_bus *bus;
        sd_device_monitor *device_monitor;
        Hashmap *polkit_registry;

        bool enumerating:1;
        bool dirty:1;

        Set *dirty_links;

        char *state_file;
        LinkOperationalState operational_state;
        LinkCarrierState carrier_state;
        LinkAddressState address_state;

        Hashmap *links;
        Hashmap *netdevs;
        OrderedHashmap *networks;
        Hashmap *dhcp6_prefixes;
        LIST_HEAD(AddressPool, address_pools);

        usec_t network_dirs_ts_usec;

        DUID duid;
        sd_id128_t product_uuid;
        bool has_product_uuid;
        Set *links_requesting_uuid;
        Set *duids_requesting_uuid;

        char* dynamic_hostname;
        char* dynamic_timezone;

        Set *rules;
        Set *rules_foreign;
        Set *rules_saved;

        /* For link speed meter*/
        bool use_speed_meter;
        sd_event_source *speed_meter_event_source;
        usec_t speed_meter_interval_usec;
        usec_t speed_meter_usec_new;
        usec_t speed_meter_usec_old;
};

int manager_new(Manager **ret);
void manager_free(Manager *m);

int manager_connect_bus(Manager *m);
int manager_start(Manager *m);

int manager_load_config(Manager *m);
bool manager_should_reload(Manager *m);

int manager_rtnl_enumerate_links(Manager *m);
int manager_rtnl_enumerate_addresses(Manager *m);
int manager_rtnl_enumerate_neighbors(Manager *m);
int manager_rtnl_enumerate_routes(Manager *m);
int manager_rtnl_enumerate_rules(Manager *m);

int manager_rtnl_process_address(sd_netlink *nl, sd_netlink_message *message, void *userdata);
int manager_rtnl_process_neighbor(sd_netlink *nl, sd_netlink_message *message, void *userdata);
int manager_rtnl_process_route(sd_netlink *nl, sd_netlink_message *message, void *userdata);
int manager_rtnl_process_rule(sd_netlink *nl, sd_netlink_message *message, void *userdata);

void manager_dirty(Manager *m);

int manager_address_pool_acquire(Manager *m, int family, unsigned prefixlen, union in_addr_union *found);

Link* manager_find_uplink(Manager *m, Link *exclude);

int manager_set_hostname(Manager *m, const char *hostname);
int manager_set_timezone(Manager *m, const char *timezone);
int manager_request_product_uuid(Manager *m, Link *link);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);
