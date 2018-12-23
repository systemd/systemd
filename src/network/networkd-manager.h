/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <arpa/inet.h>

#include "sd-bus.h"
#include "sd-device.h"
#include "sd-event.h"
#include "sd-id128.h"
#include "sd-netlink.h"
#include "sd-resolve.h"

#include "dhcp-identifier.h"
#include "hashmap.h"
#include "list.h"

#include "networkd-address-pool.h"
#include "networkd-link.h"
#include "networkd-network.h"

extern const char *const network_dirs[];

struct Manager {
        sd_netlink *rtnl;
        /* lazy initialized */
        sd_netlink *genl;
        sd_event *event;
        sd_resolve *resolve;
        sd_bus *bus;
        sd_device_monitor *device_monitor;

        bool enumerating : 1;
        bool dirty : 1;

        Set *dirty_links;

        char *state_file;
        LinkOperationalState operational_state;

        Hashmap *links;
        Hashmap *netdevs;
        Hashmap *networks_by_name;
        Hashmap *dhcp6_prefixes;
        LIST_HEAD(Network, networks);
        LIST_HEAD(AddressPool, address_pools);

        usec_t network_dirs_ts_usec;

        DUID duid;
        sd_id128_t product_uuid;
        bool has_product_uuid;
        Set *links_requesting_uuid;
        Set *duids_requesting_uuid;

        char *dynamic_hostname;
        char *dynamic_timezone;

        Set *rules;
        Set *rules_foreign;
        Set *rules_saved;
};

extern const sd_bus_vtable manager_vtable[];

int manager_new(Manager **ret);
void manager_free(Manager *m);

int manager_connect_bus(Manager *m);
int manager_start(Manager *m);

int manager_load_config(Manager *m);
bool manager_should_reload(Manager *m);

int manager_rtnl_enumerate_links(Manager *m);
int manager_rtnl_enumerate_addresses(Manager *m);
int manager_rtnl_enumerate_routes(Manager *m);
int manager_rtnl_enumerate_rules(Manager *m);

int manager_rtnl_process_address(sd_netlink *nl, sd_netlink_message *message, void *userdata);
int manager_rtnl_process_route(sd_netlink *nl, sd_netlink_message *message, void *userdata);
int manager_rtnl_process_rule(sd_netlink *nl, sd_netlink_message *message, void *userdata);

int manager_send_changed(Manager *m, const char *property, ...) _sentinel_;
void manager_dirty(Manager *m);

int manager_address_pool_acquire(Manager *m, int family, unsigned prefixlen, union in_addr_union *found);

Link *manager_find_uplink(Manager *m, Link *exclude);

int manager_set_hostname(Manager *m, const char *hostname);
int manager_set_timezone(Manager *m, const char *timezone);
int manager_request_product_uuid(Manager *m, Link *link);

Link *manager_dhcp6_prefix_get(Manager *m, struct in6_addr *addr);
int manager_dhcp6_prefix_add(Manager *m, struct in6_addr *addr, Link *link);
int manager_dhcp6_prefix_remove_all(Manager *m, Link *link);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager *, manager_free);
