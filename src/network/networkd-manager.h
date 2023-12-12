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
#include "networkd-sysctl.h"
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

        KeepConfiguration keep_configuration;
        IPv6PrivacyExtensions ipv6_privacy_extensions;

        bool test_mode;
        bool enumerating;
        bool dirty;
        bool restarting;
        bool manage_foreign_routes;
        bool manage_foreign_rules;
        bool manage_foreign_nexthops;

        Set *dirty_links;
        Set *new_wlan_ifindices;

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
        Hashmap *links_by_dhcp_pd_subnet_prefix;
        Hashmap *netdevs;
        OrderedHashmap *networks;
        OrderedSet *address_pools;
        Set *dhcp_pd_subnet_ids;

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

        /* Manager stores routes without RTA_OIF attribute. */
        unsigned route_remove_messages;
        Set *routes;

        /* Route table name */
        Hashmap *route_table_numbers_by_name;
        Hashmap *route_table_names_by_number;

        /* Wiphy */
        Hashmap *wiphy_by_index;
        Hashmap *wiphy_by_name;

        /* For link speed meter */
        bool use_speed_meter;
        sd_event_source *speed_meter_event_source;
        usec_t speed_meter_interval_usec;
        usec_t speed_meter_usec_new;
        usec_t speed_meter_usec_old;

        bool bridge_mdb_on_master_not_supported;

        FirewallContext *fw_ctx;

        OrderedSet *request_queue;

        Hashmap *tuntap_fds_by_name;
};

int manager_new(Manager **ret, bool test_mode);
Manager* manager_free(Manager *m);

int manager_setup(Manager *m);
int manager_start(Manager *m);

int manager_load_config(Manager *m);

int manager_enumerate_internal(
                Manager *m,
                sd_netlink *nl,
                sd_netlink_message *req,
                int (*process)(sd_netlink *, sd_netlink_message *, Manager *));
int manager_enumerate(Manager *m);

int manager_set_hostname(Manager *m, const char *hostname);
int manager_set_timezone(Manager *m, const char *timezone);

int manager_reload(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);
