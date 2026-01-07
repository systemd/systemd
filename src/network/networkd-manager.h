/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"
#include "networkd-network.h"

typedef enum ManagerState {
        MANAGER_RUNNING,
        MANAGER_TERMINATING,
        MANAGER_RESTARTING,
        MANAGER_STOPPED,
        _MANAGER_STATE_MAX,
        _MANAGER_STATE_INVALID = -EINVAL,
} ManagerState;

typedef struct Manager {
        sd_netlink *rtnl;
        /* lazy initialized */
        sd_netlink *genl;
        sd_netlink *nfnl;
        sd_event *event;
        sd_resolve *resolve;
        sd_bus *bus;
        sd_varlink_server *varlink_server;
        sd_varlink_server *varlink_resolve_hook_server;
        Set *query_filter_subscriptions;
        sd_device_monitor *device_monitor;
        Hashmap *polkit_registry;
        int ethtool_fd;
        int persistent_storage_fd;

        KeepConfiguration keep_configuration;
        IPv6PrivacyExtensions ipv6_privacy_extensions;

        ManagerState state;
        bool test_mode;
        bool enumerating;
        bool dirty;
        bool manage_foreign_routes;
        bool manage_foreign_rules;
        bool manage_foreign_nexthops;
        DHCPServerPersistLeases dhcp_server_persist_leases;

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

        UseDomains use_domains; /* default for all protocols */
        UseDomains dhcp_use_domains;
        UseDomains dhcp6_use_domains;
        UseDomains ndisc_use_domains;

        DHCPClientIdentifier dhcp_client_identifier;
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
        Set *nexthop_ids; /* requested IDs in .network files */

        /* Manager stores routes without RTA_OIF attribute. */
        unsigned route_remove_messages;
        Set *routes;

        /* IPv6 Address Label */
        Hashmap *address_labels_by_section;
        unsigned static_address_label_messages;
        bool static_address_labels_configured;

        /* Route table name */
        Hashmap *route_table_numbers_by_name;
        Hashmap *route_table_names_by_number;

        /* Wiphy */
        Hashmap *wiphy_by_index;
        Hashmap *wiphy_by_name;

        /* ModemManager support */
        sd_bus_slot *slot_mm;
        Hashmap *modems_by_path;

        /* For link speed meter */
        bool use_speed_meter;
        sd_event_source *speed_meter_event_source;
        usec_t speed_meter_interval_usec;
        usec_t speed_meter_usec_new;
        usec_t speed_meter_usec_old;

        bool request_queued;
        OrderedSet *request_queue;
        OrderedSet *remove_request_queue;

        Hashmap *tuntap_fds_by_name;

        unsigned reloading;

        int serialization_fd;

        /* sysctl */
        int ip_forwarding[2];
#if ENABLE_SYSCTL_BPF
        Hashmap *sysctl_shadow;
        sd_event_source *sysctl_event_source;
        struct ring_buffer *sysctl_buffer;
        struct sysctl_monitor_bpf *sysctl_skel;
        struct bpf_link *sysctl_link;
        int cgroup_fd;
#endif
} Manager;

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
int manager_set_timezone(Manager *m, const char *tz);

int manager_reload(Manager *m, sd_bus_message *message);

static inline Hashmap** manager_get_sysctl_shadow(Manager *manager) {
#if ENABLE_SYSCTL_BPF
        return &ASSERT_PTR(manager)->sysctl_shadow;
#else
        return NULL;
#endif
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);
