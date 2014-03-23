/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#pragma once

#include <arpa/inet.h>

#include "sd-event.h"
#include "sd-rtnl.h"
#include "sd-bus.h"
#include "sd-dhcp-client.h"
#include "sd-ipv4ll.h"
#include "udev.h"

#include "rtnl-util.h"
#include "hashmap.h"
#include "list.h"
#include "set.h"
#include "condition-util.h"

typedef struct NetDev NetDev;
typedef struct Network Network;
typedef struct Link Link;
typedef struct Address Address;
typedef struct Route Route;
typedef struct Manager Manager;

typedef struct netdev_enslave_callback netdev_enslave_callback;

struct netdev_enslave_callback {
        sd_rtnl_message_handler_t callback;
        Link *link;

        LIST_FIELDS(netdev_enslave_callback, callbacks);
};

typedef enum MacVlanMode {
        NETDEV_MACVLAN_MODE_PRIVATE = MACVLAN_MODE_PRIVATE,
        NETDEV_MACVLAN_MODE_VEPA = MACVLAN_MODE_VEPA,
        NETDEV_MACVLAN_MODE_BRIDGE = MACVLAN_MODE_BRIDGE,
        NETDEV_MACVLAN_MODE_PASSTHRU = MACVLAN_MODE_PASSTHRU,
        _NETDEV_MACVLAN_MODE_MAX,
        _NETDEV_MACVLAN_MODE_INVALID = -1
} MacVlanMode;

typedef enum NetDevKind {
        NETDEV_KIND_BRIDGE,
        NETDEV_KIND_BOND,
        NETDEV_KIND_VLAN,
        NETDEV_KIND_MACVLAN,
        _NETDEV_KIND_MAX,
        _NETDEV_KIND_INVALID = -1
} NetDevKind;

typedef enum NetDevState {
        NETDEV_STATE_FAILED,
        NETDEV_STATE_CREATING,
        NETDEV_STATE_READY,
        _NETDEV_STATE_MAX,
        _NETDEV_STATE_INVALID = -1,
} NetDevState;

struct NetDev {
        Manager *manager;

        char *filename;

        Condition *match_host;
        Condition *match_virt;
        Condition *match_kernel;
        Condition *match_arch;

        char *description;
        char *name;
        NetDevKind kind;

        uint64_t vlanid;
        int32_t macvlan_mode;

        int ifindex;
        NetDevState state;

        LIST_HEAD(netdev_enslave_callback, callbacks);
};

struct Network {
        Manager *manager;

        char *filename;

        struct ether_addr *match_mac;
        char *match_path;
        char *match_driver;
        char *match_type;
        char *match_name;
        Condition *match_host;
        Condition *match_virt;
        Condition *match_kernel;
        Condition *match_arch;

        char *description;
        NetDev *bridge;
        NetDev *bond;
        Hashmap *vlans;
        Hashmap *macvlans;
        bool dhcp;
        bool dhcp_dns;
        bool dhcp_mtu;
        bool dhcp_hostname;
        bool dhcp_domainname;
        bool dhcp_critical;
        bool ipv4ll;

        LIST_HEAD(Address, static_addresses);
        LIST_HEAD(Route, static_routes);

        Hashmap *addresses_by_section;
        Hashmap *routes_by_section;

        Set *dns;

        LIST_FIELDS(Network, networks);
};

struct Address {
        Network *network;
        uint64_t section;

        unsigned char family;
        unsigned char prefixlen;
        unsigned char scope;
        char *label;

        struct in_addr broadcast;

        union {
                struct in_addr in;
                struct in6_addr in6;
        } in_addr;

        LIST_FIELDS(Address, static_addresses);
};

struct Route {
        Network *network;
        uint64_t section;

        unsigned char family;
        unsigned char dst_prefixlen;
        unsigned char scope;
        uint32_t metrics;

        union {
                struct in_addr in;
                struct in6_addr in6;
        } in_addr;

        union {
                struct in_addr in;
                struct in6_addr in6;
        } dst_addr;

        LIST_FIELDS(Route, static_routes);
};

typedef enum LinkState {
        LINK_STATE_ENSLAVING,
        LINK_STATE_SETTING_ADDRESSES,
        LINK_STATE_SETTING_ROUTES,
        LINK_STATE_CONFIGURED,
        LINK_STATE_FAILED,
        _LINK_STATE_MAX,
        _LINK_STATE_INVALID = -1
} LinkState;

struct Link {
        Manager *manager;

        uint64_t ifindex;
        char *ifname;
        char *state_file;
        struct ether_addr mac;
        struct udev_device *udev_device;

        unsigned flags;

        Network *network;

        LinkState state;

        unsigned addr_messages;
        unsigned route_messages;
        unsigned enslaving;

        sd_dhcp_client *dhcp_client;
        sd_dhcp_lease *dhcp_lease;
        uint16_t original_mtu;
        sd_ipv4ll *ipv4ll;
};

struct Manager {
        sd_rtnl *rtnl;
        sd_event *event;
        sd_bus *bus;
        struct udev *udev;
        struct udev_monitor *udev_monitor;
        sd_event_source *udev_event_source;
        sd_event_source *sigterm_event_source;
        sd_event_source *sigint_event_source;

        Hashmap *links;
        Hashmap *netdevs;
        LIST_HEAD(Network, networks);

        usec_t network_dirs_ts_usec;
};

extern const char* const network_dirs[];

/* Manager */

int manager_new(Manager **ret);
void manager_free(Manager *m);

int manager_load_config(Manager *m);
bool manager_should_reload(Manager *m);

int manager_udev_enumerate_links(Manager *m);
int manager_udev_listen(Manager *m);

int manager_rtnl_listen(Manager *m);
int manager_bus_listen(Manager *m);

int manager_update_resolv_conf(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);
#define _cleanup_manager_free_ _cleanup_(manager_freep)

/* NetDev */

int netdev_load(Manager *manager);

void netdev_free(NetDev *netdev);

DEFINE_TRIVIAL_CLEANUP_FUNC(NetDev*, netdev_free);
#define _cleanup_netdev_free_ _cleanup_(netdev_freep)

int netdev_get(Manager *manager, const char *name, NetDev **ret);
int netdev_set_ifindex(NetDev *netdev, sd_rtnl_message *newlink);
int netdev_enslave(NetDev *netdev, Link *link, sd_rtnl_message_handler_t cb);

const char *netdev_kind_to_string(NetDevKind d) _const_;
NetDevKind netdev_kind_from_string(const char *d) _pure_;

const char *macvlan_mode_to_string(MacVlanMode d) _const_;
MacVlanMode macvlan_mode_from_string(const char *d) _pure_;

int config_parse_netdev_kind(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_macvlan_mode(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

/* gperf */
const struct ConfigPerfItem* network_netdev_gperf_lookup(const char *key, unsigned length);

/* Network */

int network_load(Manager *manager);

void network_free(Network *network);

DEFINE_TRIVIAL_CLEANUP_FUNC(Network*, network_free);
#define _cleanup_network_free_ _cleanup_(network_freep)

int network_get(Manager *manager, struct udev_device *device, Network **ret);
int network_apply(Manager *manager, Network *network, Link *link);

int config_parse_bridge(const char *unit, const char *filename, unsigned line,
                        const char *section, unsigned section_line, const char *lvalue,
                        int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_bond(const char *unit, const char *filename, unsigned line,
                      const char *section, unsigned section_line, const char *lvalue,
                      int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_vlan(const char *unit, const char *filename, unsigned line,
                      const char *section, unsigned section_line, const char *lvalue,
                      int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_macvlan(const char *unit, const char *filename, unsigned line,
                         const char *section, unsigned section_line, const char *lvalue,
                         int ltype, const char *rvalue, void *data, void *userdata);

/* gperf */
const struct ConfigPerfItem* network_network_gperf_lookup(const char *key, unsigned length);

/* Route */
int route_new_static(Network *network, unsigned section, Route **ret);
int route_new_dynamic(Route **ret);
void route_free(Route *route);
int route_configure(Route *route, Link *link, sd_rtnl_message_handler_t callback);
int route_drop(Route *route, Link *link, sd_rtnl_message_handler_t callback);


DEFINE_TRIVIAL_CLEANUP_FUNC(Route*, route_free);
#define _cleanup_route_free_ _cleanup_(route_freep)

int config_parse_gateway(const char *unit, const char *filename, unsigned line,
                         const char *section, unsigned section_line, const char *lvalue,
                         int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_destination(const char *unit, const char *filename, unsigned line,
                             const char *section, unsigned section_line, const char *lvalue,
                             int ltype, const char *rvalue, void *data, void *userdata);

/* Address */
int address_new_static(Network *network, unsigned section, Address **ret);
int address_new_dynamic(Address **ret);
void address_free(Address *address);
int address_configure(Address *address, Link *link, sd_rtnl_message_handler_t callback);
int address_drop(Address *address, Link *link, sd_rtnl_message_handler_t callback);

DEFINE_TRIVIAL_CLEANUP_FUNC(Address*, address_free);
#define _cleanup_address_free_ _cleanup_(address_freep)

int config_parse_dns(const char *unit, const char *filename, unsigned line,
                     const char *section, unsigned section_line, const char *lvalue,
                     int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_address(const char *unit, const char *filename, unsigned line,
                         const char *section, unsigned section_line, const char *lvalue,
                         int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_broadcast(const char *unit, const char *filename, unsigned line,
                           const char *section, unsigned section_line, const char *lvalue,
                           int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_label(const char *unit, const char *filename, unsigned line,
                       const char *section, unsigned section_line, const char *lvalue,
                       int ltype, const char *rvalue, void *data, void *userdata);

/* Link */

int link_new(Manager *manager, struct udev_device *device, Link **ret);
void link_free(Link *link);
int link_get(Manager *m, int ifindex, Link **ret);
int link_add(Manager *manager, struct udev_device *device, Link **ret);

int link_update(Link *link, sd_rtnl_message *message);

int link_save(Link *link);

const char* link_state_to_string(LinkState s) _const_;
LinkState link_state_from_string(const char *s) _pure_;

DEFINE_TRIVIAL_CLEANUP_FUNC(Link*, link_free);
#define _cleanup_link_free_ _cleanup_(link_freep)

/* Macros which append INTERFACE= to the message */

#define log_full_link(level, link, fmt, ...) log_meta_object(level, __FILE__, __LINE__, __func__, "INTERFACE=", link->ifname, "%s: " fmt, link->ifname, ##__VA_ARGS__)
#define log_debug_link(link, ...)       log_full_link(LOG_DEBUG, link, ##__VA_ARGS__)
#define log_info_link(link, ...)        log_full_link(LOG_INFO, link, ##__VA_ARGS__)
#define log_notice_link(link, ...)      log_full_link(LOG_NOTICE, link, ##__VA_ARGS__)
#define log_warning_link(link, ...)     log_full_link(LOG_WARNING, link, ##__VA_ARGS__)
#define log_error_link(link, ...)       log_full_link(LOG_ERR, link, ##__VA_ARGS__)

#define log_struct_link(level, link, ...) log_struct(level, "INTERFACE=%s", link->ifname, __VA_ARGS__)

/* More macros which append INTERFACE= to the message */

#define log_full_netdev(level, netdev, fmt, ...) log_meta_object(level, __FILE__, __LINE__, __func__, "INTERFACE=", netdev->name, "%s: " fmt, netdev->name, ##__VA_ARGS__)
#define log_debug_netdev(netdev, ...)       log_full_netdev(LOG_DEBUG, netdev, ##__VA_ARGS__)
#define log_info_netdev(netdev, ...)        log_full_netdev(LOG_INFO, netdev, ##__VA_ARGS__)
#define log_notice_netdev(netdev, ...)      log_full_netdev(LOG_NOTICE, netdev, ##__VA_ARGS__)
#define log_warning_netdev(netdev, ...)     log_full_netdev(LOG_WARNING, netdev,## __VA_ARGS__)
#define log_error_netdev(netdev, ...)       log_full_netdev(LOG_ERR, netdev, ##__VA_ARGS__)

#define log_struct_netdev(level, netdev, ...) log_struct(level, "INTERFACE=%s", netdev->name, __VA_ARGS__)

#define NETDEV(netdev) "INTERFACE=%s", netdev->name
#define ADDRESS_FMT_VAL(address)            \
        (address).s_addr & 0xFF,            \
        ((address).s_addr >> 8) & 0xFF,     \
        ((address).s_addr >> 16) & 0xFF,    \
        (address).s_addr >> 24
