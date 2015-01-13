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
#include "sd-dhcp-server.h"
#include "sd-ipv4ll.h"
#include "sd-icmp6-nd.h"
#include "sd-dhcp6-client.h"
#include "udev.h"
#include "sd-lldp.h"

#include "rtnl-util.h"
#include "hashmap.h"
#include "list.h"
#include "set.h"
#include "condition.h"
#include "in-addr-util.h"

#define CACHE_INFO_INFINITY_LIFE_TIME 0xFFFFFFFFU
#define DHCP_ROUTE_METRIC 1024
#define IPV4LL_ROUTE_METRIC 2048

typedef struct NetDev NetDev;
typedef struct Network Network;
typedef struct Link Link;
typedef struct Address Address;
typedef struct Route Route;
typedef struct Manager Manager;
typedef struct AddressPool AddressPool;
typedef struct FdbEntry FdbEntry;

typedef enum AddressFamilyBoolean {
        /* This is a bitmask, though it usually doesn't feel that way! */
        ADDRESS_FAMILY_NO = 0,
        ADDRESS_FAMILY_IPV4 = 1,
        ADDRESS_FAMILY_IPV6 = 2,
        ADDRESS_FAMILY_YES = 3,
        _ADDRESS_FAMILY_BOOLEAN_MAX,
        _ADDRESS_FAMILY_BOOLEAN_INVALID = -1,
} AddressFamilyBoolean;

typedef enum LLMNRSupport {
        LLMNR_SUPPORT_NO,
        LLMNR_SUPPORT_YES,
        LLMNR_SUPPORT_RESOLVE,
        _LLMNR_SUPPORT_MAX,
        _LLMNR_SUPPORT_INVALID = -1,
} LLMNRSupport;

struct FdbEntry {
        Network *network;
        unsigned section;

        struct ether_addr *mac_addr;
        uint16_t vlan_id;

        LIST_FIELDS(FdbEntry, static_fdb_entries);
};

struct Network {
        Manager *manager;

        char *filename;

        struct ether_addr *match_mac;
        char *match_path;
        char *match_driver;
        char *match_type;
        char *match_name;
        char *dhcp_vendor_class_identifier;

        Condition *match_host;
        Condition *match_virt;
        Condition *match_kernel;
        Condition *match_arch;

        char *description;
        NetDev *bridge;
        NetDev *bond;
        Hashmap *stacked_netdevs;
        AddressFamilyBoolean dhcp;
        bool dhcp_dns;
        bool dhcp_ntp;
        bool dhcp_mtu;
        bool dhcp_hostname;
        bool dhcp_domains;
        bool dhcp_sendhost;
        bool dhcp_broadcast;
        bool dhcp_critical;
        bool dhcp_routes;
        unsigned dhcp_route_metric;
        bool ipv4ll;
        bool ipv4ll_route;

        bool dhcp_server;

        unsigned cost;

        AddressFamilyBoolean ip_forward;
        bool ip_masquerade;

        struct ether_addr *mac;
        unsigned mtu;

        bool lldp;

        LIST_HEAD(Address, static_addresses);
        LIST_HEAD(Route, static_routes);
        LIST_HEAD(FdbEntry, static_fdb_entries);

        Hashmap *addresses_by_section;
        Hashmap *routes_by_section;
        Hashmap *fdb_entries_by_section;

        bool wildcard_domain;
        char **domains, **dns, **ntp;

        LLMNRSupport llmnr;

        LIST_FIELDS(Network, networks);
};

struct Address {
        Network *network;
        unsigned section;

        int family;
        unsigned char prefixlen;
        unsigned char scope;
        unsigned char flags;
        char *label;

        struct in_addr broadcast;
        struct ifa_cacheinfo cinfo;

        union in_addr_union in_addr;
        union in_addr_union in_addr_peer;

        bool ip_masquerade_done;

        LIST_FIELDS(Address, addresses);
};

struct Route {
        Network *network;
        unsigned section;

        int family;
        unsigned char dst_prefixlen;
        unsigned char src_prefixlen;
        unsigned char scope;
        uint32_t metrics;
        unsigned char protocol;  /* RTPROT_* */

        union in_addr_union in_addr;
        union in_addr_union dst_addr;
        union in_addr_union src_addr;
        union in_addr_union prefsrc_addr;

        LIST_FIELDS(Route, routes);
};

struct AddressPool {
        Manager *manager;

        int family;
        unsigned prefixlen;

        union in_addr_union in_addr;

        LIST_FIELDS(AddressPool, address_pools);
};

struct Manager {
        sd_rtnl *rtnl;
        sd_event *event;
        sd_bus *bus;
        struct udev *udev;
        struct udev_monitor *udev_monitor;
        sd_event_source *udev_event_source;

        char *state_file;

        Hashmap *links;
        Hashmap *netdevs;
        LIST_HEAD(Network, networks);
        LIST_HEAD(AddressPool, address_pools);

        usec_t network_dirs_ts_usec;
};

extern const char* const network_dirs[];

/* Manager */

int manager_new(Manager **ret);
void manager_free(Manager *m);

int manager_load_config(Manager *m);
bool manager_should_reload(Manager *m);

int manager_rtnl_enumerate_links(Manager *m);
int manager_rtnl_enumerate_addresses(Manager *m);

int manager_rtnl_listen(Manager *m);
int manager_udev_listen(Manager *m);
int manager_bus_listen(Manager *m);

int manager_save(Manager *m);

int manager_address_pool_acquire(Manager *m, int family, unsigned prefixlen, union in_addr_union *found);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);
#define _cleanup_manager_free_ _cleanup_(manager_freep)

/* Network */

int network_load(Manager *manager);

void network_free(Network *network);

DEFINE_TRIVIAL_CLEANUP_FUNC(Network*, network_free);
#define _cleanup_network_free_ _cleanup_(network_freep)

int network_get(Manager *manager, struct udev_device *device,
                const char *ifname, const struct ether_addr *mac,
                Network **ret);
int network_apply(Manager *manager, Network *network, Link *link);

int config_parse_netdev(const char *unit, const char *filename, unsigned line,
                        const char *section, unsigned section_line, const char *lvalue,
                        int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_domains(const char *unit,
                         const char *filename,
                         unsigned line,
                         const char *section,
                         unsigned section_line,
                         const char *lvalue,
                         int ltype,
                         const char *rvalue,
                         void *data,
                         void *userdata);

int config_parse_tunnel(const char *unit,
                        const char *filename,
                        unsigned line,
                        const char *section,
                        unsigned section_line,
                        const char *lvalue,
                        int ltype,
                        const char *rvalue,
                        void *data,
                        void *userdata);

int config_parse_tunnel_address(const char *unit,
                                const char *filename,
                                unsigned line,
                                const char *section,
                                unsigned section_line,
                                const char *lvalue,
                                int ltype,
                                const char *rvalue,
                                void *data,
                                void *userdata);

int config_parse_vxlan_group_address(const char *unit,
                                     const char *filename,
                                     unsigned line,
                                     const char *section,
                                     unsigned section_line,
                                     const char *lvalue,
                                     int ltype,
                                     const char *rvalue,
                                     void *data,
                                     void *userdata);

/* gperf */
const struct ConfigPerfItem* network_network_gperf_lookup(const char *key, unsigned length);

/* Route */
int route_new_static(Network *network, unsigned section, Route **ret);
int route_new_dynamic(Route **ret, unsigned char rtm_protocol);
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

int config_parse_route_priority(const char *unit, const char *filename, unsigned line,
                                const char *section, unsigned section_line, const char *lvalue,
                                int ltype, const char *rvalue, void *data, void *userdata);
/* Address */
int address_new_static(Network *network, unsigned section, Address **ret);
int address_new_dynamic(Address **ret);
void address_free(Address *address);
int address_configure(Address *address, Link *link, sd_rtnl_message_handler_t callback);
int address_update(Address *address, Link *link, sd_rtnl_message_handler_t callback);
int address_drop(Address *address, Link *link, sd_rtnl_message_handler_t callback);
int address_establish(Address *address, Link *link);
int address_release(Address *address, Link *link);
bool address_equal(Address *a1, Address *a2);

DEFINE_TRIVIAL_CLEANUP_FUNC(Address*, address_free);
#define _cleanup_address_free_ _cleanup_(address_freep)

int config_parse_address(const char *unit, const char *filename, unsigned line,
                         const char *section, unsigned section_line, const char *lvalue,
                         int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_broadcast(const char *unit, const char *filename, unsigned line,
                           const char *section, unsigned section_line, const char *lvalue,
                           int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_label(const char *unit, const char *filename, unsigned line,
                       const char *section, unsigned section_line, const char *lvalue,
                       int ltype, const char *rvalue, void *data, void *userdata);

/* Forwarding database table. */
int fdb_entry_configure(sd_rtnl *const rtnl, FdbEntry *const fdb_entry, const int ifindex);
void fdb_entry_free(FdbEntry *fdb_entry);
int fdb_entry_new_static(Network *const network, const unsigned section, FdbEntry **ret);

DEFINE_TRIVIAL_CLEANUP_FUNC(FdbEntry*, fdb_entry_free);
#define _cleanup_fdbentry_free_ _cleanup_(fdb_entry_freep)

int config_parse_fdb_hwaddr(const char *unit, const char *filename, unsigned line,
                            const char *section, unsigned section_line, const char *lvalue,
                            int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_fdb_vlan_id(const char *unit, const char *filename, unsigned line,
                             const char *section, unsigned section_line, const char *lvalue,
                             int ltype, const char *rvalue, void *data, void *userdata);

/* DHCP support */

int config_parse_dhcp(const char *unit, const char *filename, unsigned line,
                      const char *section, unsigned section_line, const char *lvalue,
                      int ltype, const char *rvalue, void *data, void *userdata);

/* LLMNR support */

const char* llmnr_support_to_string(LLMNRSupport i) _const_;
LLMNRSupport llmnr_support_from_string(const char *s) _pure_;

int config_parse_llmnr(const char *unit, const char *filename, unsigned line,
                      const char *section, unsigned section_line, const char *lvalue,
                      int ltype, const char *rvalue, void *data, void *userdata);

/* Address Pool */

int address_pool_new(Manager *m, AddressPool **ret, int family, const union in_addr_union *u, unsigned prefixlen);
int address_pool_new_from_string(Manager *m, AddressPool **ret, int family, const char *p, unsigned prefixlen);
void address_pool_free(AddressPool *p);

int address_pool_acquire(AddressPool *p, unsigned prefixlen, union in_addr_union *found);

const char *address_family_boolean_to_string(AddressFamilyBoolean b) _const_;
AddressFamilyBoolean address_family_boolean_from_string(const char *s) _const_;

int config_parse_address_family_boolean(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
