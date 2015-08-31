/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include "condition.h"

typedef struct Network Network;

#include "networkd.h"
#include "networkd-netdev.h"
#include "networkd-address.h"
#include "networkd-route.h"
#include "networkd-fdb.h"
#include "networkd-util.h"

#define DHCP_ROUTE_METRIC 1024
#define IPV4LL_ROUTE_METRIC 2048

typedef enum DCHPClientIdentifier {
        DHCP_CLIENT_ID_MAC,
        DHCP_CLIENT_ID_DUID,
        _DHCP_CLIENT_ID_MAX,
        _DHCP_CLIENT_ID_INVALID = -1,
} DCHPClientIdentifier;

typedef enum IPv6PrivacyExtensions {
        /* The values map to the kernel's /proc/sys/net/ipv6/conf/xxx/use_tempaddr values */
        IPV6_PRIVACY_EXTENSIONS_NO,
        IPV6_PRIVACY_EXTENSIONS_PREFER_PUBLIC,
        IPV6_PRIVACY_EXTENSIONS_YES, /* aka prefer-temporary */
        _IPV6_PRIVACY_EXTENSIONS_MAX,
        _IPV6_PRIVACY_EXTENSIONS_INVALID = -1,
} IPv6PrivacyExtensions;

struct Network {
        Manager *manager;

        char *filename;
        char *name;

        struct ether_addr *match_mac;
        char **match_path;
        char **match_driver;
        char **match_type;
        char **match_name;

        Condition *match_host;
        Condition *match_virt;
        Condition *match_kernel;
        Condition *match_arch;

        char *description;

        NetDev *bridge;
        NetDev *bond;
        Hashmap *stacked_netdevs;

        /* DHCP Client Support */
        AddressFamilyBoolean dhcp;
        DCHPClientIdentifier dhcp_client_identifier;
        char *dhcp_vendor_class_identifier;
        char *hostname;
        bool dhcp_dns;
        bool dhcp_ntp;
        bool dhcp_mtu;
        bool dhcp_hostname;
        bool dhcp_domains;
        bool dhcp_sendhost;
        bool dhcp_broadcast;
        bool dhcp_critical;
        bool dhcp_routes;
        bool dhcp_timezone;
        unsigned dhcp_route_metric;

        /* DHCP Server Support */
        bool dhcp_server;
        bool dhcp_server_emit_dns;
        struct in_addr *dhcp_server_dns;
        unsigned n_dhcp_server_dns;
        bool dhcp_server_emit_ntp;
        struct in_addr *dhcp_server_ntp;
        unsigned n_dhcp_server_ntp;
        bool dhcp_server_emit_timezone;
        char *dhcp_server_timezone;
        usec_t dhcp_server_default_lease_time_usec, dhcp_server_max_lease_time_usec;
        uint32_t dhcp_server_pool_offset;
        uint32_t dhcp_server_pool_size;

        /* IPV4LL Support */
        AddressFamilyBoolean link_local;
        bool ipv4ll_route;

        /* Bridge Support */
        bool use_bpdu;
        bool hairpin;
        bool fast_leave;
        bool allow_port_to_be_root;
        bool unicast_flood;
        unsigned cost;

        AddressFamilyBoolean ip_forward;
        bool ip_masquerade;

        union in_addr_union ipv6_token;
        IPv6PrivacyExtensions ipv6_privacy_extensions;

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
        char **domains, **dns, **ntp, **bind_carrier;

        ResolveSupport llmnr;

        LIST_FIELDS(Network, networks);
};

void network_free(Network *network);

DEFINE_TRIVIAL_CLEANUP_FUNC(Network*, network_free);
#define _cleanup_network_free_ _cleanup_(network_freep)

int network_load(Manager *manager);

int network_get_by_name(Manager *manager, const char *name, Network **ret);
int network_get(Manager *manager, struct udev_device *device, const char *ifname, const struct ether_addr *mac, Network **ret);
int network_apply(Manager *manager, Network *network, Link *link);

int config_parse_netdev(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_domains(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_tunnel(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_dhcp(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_dhcp_client_identifier(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_ipv6token(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_ipv6_privacy_extensions(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_hostname(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_timezone(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_dhcp_server_dns(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_dhcp_server_ntp(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

/* Legacy IPv4LL support */
int config_parse_ipv4ll(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

const struct ConfigPerfItem* network_network_gperf_lookup(const char *key, unsigned length);

extern const sd_bus_vtable network_vtable[];

int network_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error);
int network_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error);

const char* ipv6_privacy_extensions_to_string(IPv6PrivacyExtensions i) _const_;
IPv6PrivacyExtensions ipv6_privacy_extensions_from_string(const char *s) _pure_;
