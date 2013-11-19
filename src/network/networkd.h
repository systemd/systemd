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
#include <linux/rtnetlink.h>

#include "sd-event.h"
#include "sd-rtnl.h"
#include "udev.h"

#include "rtnl-util.h"
#include "hashmap.h"
#include "list.h"

typedef struct Network Network;
typedef struct Link Link;
typedef struct Address Address;
typedef struct Route Route;
typedef struct Manager Manager;

struct Network {
        Manager *manager;

        char *filename;

        struct ether_addr *match_mac;
        char *match_path;
        char *match_driver;
        char *match_type;
        char *match_name;

        char *description;

        LIST_HEAD(Address, addresses);
        LIST_HEAD(Route, routes);

        Hashmap *addresses_by_section;
        Hashmap *routes_by_section;

        LIST_FIELDS(Network, networks);
};

struct Address {
        Network *network;
        uint64_t section;

        unsigned char family;
        unsigned char prefixlen;
        char *label;

        struct in_addr netmask;

        union {
                struct in_addr in;
                struct in6_addr in6;
        } in_addr;

        LIST_FIELDS(Address, addresses);
};

struct Route {
        Network *network;
        uint64_t section;

        unsigned char family;
        unsigned char dst_prefixlen;

        union {
                struct in_addr in;
                struct in6_addr in6;
        } in_addr;

        union {
                struct in_addr in;
                struct in6_addr in6;
        } dst_addr;

        LIST_FIELDS(Route, routes);
};

typedef enum LinkState {
        LINK_STATE_SET_ADDRESSES,
        LINK_STATE_ADDRESSES_SET,
        LINK_STATE_SET_ROUTES,
        LINK_STATE_ROUTES_SET,
        LINK_STATE_CONFIGURED,
        LINK_STATE_FAILED,
        _LINK_STATE_MAX,
        _LINK_STATE_INVALID = -1
} LinkState;

struct Link {
        Manager *manager;

        uint64_t ifindex;
        struct ether_addr mac;

        unsigned flags;

        Network *network;

        LinkState state;

        unsigned rtnl_messages;
};

struct Manager {
        sd_rtnl *rtnl;
        sd_event *event;
        struct udev *udev;
        struct udev_monitor *udev_monitor;
        sd_event_source *udev_event_source;

        Hashmap *links;
        LIST_HEAD(Network, networks);

        char **network_dirs;
        usec_t network_dirs_ts_usec;
};

/* Manager */

int manager_new(Manager **ret);
void manager_free(Manager *m);

int manager_udev_enumerate_links(Manager *m);
int manager_udev_listen(Manager *m);

int manager_rtnl_listen(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);
#define _cleanup_manager_free_ _cleanup_(manager_freep)

/* Network */

int network_load(Manager *manager);
bool network_should_reload(Manager *manager);

void network_free(Network *network);

DEFINE_TRIVIAL_CLEANUP_FUNC(Network*, network_free);
#define _cleanup_network_free_ _cleanup_(network_freep)

int network_get(Manager *manager, struct udev_device *device, Network **ret);
int network_apply(Manager *manager, Network *network, Link *link);

const struct ConfigPerfItem* network_gperf_lookup(const char *key, unsigned length);

/* Route */
int route_new(Network *network, unsigned section, Route **ret);
void route_free(Route *route);
int route_configure(Route *route, Link *link, sd_rtnl_message_handler_t callback);

DEFINE_TRIVIAL_CLEANUP_FUNC(Route*, route_free);
#define _cleanup_route_free_ _cleanup_(route_freep)

int config_parse_gateway(const char *unit, const char *filename, unsigned line,
                         const char *section, unsigned section_line, const char *lvalue,
                         int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_destination(const char *unit, const char *filename, unsigned line,
                             const char *section, unsigned section_line, const char *lvalue,
                             int ltype, const char *rvalue, void *data, void *userdata);

/* Address */
int address_new(Network *network, unsigned section, Address **ret);
void address_free(Address *address);
int address_configure(Address *address, Link *link, sd_rtnl_message_handler_t callback);

DEFINE_TRIVIAL_CLEANUP_FUNC(Address*, address_free);
#define _cleanup_address_free_ _cleanup_(address_freep)

int config_parse_address(const char *unit, const char *filename, unsigned line,
                         const char *section, unsigned section_line, const char *lvalue,
                         int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_label(const char *unit, const char *filename, unsigned line,
                       const char *section, unsigned section_line, const char *lvalue,
                       int ltype, const char *rvalue, void *data, void *userdata);

/* Link */

int link_new(Manager *manager, struct udev_device *device, Link **ret);
void link_free(Link *link);
int link_add(Manager *manager, struct udev_device *device);
int link_configure(Link *link);

DEFINE_TRIVIAL_CLEANUP_FUNC(Link*, link_free);
#define _cleanup_link_free_ _cleanup_(link_freep)
