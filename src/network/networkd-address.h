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

#include <inttypes.h>
#include <stdbool.h>

#include "in-addr-util.h"

typedef struct Address Address;
typedef struct Prefix Prefix;

#include "networkd-link.h"
#include "networkd-network.h"

#define CACHE_INFO_INFINITY_LIFE_TIME 0xFFFFFFFFU

typedef struct Network Network;
typedef struct Link Link;
typedef struct NetworkConfigSection NetworkConfigSection;

struct Prefix {
        Network *network;
        NetworkConfigSection *section;

        sd_radv_prefix *radv_prefix;

        LIST_FIELDS(Prefix, prefixes);
};

struct Address {
        Network *network;
        NetworkConfigSection *section;

        Link *link;

        int family;
        unsigned char prefixlen;
        unsigned char scope;
        uint32_t flags;
        char *label;

        struct in_addr broadcast;
        struct ifa_cacheinfo cinfo;

        union in_addr_union in_addr;
        union in_addr_union in_addr_peer;

        bool ip_masquerade_done:1;
        bool duplicate_address_detection;
        bool manage_temporary_address;
        bool home_address;
        bool prefix_route;
        bool autojoin;

        LIST_FIELDS(Address, addresses);
};

int address_new_static(Network *network, const char *filename, unsigned section, Address **ret);
int address_new(Address **ret);
void address_free(Address *address);
int address_add_foreign(Link *link, int family, const union in_addr_union *in_addr, unsigned char prefixlen, Address **ret);
int address_add(Link *link, int family, const union in_addr_union *in_addr, unsigned char prefixlen, Address **ret);
int address_get(Link *link, int family, const union in_addr_union *in_addr, unsigned char prefixlen, Address **ret);
int address_update(Address *address, unsigned char flags, unsigned char scope, const struct ifa_cacheinfo *cinfo);
int address_drop(Address *address);
int address_configure(Address *address, Link *link, sd_netlink_message_handler_t callback, bool update);
int address_remove(Address *address, Link *link, sd_netlink_message_handler_t callback);
bool address_equal(Address *a1, Address *a2);
bool address_is_ready(const Address *a);

DEFINE_TRIVIAL_CLEANUP_FUNC(Address*, address_free);
#define _cleanup_address_free_ _cleanup_(address_freep)

int prefix_new(Prefix **ret);
void prefix_free(Prefix *prefix);
int prefix_new_static(Network *network, const char *filename, unsigned section,
                      Prefix **ret);

DEFINE_TRIVIAL_CLEANUP_FUNC(Prefix*, prefix_free);
#define _cleanup_prefix_free_ _cleanup_(prefix_freep)

int config_parse_address(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_broadcast(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_label(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_lifetime(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_address_flags(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_router_preference(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_prefix(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_prefix_flags(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_prefix_lifetime(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
