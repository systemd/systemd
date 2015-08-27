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

#include <inttypes.h>
#include <stdbool.h>

#include "in-addr-util.h"

typedef struct Address Address;

#include "networkd.h"
#include "networkd-network.h"
#include "networkd-link.h"

#define CACHE_INFO_INFINITY_LIFE_TIME 0xFFFFFFFFU

struct Address {
        Network *network;
        unsigned section;

        int family;
        unsigned char prefixlen;
        unsigned char scope;
        uint32_t flags;
        char *label;

        struct in_addr broadcast;
        struct ifa_cacheinfo cinfo;

        union in_addr_union in_addr;
        union in_addr_union in_addr_peer;

        bool ip_masquerade_done;

        LIST_FIELDS(Address, addresses);
};

int address_new_static(Network *network, unsigned section, Address **ret);
int address_new_dynamic(Address **ret);
void address_free(Address *address);
int address_configure(Address *address, Link *link, sd_netlink_message_handler_t callback);
int address_update(Address *address, Link *link, sd_netlink_message_handler_t callback);
int address_drop(Address *address, Link *link, sd_netlink_message_handler_t callback);
int address_establish(Address *address, Link *link);
int address_release(Address *address, Link *link);
bool address_equal(Address *a1, Address *a2);

DEFINE_TRIVIAL_CLEANUP_FUNC(Address*, address_free);
#define _cleanup_address_free_ _cleanup_(address_freep)

int config_parse_address(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_broadcast(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_label(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
