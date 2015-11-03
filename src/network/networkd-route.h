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

typedef struct Route Route;

#include "networkd.h"
#include "networkd-network.h"

struct Route {
        Network *network;
        unsigned section;

        Link *link;

        int family;
        unsigned char dst_prefixlen;
        unsigned char src_prefixlen;
        unsigned char scope;
        unsigned char protocol;  /* RTPROT_* */
        unsigned char tos;
        uint32_t priority; /* note that ip(8) calls this 'metric' */
        unsigned char table;
        unsigned char pref;
        unsigned flags;

        union in_addr_union gw;
        union in_addr_union dst;
        union in_addr_union src;
        union in_addr_union prefsrc;

        usec_t lifetime;
        sd_event_source *expire;

        LIST_FIELDS(Route, routes);
};

int route_new_static(Network *network, unsigned section, Route **ret);
int route_new(Route **ret);
void route_free(Route *route);
int route_configure(Route *route, Link *link, sd_netlink_message_handler_t callback);
int route_remove(Route *route, Link *link, sd_netlink_message_handler_t callback);

int route_get(Link *link, int family, union in_addr_union *dst, unsigned char dst_prefixlen, unsigned char tos, uint32_t priority, unsigned char table, Route **ret);
int route_add(Link *link, int family, union in_addr_union *dst, unsigned char dst_prefixlen, unsigned char tos, uint32_t priority, unsigned char table, Route **ret);
int route_add_foreign(Link *link, int family, union in_addr_union *dst, unsigned char dst_prefixlen, unsigned char tos, uint32_t priority, unsigned char table, Route **ret);
int route_update(Route *route, union in_addr_union *src, unsigned char src_prefixlen, union in_addr_union *gw, union in_addr_union *prefsrc, unsigned char scope, unsigned char protocol);
void route_drop(Route *route);

int route_expire_handler(sd_event_source *s, uint64_t usec, void *userdata);

DEFINE_TRIVIAL_CLEANUP_FUNC(Route*, route_free);
#define _cleanup_route_free_ _cleanup_(route_freep)

int config_parse_gateway(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_preferred_src(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_destination(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_route_priority(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_route_scope(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
