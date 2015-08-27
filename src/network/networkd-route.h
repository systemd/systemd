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

int route_new_static(Network *network, unsigned section, Route **ret);
int route_new_dynamic(Route **ret, unsigned char rtm_protocol);
void route_free(Route *route);
int route_configure(Route *route, Link *link, sd_netlink_message_handler_t callback);
int route_drop(Route *route, Link *link, sd_netlink_message_handler_t callback);

DEFINE_TRIVIAL_CLEANUP_FUNC(Route*, route_free);
#define _cleanup_route_free_ _cleanup_(route_freep)

int config_parse_gateway(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_destination(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_route_priority(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_route_scope(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
