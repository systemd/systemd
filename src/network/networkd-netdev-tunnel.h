/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Tom Gundersen <teg@jklm.no>

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

typedef struct Tunnel Tunnel;

#include "networkd-netdev.h"

typedef enum Ip6TnlMode {
        NETDEV_IP6_TNL_MODE_IP6IP6,
        NETDEV_IP6_TNL_MODE_IPIP6,
        NETDEV_IP6_TNL_MODE_ANYIP6,
        _NETDEV_IP6_TNL_MODE_MAX,
        _NETDEV_IP6_TNL_MODE_INVALID = -1,
} Ip6TnlMode;

typedef enum IPv6FlowLabel {
        NETDEV_IPV6_FLOWLABEL_INHERIT = 0xFFFFF + 1,
        _NETDEV_IPV6_FLOWLABEL_MAX,
        _NETDEV_IPV6_FLOWLABEL_INVALID = -1,
} IPv6FlowLabel;

struct Tunnel {
        NetDev meta;

        uint8_t encap_limit;

        int family;
        int ipv6_flowlabel;

        unsigned ttl;
        unsigned tos;
        unsigned flags;

        union in_addr_union local;
        union in_addr_union remote;

        Ip6TnlMode ip6tnl_mode;

        bool pmtudisc;
        bool copy_dscp;
};

extern const NetDevVTable ipip_vtable;
extern const NetDevVTable sit_vtable;
extern const NetDevVTable vti_vtable;
extern const NetDevVTable vti6_vtable;
extern const NetDevVTable gre_vtable;
extern const NetDevVTable gretap_vtable;
extern const NetDevVTable ip6gre_vtable;
extern const NetDevVTable ip6gretap_vtable;
extern const NetDevVTable ip6tnl_vtable;

const char *ip6tnl_mode_to_string(Ip6TnlMode d) _const_;
Ip6TnlMode ip6tnl_mode_from_string(const char *d) _pure_;

int config_parse_ip6tnl_mode(const char *unit, const char *filename,
                             unsigned line, const char *section,
                             unsigned section_line, const char *lvalue,
                             int ltype, const char *rvalue, void *data,
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

int config_parse_ipv6_flowlabel(const char *unit, const char *filename,
                                unsigned line, const char *section,
                                unsigned section_line, const char *lvalue,
                                int ltype, const char *rvalue, void *data,
                                void *userdata);
