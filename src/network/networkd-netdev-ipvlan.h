/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014-2015 Tom Gundersen <teg@jklm.no>

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

typedef struct IPVlan IPVlan;

#include "missing.h"
#include "networkd-netdev.h"

typedef enum IPVlanMode {
        NETDEV_IPVLAN_MODE_L2 = IPVLAN_MODE_L2,
        NETDEV_IPVLAN_MODE_L3 = IPVLAN_MODE_L3,
        _NETDEV_IPVLAN_MODE_MAX,
        _NETDEV_IPVLAN_MODE_INVALID = -1
} IPVlanMode;

struct IPVlan {
        NetDev meta;

        IPVlanMode mode;
};

extern const NetDevVTable ipvlan_vtable;

const char *ipvlan_mode_to_string(IPVlanMode d) _const_;
IPVlanMode ipvlan_mode_from_string(const char *d) _pure_;

int config_parse_ipvlan_mode(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
