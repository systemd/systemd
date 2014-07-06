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

#include "networkd-netdev.h"

extern const NetDevVTable bond_vtable;

typedef enum BondMode {
        NETDEV_BOND_MODE_BALANCE_RR,
        NETDEV_BOND_MODE_ACTIVE_BACKUP,
        NETDEV_BOND_MODE_BALANCE_XOR,
        NETDEV_BOND_MODE_BROADCAST,
        NETDEV_BOND_MODE_802_3AD,
        NETDEV_BOND_MODE_BALANCE_TLB,
        NETDEV_BOND_MODE_BALANCE_ALB,
        _NETDEV_BOND_MODE_MAX,
        _NETDEV_BOND_MODE_INVALID = -1
} BondMode;

const char *bond_mode_to_string(BondMode d) _const_;
BondMode bond_mode_from_string(const char *d) _pure_;

int config_parse_bond_mode(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
