/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
 This file is part of systemd.

 Copyright (C) 2013 Tom Gundersen <teg@jklm.no>

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

#include <macro.h>

/* we can't use DUPLEX_ prefix, as it
 * clashes with <linux/ethtool.h> */
typedef enum Duplex {
        DUP_FULL,
        DUP_HALF,
        _DUP_MAX,
        _DUP_INVALID = -1
} Duplex;

typedef enum WakeOnLan {
        WOL_PHY,
        WOL_MAGIC,
        WOL_OFF,
        _WOL_MAX,
        _WOL_INVALID = -1
} WakeOnLan;

int ethtool_connect(int *ret);

int ethtool_get_driver(int *fd, const char *ifname, char **ret);
int ethtool_set_speed(int *fd, const char *ifname, unsigned int speed, Duplex duplex);
int ethtool_set_wol(int *fd, const char *ifname, WakeOnLan wol);

const char *duplex_to_string(Duplex d) _const_;
Duplex duplex_from_string(const char *d) _pure_;

const char *wol_to_string(WakeOnLan wol) _const_;
WakeOnLan wol_from_string(const char *wol) _pure_;

int config_parse_duplex(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_wol(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
