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

typedef struct TunTap TunTap;

#include "networkd-netdev.h"

struct TunTap {
        NetDev meta;

        char *user_name;
        char *group_name;
        bool one_queue;
        bool multi_queue;
        bool packet_info;
        bool vnet_hdr;
};

extern const NetDevVTable tun_vtable;
extern const NetDevVTable tap_vtable;
