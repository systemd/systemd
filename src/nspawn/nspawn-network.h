/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include <net/if.h>

#include <sys/types.h>
#include <stdbool.h>

int setup_veth(const char *machine_name, pid_t pid, char iface_name[IFNAMSIZ], bool bridge);

int setup_bridge(const char *veth_name, const char *bridge_name);

int setup_macvlan(const char *machine_name, pid_t pid, char **ifaces);
int setup_ipvlan(const char *machine_name, pid_t pid, char **ifaces);

int move_network_interfaces(pid_t pid, char **ifaces);
