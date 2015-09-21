/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2014 Axis Communications AB. All rights reserved.

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

#include <netinet/if_ether.h>

#include "sparse-endian.h"
#include "socket-util.h"

int arp_network_bind_raw_socket(int index, be32_t address, const struct ether_addr *eth_mac);

int arp_send_probe(int fd, int ifindex,
                   be32_t pa, const struct ether_addr *ha);
int arp_send_announcement(int fd, int ifindex,
                          be32_t pa, const struct ether_addr *ha);
