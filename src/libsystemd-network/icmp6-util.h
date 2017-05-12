#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2014-2015 Intel Corporation. All rights reserved.

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

#include <net/ethernet.h>

#include "time-util.h"

#define IN6ADDR_ALL_ROUTERS_MULTICAST_INIT \
        { { { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 } } }

#define IN6ADDR_ALL_NODES_MULTICAST_INIT \
        { { { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } } }

int icmp6_bind_router_solicitation(int index);
int icmp6_bind_router_advertisement(int index);
int icmp6_send_router_solicitation(int s, const struct ether_addr *ether_addr);
int icmp6_receive(int fd, void *buffer, size_t size, struct in6_addr *dst,
                  triple_timestamp *timestamp);
