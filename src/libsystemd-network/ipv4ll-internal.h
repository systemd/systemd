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

int arp_network_bind_raw_socket(int index, union sockaddr_union *link);
int arp_network_send_raw_socket(int fd, const union sockaddr_union *link,
                                        const struct ether_arp *arp);

void arp_packet_init(struct ether_arp *arp);
void arp_packet_probe(struct ether_arp *arp, be32_t pa, const struct ether_addr *ha);
void arp_packet_announcement(struct ether_arp *arp, be32_t pa, const struct ether_addr *ha);
int arp_packet_verify_headers(struct ether_arp *arp);

#define log_ipv4ll(ll, fmt, ...) log_internal(LOG_DEBUG, 0, __FILE__, __LINE__, __func__, "IPv4LL: " fmt, ##__VA_ARGS__)
