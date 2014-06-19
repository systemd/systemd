/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2014 Intel Corporation. All rights reserved.

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
#include <netinet/in.h>

#include "sparse-endian.h"
#include "sd-event.h"
#include "list.h"

typedef struct DHCP6Address DHCP6Address;

struct DHCP6Address {
        LIST_FIELDS(DHCP6Address, addresses);

        struct {
                struct in6_addr address;
                be32_t lifetime_preferred;
                be32_t lifetime_valid;
        } _packed_;
};

struct DHCP6IA {
        uint16_t type;
        struct {
                be32_t id;
                be32_t lifetime_t1;
                be32_t lifetime_t2;
        } _packed_;
        sd_event_source *timeout_t1;
        sd_event_source *timeout_t2;

        LIST_HEAD(DHCP6Address, addresses);
};

typedef struct DHCP6IA DHCP6IA;

#define log_dhcp6_client(p, fmt, ...) log_meta(LOG_DEBUG, __FILE__, __LINE__, __func__, "DHCPv6 CLIENT: " fmt, ##__VA_ARGS__)

int dhcp_network_icmp6_bind_router_solicitation(int index);
int dhcp_network_icmp6_send_router_solicitation(int s, const struct ether_addr *ether_addr);
