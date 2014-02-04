/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2013 Intel Corporation. All rights reserved.
  Copyright (C) 2014 Tom Gundersen

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

#include <stdint.h>
#include <linux/if_packet.h>

#include "socket-util.h"
#include "refcnt.h"

#include "dhcp-protocol.h"

#include "sd-dhcp-client.h"

struct sd_dhcp_lease {
        RefCount n_ref;

        uint32_t t1;
        uint32_t t2;
        uint32_t lifetime;
        be32_t address;
        be32_t server_address;
        be32_t subnet_mask;
        be32_t router;
        struct in_addr *dns;
        size_t dns_size;
        uint16_t mtu;
        char *domainname;
        char *hostname;
};

int dhcp_lease_new(sd_dhcp_lease **ret);
int dhcp_lease_parse_options(uint8_t code, uint8_t len, const uint8_t *option,
                              void *user_data);

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_dhcp_lease*, sd_dhcp_lease_unref);
#define _cleanup_dhcp_lease_unref_ _cleanup_(sd_dhcp_lease_unrefp)
