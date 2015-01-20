/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosddhcp6leasehfoo
#define foosddhcp6leasehfoo

/***
  This file is part of systemd.

  Copyright (C) 2014 Tom Gundersen
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

#include <netinet/in.h>

typedef struct sd_dhcp6_lease sd_dhcp6_lease;

void sd_dhcp6_lease_reset_address_iter(sd_dhcp6_lease *lease);
int sd_dhcp6_lease_get_address(sd_dhcp6_lease *lease,
                               struct in6_addr *addr,
                               uint32_t *lifetime_preferred,
                               uint32_t *lifetime_valid);

sd_dhcp6_lease *sd_dhcp6_lease_ref(sd_dhcp6_lease *lease);
sd_dhcp6_lease *sd_dhcp6_lease_unref(sd_dhcp6_lease *lease);

#endif
