/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosddhcp6leasehfoo
#define foosddhcp6leasehfoo

/***
  Copyright © 2014-2015 Intel Corporation. All rights reserved.

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <https://www.gnu.org/licenses/>.
***/

#include <inttypes.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_dhcp6_lease sd_dhcp6_lease;

int sd_dhcp6_lease_get_timestamp(sd_dhcp6_lease *lease, clockid_t clock, uint64_t *ret);
int sd_dhcp6_lease_get_server_address(sd_dhcp6_lease *lease, struct in6_addr *ret);

void sd_dhcp6_lease_reset_address_iter(sd_dhcp6_lease *lease);
int sd_dhcp6_lease_get_address(sd_dhcp6_lease *lease,
                               struct in6_addr *addr,
                               uint32_t *lifetime_preferred,
                               uint32_t *lifetime_valid);
void sd_dhcp6_lease_reset_pd_prefix_iter(sd_dhcp6_lease *lease);
int sd_dhcp6_lease_get_pd(sd_dhcp6_lease *lease, struct in6_addr *prefix,
                          uint8_t *prefix_len,
                          uint32_t *lifetime_preferred,
                          uint32_t *lifetime_valid);

int sd_dhcp6_lease_get_dns(sd_dhcp6_lease *lease, const struct in6_addr **ret);
int sd_dhcp6_lease_get_domains(sd_dhcp6_lease *lease, char ***ret);
int sd_dhcp6_lease_get_ntp_addrs(sd_dhcp6_lease *lease, const struct in6_addr **ret);
int sd_dhcp6_lease_get_ntp_fqdn(sd_dhcp6_lease *lease, char ***ret);
int sd_dhcp6_lease_get_fqdn(sd_dhcp6_lease *lease, const char **ret);

sd_dhcp6_lease *sd_dhcp6_lease_ref(sd_dhcp6_lease *lease);
sd_dhcp6_lease *sd_dhcp6_lease_unref(sd_dhcp6_lease *lease);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp6_lease, sd_dhcp6_lease_unref);

_SD_END_DECLARATIONS;

#endif
