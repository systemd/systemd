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

#include "sd-dhcp6-option.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_dhcp6_lease sd_dhcp6_lease;
typedef struct sd_dns_resolver sd_dns_resolver;

int sd_dhcp6_lease_get_timestamp(sd_dhcp6_lease *lease, clockid_t clock, uint64_t *ret);
int sd_dhcp6_lease_get_t1(sd_dhcp6_lease *lease, uint64_t *ret);
int sd_dhcp6_lease_get_t1_timestamp(sd_dhcp6_lease *lease, clockid_t clock, uint64_t *ret);
int sd_dhcp6_lease_get_t2(sd_dhcp6_lease *lease, uint64_t *ret);
int sd_dhcp6_lease_get_t2_timestamp(sd_dhcp6_lease *lease, clockid_t clock, uint64_t *ret);
int sd_dhcp6_lease_get_valid_lifetime(sd_dhcp6_lease *lease, uint64_t *ret);
int sd_dhcp6_lease_get_valid_lifetime_timestamp(sd_dhcp6_lease *lease, clockid_t clock, uint64_t *ret);
int sd_dhcp6_lease_get_server_address(sd_dhcp6_lease *lease, struct in6_addr *ret);

int sd_dhcp6_lease_address_iterator_reset(sd_dhcp6_lease *lease);
int sd_dhcp6_lease_address_iterator_next(sd_dhcp6_lease *lease);
int sd_dhcp6_lease_get_address(
                sd_dhcp6_lease *lease,
                struct in6_addr *ret);
int sd_dhcp6_lease_get_address_lifetime(
                sd_dhcp6_lease *lease,
                uint64_t *ret_lifetime_preferred,
                uint64_t *ret_lifetime_valid);
int sd_dhcp6_lease_get_address_lifetime_timestamp(
                sd_dhcp6_lease *lease,
                clockid_t clock,
                uint64_t *ret_lifetime_preferred,
                uint64_t *ret_lifetime_valid);
int sd_dhcp6_lease_has_address(sd_dhcp6_lease *lease);

int sd_dhcp6_lease_pd_iterator_reset(sd_dhcp6_lease *lease);
int sd_dhcp6_lease_pd_iterator_next(sd_dhcp6_lease *lease);
int sd_dhcp6_lease_get_pd_prefix(
                sd_dhcp6_lease *lease,
                struct in6_addr *ret_prefix,
                uint8_t *ret_prefix_length);
int sd_dhcp6_lease_get_pd_lifetime(
                sd_dhcp6_lease *lease,
                uint64_t *ret_lifetime_preferred,
                uint64_t *ret_lifetime_valid);
int sd_dhcp6_lease_get_pd_lifetime_timestamp(
                sd_dhcp6_lease *lease,
                clockid_t clock,
                uint64_t *ret_lifetime_preferred,
                uint64_t *ret_lifetime_valid);
int sd_dhcp6_lease_has_pd_prefix(sd_dhcp6_lease *lease);

int sd_dhcp6_lease_get_dns(sd_dhcp6_lease *lease, const struct in6_addr **ret);
int sd_dhcp6_lease_get_dnr(sd_dhcp6_lease *lease, sd_dns_resolver **ret);
int sd_dhcp6_lease_get_domains(sd_dhcp6_lease *lease, char ***ret);
int sd_dhcp6_lease_get_ntp_addrs(sd_dhcp6_lease *lease, const struct in6_addr **ret);
int sd_dhcp6_lease_get_ntp_fqdn(sd_dhcp6_lease *lease, char ***ret);
int sd_dhcp6_lease_get_fqdn(sd_dhcp6_lease *lease, const char **ret);
int sd_dhcp6_lease_get_captive_portal(sd_dhcp6_lease *lease, const char **ret);
int sd_dhcp6_lease_get_vendor_options(sd_dhcp6_lease *lease, sd_dhcp6_option ***ret);

sd_dhcp6_lease *sd_dhcp6_lease_ref(sd_dhcp6_lease *lease);
sd_dhcp6_lease *sd_dhcp6_lease_unref(sd_dhcp6_lease *lease);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp6_lease, sd_dhcp6_lease_unref);

_SD_END_DECLARATIONS;

#endif
