/* SPDX-License-Identifier: LGPL-2.1+ */
#ifndef foosdradvfoo
#define foosdradvfoo

/***
  Copyright © 2017 Intel Corporation. All rights reserved.

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

#include <inttypes.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "_sd-common.h"
#include "sd-event.h"
#include "sd-ndisc.h"

_SD_BEGIN_DECLARATIONS;

#define SD_RADV_DEFAULT_MIN_TIMEOUT_USEC        (200*USEC_PER_SEC)
#define SD_RADV_DEFAULT_MAX_TIMEOUT_USEC        (600*USEC_PER_SEC)

#define SD_RADV_DEFAULT_DNS_LIFETIME_USEC       (3*SD_RADV_DEFAULT_MAX_TIMEOUT_USEC)

typedef struct sd_radv sd_radv;
typedef struct sd_radv_prefix sd_radv_prefix;
typedef struct sd_radv_route_prefix sd_radv_route_prefix;

/* Router Advertisement */
int sd_radv_new(sd_radv **ret);
sd_radv *sd_radv_ref(sd_radv *ra);
sd_radv *sd_radv_unref(sd_radv *ra);

int sd_radv_attach_event(sd_radv *ra, sd_event *event, int64_t priority);
int sd_radv_detach_event(sd_radv *nd);
sd_event *sd_radv_get_event(sd_radv *ra);

int sd_radv_start(sd_radv *ra);
int sd_radv_stop(sd_radv *ra);

int sd_radv_set_ifindex(sd_radv *ra, int interface_index);
int sd_radv_set_mac(sd_radv *ra, const struct ether_addr *mac_addr);
int sd_radv_set_mtu(sd_radv *ra, uint32_t mtu);
int sd_radv_set_hop_limit(sd_radv *ra, uint8_t hop_limit);
int sd_radv_set_router_lifetime(sd_radv *ra, uint32_t router_lifetime);
int sd_radv_set_managed_information(sd_radv *ra, int managed);
int sd_radv_set_other_information(sd_radv *ra, int other);
int sd_radv_set_preference(sd_radv *ra, unsigned preference);
int sd_radv_add_prefix(sd_radv *ra, sd_radv_prefix *p, int dynamic);
int sd_radv_add_route_prefix(sd_radv *ra, sd_radv_route_prefix *p, int dynamic);
sd_radv_prefix *sd_radv_remove_prefix(sd_radv *ra, const struct in6_addr *prefix,
                                      unsigned char prefixlen);
int sd_radv_set_rdnss(sd_radv *ra, uint32_t lifetime,
                      const struct in6_addr *dns, size_t n_dns);
int sd_radv_set_dnssl(sd_radv *ra, uint32_t lifetime, char **search_list);

/* Advertised prefixes */
int sd_radv_prefix_new(sd_radv_prefix **ret);
sd_radv_prefix *sd_radv_prefix_ref(sd_radv_prefix *ra);
sd_radv_prefix *sd_radv_prefix_unref(sd_radv_prefix *ra);

int sd_radv_prefix_set_prefix(sd_radv_prefix *p, const struct in6_addr *in6_addr,
                              unsigned char prefixlen);
int sd_radv_prefix_set_onlink(sd_radv_prefix *p, int onlink);
int sd_radv_prefix_set_address_autoconfiguration(sd_radv_prefix *p,
                                                 int address_autoconfiguration);
int sd_radv_prefix_set_valid_lifetime(sd_radv_prefix *p,
                                      uint32_t valid_lifetime);
int sd_radv_prefix_set_preferred_lifetime(sd_radv_prefix *p,
                                          uint32_t preferred_lifetime);

int sd_radv_route_prefix_new(sd_radv_route_prefix **ret);
sd_radv_route_prefix *sd_radv_route_prefix_ref(sd_radv_route_prefix *ra);
sd_radv_route_prefix *sd_radv_route_prefix_unref(sd_radv_route_prefix *ra);

int sd_radv_prefix_set_route_prefix(sd_radv_route_prefix *p, const struct in6_addr *in6_addr, unsigned char prefixlen);
int sd_radv_route_prefix_set_lifetime(sd_radv_route_prefix *p, uint32_t valid_lifetime);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_radv, sd_radv_unref);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_radv_prefix, sd_radv_prefix_unref);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_radv_route_prefix, sd_radv_route_prefix_unref);

_SD_END_DECLARATIONS;

#endif
