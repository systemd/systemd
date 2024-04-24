/* SPDX-License-Identifier: LGPL-2.1-or-later */
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
  along with systemd; If not, see <https://www.gnu.org/licenses/>.
***/

#include <inttypes.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "_sd-common.h"
#include "sd-event.h"
#include "sd-ndisc-protocol.h"
#include "sd-ndisc-router-solicit.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_radv sd_radv;

int sd_radv_new(sd_radv **ret);
sd_radv *sd_radv_ref(sd_radv *ra);
sd_radv *sd_radv_unref(sd_radv *ra);

int sd_radv_attach_event(sd_radv *ra, sd_event *event, int64_t priority);
int sd_radv_detach_event(sd_radv *nd);
sd_event *sd_radv_get_event(sd_radv *ra);

int sd_radv_start(sd_radv *ra);
int sd_radv_stop(sd_radv *ra);
int sd_radv_is_running(sd_radv *ra);
int sd_radv_send(sd_radv *ra);

int sd_radv_set_ifindex(sd_radv *ra, int interface_index);
int sd_radv_set_ifname(sd_radv *ra, const char *interface_name);
int sd_radv_get_ifname(sd_radv *ra, const char **ret);
int sd_radv_set_link_local_address(sd_radv *ra, const struct in6_addr *addr);

/* RA header */
int sd_radv_set_hop_limit(sd_radv *ra, uint8_t hop_limit);
int sd_radv_set_reachable_time(sd_radv *ra, uint64_t usec);
int sd_radv_set_retransmit(sd_radv *ra, uint64_t usec);
int sd_radv_set_router_lifetime(sd_radv *ra, uint64_t usec);
int sd_radv_set_managed_information(sd_radv *ra, int b);
int sd_radv_set_other_information(sd_radv *ra, int b);
int sd_radv_set_preference(sd_radv *ra, uint8_t preference);

/* Options */
int sd_radv_set_mac(sd_radv *ra, const struct ether_addr *mac_addr);
void sd_radv_unset_mac(sd_radv *ra);
int sd_radv_add_prefix(
                sd_radv *ra,
                const struct in6_addr *prefix,
                uint8_t prefixlen,
                uint8_t flags,
                uint64_t valid_lifetime_usec,
                uint64_t preferred_lifetime_usec,
                uint64_t valid_until,
                uint64_t preferred_until);
void sd_radv_remove_prefix(
                sd_radv *ra,
                const struct in6_addr *prefix,
                uint8_t prefixlen);
int sd_radv_set_mtu(sd_radv *ra, uint32_t mtu);
void sd_radv_unset_mtu(sd_radv *ra);
int sd_radv_set_home_agent(sd_radv *ra, uint16_t preference, uint64_t lifetime_usec, uint64_t valid_until);
void sd_radv_unset_home_agent(sd_radv *ra);
int sd_radv_add_route(
                sd_radv *ra,
                const struct in6_addr *prefix,
                uint8_t prefixlen,
                uint8_t preference,
                uint64_t lifetime_usec,
                uint64_t valid_until);
void sd_radv_remove_route(
                sd_radv *ra,
                const struct in6_addr *prefix,
                uint8_t prefixlen);
int sd_radv_add_rdnss(
                sd_radv *ra,
                size_t n_dns,
                const struct in6_addr *dns,
                uint64_t lifetime_usec,
                uint64_t valid_until);
void sd_radv_clear_rdnss(sd_radv *ra);
int sd_radv_add_dnssl(
                sd_radv *ra,
                char * const *domains,
                uint64_t lifetime_usec,
                uint64_t valid_until);
void sd_radv_clear_dnssl(sd_radv *ra);
int sd_radv_set_captive_portal(sd_radv *ra, const char *portal);
void sd_radv_unset_captive_portal(sd_radv *ra);
int sd_radv_add_prefix64(
                sd_radv *ra,
                const struct in6_addr *prefix,
                uint8_t prefixlen,
                uint64_t lifetime_usec,
                uint64_t valid_until);
void sd_radv_remove_prefix64(
                sd_radv *ra,
                const struct in6_addr *prefix,
                uint8_t prefixlen);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_radv, sd_radv_unref);

_SD_END_DECLARATIONS;

#endif
