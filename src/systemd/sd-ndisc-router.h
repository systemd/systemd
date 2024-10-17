/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdndiscrouterfoo
#define foosdndiscrouterfoo

/***
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
#include <time.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_ndisc_router sd_ndisc_router;
typedef struct sd_dns_resolver sd_dns_resolver;

sd_ndisc_router *sd_ndisc_router_ref(sd_ndisc_router *rt);
sd_ndisc_router *sd_ndisc_router_unref(sd_ndisc_router *rt);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_ndisc_router, sd_ndisc_router_unref);

int sd_ndisc_router_set_sender_address(sd_ndisc_router *rt, const struct in6_addr *addr);
int sd_ndisc_router_get_sender_address(sd_ndisc_router *rt, struct in6_addr *ret);
int sd_ndisc_router_get_timestamp(sd_ndisc_router *rt, clockid_t clock, uint64_t *ret);

int sd_ndisc_router_get_hop_limit(sd_ndisc_router *rt, uint8_t *ret);
int sd_ndisc_router_get_flags(sd_ndisc_router *rt, uint64_t *ret);
int sd_ndisc_router_get_preference(sd_ndisc_router *rt, uint8_t *ret);
int sd_ndisc_router_get_lifetime(sd_ndisc_router *rt, uint64_t *ret);
int sd_ndisc_router_get_lifetime_timestamp(sd_ndisc_router *rt, clockid_t clock, uint64_t *ret);
int sd_ndisc_router_get_reachable_time(sd_ndisc_router *rt, uint64_t *ret);
int sd_ndisc_router_get_retransmission_time(sd_ndisc_router *rt, uint64_t *ret);
int sd_ndisc_router_get_sender_mac(sd_ndisc_router *rt, struct ether_addr *ret);
int sd_ndisc_router_get_mtu(sd_ndisc_router *rt, uint32_t *ret);
int sd_ndisc_router_get_captive_portal(sd_ndisc_router *rt, const char **ret);

/* Generic option access */
int sd_ndisc_router_option_rewind(sd_ndisc_router *rt);
int sd_ndisc_router_option_next(sd_ndisc_router *rt);
int sd_ndisc_router_option_get_type(sd_ndisc_router *rt, uint8_t *ret);
int sd_ndisc_router_option_is_type(sd_ndisc_router *rt, uint8_t type);
int sd_ndisc_router_option_get_raw(sd_ndisc_router *rt, const uint8_t **ret, size_t *ret_size);

/* Specific option access: SD_NDISC_OPTION_PREFIX_INFORMATION */
int sd_ndisc_router_prefix_get_valid_lifetime(sd_ndisc_router *rt, uint64_t *ret);
int sd_ndisc_router_prefix_get_valid_lifetime_timestamp(sd_ndisc_router *rt, clockid_t clock, uint64_t *ret);
int sd_ndisc_router_prefix_get_preferred_lifetime(sd_ndisc_router *rt, uint64_t *ret);
int sd_ndisc_router_prefix_get_preferred_lifetime_timestamp(sd_ndisc_router *rt, clockid_t clock, uint64_t *ret);
int sd_ndisc_router_prefix_get_flags(sd_ndisc_router *rt, uint8_t *ret);
int sd_ndisc_router_prefix_get_address(sd_ndisc_router *rt, struct in6_addr *ret);
int sd_ndisc_router_prefix_get_prefixlen(sd_ndisc_router *rt, uint8_t *ret);

/* Specific option access: SD_NDISC_OPTION_ROUTE_INFORMATION */
int sd_ndisc_router_route_get_lifetime(sd_ndisc_router *rt, uint64_t *ret);
int sd_ndisc_router_route_get_lifetime_timestamp(sd_ndisc_router *rt, clockid_t clock, uint64_t *ret);
int sd_ndisc_router_route_get_address(sd_ndisc_router *rt, struct in6_addr *ret);
int sd_ndisc_router_route_get_prefixlen(sd_ndisc_router *rt, uint8_t *ret);
int sd_ndisc_router_route_get_preference(sd_ndisc_router *rt, uint8_t *ret);

/* Specific option access: SD_NDISC_OPTION_RDNSS */
int sd_ndisc_router_rdnss_get_addresses(sd_ndisc_router *rt, const struct in6_addr **ret);
int sd_ndisc_router_rdnss_get_lifetime(sd_ndisc_router *rt, uint64_t *ret);
int sd_ndisc_router_rdnss_get_lifetime_timestamp(sd_ndisc_router *rt, clockid_t clock, uint64_t *ret);

/* Specific option access: SD_NDISC_OPTION_DNSSL */
int sd_ndisc_router_dnssl_get_domains(sd_ndisc_router *rt, char ***ret);
int sd_ndisc_router_dnssl_get_lifetime(sd_ndisc_router *rt, uint64_t *ret);
int sd_ndisc_router_dnssl_get_lifetime_timestamp(sd_ndisc_router *rt, clockid_t clock, uint64_t *ret);

/* Specific option access: SD_NDISC_OPTION_PREF64 */
int sd_ndisc_router_prefix64_get_prefix(sd_ndisc_router *rt, struct in6_addr *ret);
int sd_ndisc_router_prefix64_get_prefixlen(sd_ndisc_router *rt, uint8_t *ret);
int sd_ndisc_router_prefix64_get_lifetime(sd_ndisc_router *rt, uint64_t *ret);
int sd_ndisc_router_prefix64_get_lifetime_timestamp(sd_ndisc_router *rt, clockid_t clock, uint64_t *ret);

/* Specific option access: SD_NDISC_OPTION_ENCRYPTED_DNS */
int sd_ndisc_router_encrypted_dns_get_resolver(sd_ndisc_router *rt, sd_dns_resolver **ret);
int sd_ndisc_router_encrypted_dns_get_lifetime(sd_ndisc_router *rt, uint64_t *ret);
int sd_ndisc_router_encrypted_dns_get_lifetime_timestamp(sd_ndisc_router *rt, clockid_t clock, uint64_t *ret);

_SD_END_DECLARATIONS;

#endif
