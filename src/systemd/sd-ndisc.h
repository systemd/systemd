/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdndiscfoo
#define foosdndiscfoo

/***
  Copyright © 2014 Intel Corporation. All rights reserved.

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

#include <errno.h>
#include <inttypes.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "sd-event.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

/* Neighbor Discovery Options, RFC 4861, Section 4.6 and
 * https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-5 */
enum {
        SD_NDISC_OPTION_SOURCE_LL_ADDRESS  = 1,
        SD_NDISC_OPTION_TARGET_LL_ADDRESS  = 2,
        SD_NDISC_OPTION_PREFIX_INFORMATION = 3,
        SD_NDISC_OPTION_MTU                = 5,
        SD_NDISC_OPTION_ROUTE_INFORMATION  = 24,
        SD_NDISC_OPTION_RDNSS              = 25,
        SD_NDISC_OPTION_FLAGS_EXTENSION    = 26,
        SD_NDISC_OPTION_DNSSL              = 31,
        SD_NDISC_OPTION_CAPTIVE_PORTAL     = 37,
};

/* Route preference, RFC 4191, Section 2.1 */
enum {
        SD_NDISC_PREFERENCE_LOW    = 3U,
        SD_NDISC_PREFERENCE_MEDIUM = 0U,
        SD_NDISC_PREFERENCE_HIGH   = 1U,
};

typedef struct sd_ndisc sd_ndisc;
typedef struct sd_ndisc_router sd_ndisc_router;

typedef enum sd_ndisc_event_t {
        SD_NDISC_EVENT_TIMEOUT,
        SD_NDISC_EVENT_ROUTER,
        _SD_NDISC_EVENT_MAX,
        _SD_NDISC_EVENT_INVALID = -EINVAL,
        _SD_ENUM_FORCE_S64(NDISC_EVENT),
} sd_ndisc_event_t;

typedef void (*sd_ndisc_callback_t)(sd_ndisc *nd, sd_ndisc_event_t event, sd_ndisc_router *rt, void *userdata);

int sd_ndisc_new(sd_ndisc **ret);
sd_ndisc *sd_ndisc_ref(sd_ndisc *nd);
sd_ndisc *sd_ndisc_unref(sd_ndisc *nd);

int sd_ndisc_start(sd_ndisc *nd);
int sd_ndisc_stop(sd_ndisc *nd);

int sd_ndisc_attach_event(sd_ndisc *nd, sd_event *event, int64_t priority);
int sd_ndisc_detach_event(sd_ndisc *nd);
sd_event *sd_ndisc_get_event(sd_ndisc *nd);

int sd_ndisc_set_callback(sd_ndisc *nd, sd_ndisc_callback_t cb, void *userdata);
int sd_ndisc_set_ifindex(sd_ndisc *nd, int interface_index);
int sd_ndisc_set_ifname(sd_ndisc *nd, const char *interface_name);
int sd_ndisc_get_ifname(sd_ndisc *nd, const char **ret);
int sd_ndisc_set_mac(sd_ndisc *nd, const struct ether_addr *mac_addr);

sd_ndisc_router *sd_ndisc_router_ref(sd_ndisc_router *rt);
sd_ndisc_router *sd_ndisc_router_unref(sd_ndisc_router *rt);

int sd_ndisc_router_get_address(sd_ndisc_router *rt, struct in6_addr *ret_addr);
int sd_ndisc_router_get_timestamp(sd_ndisc_router *rt, clockid_t clock, uint64_t *ret);
int sd_ndisc_router_get_raw(sd_ndisc_router *rt, const void **ret, size_t *size);

int sd_ndisc_router_get_hop_limit(sd_ndisc_router *rt, uint8_t *ret);
int sd_ndisc_router_get_flags(sd_ndisc_router *rt, uint64_t *ret_flags);
int sd_ndisc_router_get_preference(sd_ndisc_router *rt, unsigned *ret);
int sd_ndisc_router_get_lifetime(sd_ndisc_router *rt, uint16_t *ret_lifetime);
int sd_ndisc_router_get_mtu(sd_ndisc_router *rt, uint32_t *ret);

/* Generic option access */
int sd_ndisc_router_option_rewind(sd_ndisc_router *rt);
int sd_ndisc_router_option_next(sd_ndisc_router *rt);
int sd_ndisc_router_option_get_type(sd_ndisc_router *rt, uint8_t *ret);
int sd_ndisc_router_option_is_type(sd_ndisc_router *rt, uint8_t type);
int sd_ndisc_router_option_get_raw(sd_ndisc_router *rt, const void **ret, size_t *size);

/* Specific option access: SD_NDISC_OPTION_PREFIX_INFORMATION */
int sd_ndisc_router_prefix_get_valid_lifetime(sd_ndisc_router *rt, uint32_t *ret);
int sd_ndisc_router_prefix_get_preferred_lifetime(sd_ndisc_router *rt, uint32_t *ret);
int sd_ndisc_router_prefix_get_flags(sd_ndisc_router *rt, uint8_t *ret);
int sd_ndisc_router_prefix_get_address(sd_ndisc_router *rt, struct in6_addr *ret_addr);
int sd_ndisc_router_prefix_get_prefixlen(sd_ndisc_router *rt, unsigned *prefixlen);

/* Specific option access: SD_NDISC_OPTION_ROUTE_INFORMATION */
int sd_ndisc_router_route_get_lifetime(sd_ndisc_router *rt, uint32_t *ret);
int sd_ndisc_router_route_get_address(sd_ndisc_router *rt, struct in6_addr *ret_addr);
int sd_ndisc_router_route_get_prefixlen(sd_ndisc_router *rt, unsigned *prefixlen);
int sd_ndisc_router_route_get_preference(sd_ndisc_router *rt, unsigned *ret);

/* Specific option access: SD_NDISC_OPTION_RDNSS */
int sd_ndisc_router_rdnss_get_addresses(sd_ndisc_router *rt, const struct in6_addr **ret);
int sd_ndisc_router_rdnss_get_lifetime(sd_ndisc_router *rt, uint32_t *ret);

/* Specific option access: SD_NDISC_OPTION_DNSSL */
int sd_ndisc_router_dnssl_get_domains(sd_ndisc_router *rt, char ***ret);
int sd_ndisc_router_dnssl_get_lifetime(sd_ndisc_router *rt, uint32_t *ret);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_ndisc, sd_ndisc_unref);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_ndisc_router, sd_ndisc_router_unref);

_SD_END_DECLARATIONS;

#endif
