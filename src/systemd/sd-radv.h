#ifndef foosdradvfoo
#define foosdradvfoo

/***
  This file is part of systemd.

  Copyright (C) 2017 Intel Corporation. All rights reserved.

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

#include "sd-event.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_radv_prefix sd_radv_prefix;

/* Advertised prefixes */
int sd_radv_prefix_new(sd_radv_prefix **ret);
sd_radv_prefix *sd_radv_prefix_ref(sd_radv_prefix *ra);
sd_radv_prefix *sd_radv_prefix_unref(sd_radv_prefix *ra);

int sd_radv_prefix_set_prefix(sd_radv_prefix *p, struct in6_addr *in6_addr,
                              unsigned char prefixlen);
int sd_radv_prefix_set_onlink(sd_radv_prefix *p, int onlink);
int sd_radv_prefix_set_address_autoconfiguration(sd_radv_prefix *p,
                                                 int address_autoconfiguration);
int sd_radv_prefix_set_valid_lifetime(sd_radv_prefix *p,
                                      uint32_t valid_lifetime);
int sd_radv_prefix_set_preferred_lifetime(sd_radv_prefix *p,
                                          uint32_t preferred_lifetime);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_radv, sd_radv_unref);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_radv_prefix, sd_radv_prefix_unref);

_SD_END_DECLARATIONS;

#endif
