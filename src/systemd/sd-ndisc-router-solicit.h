/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdndiscroutersolicitfoo
#define foosdndiscroutersolicitfoo

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

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_ndisc_router_solicit sd_ndisc_router_solicit;

sd_ndisc_router_solicit *sd_ndisc_router_solicit_ref(sd_ndisc_router_solicit *rs);
sd_ndisc_router_solicit *sd_ndisc_router_solicit_unref(sd_ndisc_router_solicit *rs);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_ndisc_router_solicit, sd_ndisc_router_solicit_unref);

int sd_ndisc_router_solicit_get_sender_address(sd_ndisc_router_solicit *rs, struct in6_addr *ret);
int sd_ndisc_router_solicit_get_sender_mac(sd_ndisc_router_solicit *rs, struct ether_addr *ret);

_SD_END_DECLARATIONS;

#endif
