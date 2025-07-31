/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdndiscneighborfoo
#define foosdndiscneighborfoo

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

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

struct in6_addr;
struct ether_addr;

typedef struct sd_ndisc_neighbor sd_ndisc_neighbor;

sd_ndisc_neighbor *sd_ndisc_neighbor_ref(sd_ndisc_neighbor *na);
sd_ndisc_neighbor *sd_ndisc_neighbor_unref(sd_ndisc_neighbor *na);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_ndisc_neighbor, sd_ndisc_neighbor_unref);

int sd_ndisc_neighbor_get_sender_address(sd_ndisc_neighbor *na, struct in6_addr *ret);
/* RFC 4861 section 4.4:
 * For solicited advertisements, the Target Address field in the Neighbor Solicitation message that prompted
 * this advertisement. For an unsolicited advertisement, the address whose link-layer address has changed.
 * The Target Address MUST NOT be a multicast address. */
int sd_ndisc_neighbor_get_target_address(sd_ndisc_neighbor *na, struct in6_addr *ret);
int sd_ndisc_neighbor_get_target_mac(sd_ndisc_neighbor *na, struct ether_addr *ret);
int sd_ndisc_neighbor_get_flags(sd_ndisc_neighbor *na, uint32_t *ret);
int sd_ndisc_neighbor_is_router(sd_ndisc_neighbor *na);
int sd_ndisc_neighbor_is_solicited(sd_ndisc_neighbor *na);
int sd_ndisc_neighbor_is_override(sd_ndisc_neighbor *na);

_SD_END_DECLARATIONS;

#endif
