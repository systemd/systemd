/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdndiscredirectfoo
#define foosdndiscredirectfoo

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
#include <netinet/ip6.h>
#include <sys/types.h>
#include <time.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_ndisc_redirect sd_ndisc_redirect;

sd_ndisc_redirect* sd_ndisc_redirect_ref(sd_ndisc_redirect *na);
sd_ndisc_redirect* sd_ndisc_redirect_unref(sd_ndisc_redirect *na);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_ndisc_redirect, sd_ndisc_redirect_unref);

int sd_ndisc_redirect_set_sender_address(sd_ndisc_redirect *rd, const struct in6_addr *addr);
int sd_ndisc_redirect_get_sender_address(sd_ndisc_redirect *na, struct in6_addr *ret);
int sd_ndisc_redirect_get_target_address(sd_ndisc_redirect *na, struct in6_addr *ret);
int sd_ndisc_redirect_get_destination_address(sd_ndisc_redirect *na, struct in6_addr *ret);
int sd_ndisc_redirect_get_target_mac(sd_ndisc_redirect *na, struct ether_addr *ret);
int sd_ndisc_redirect_get_redirected_header(sd_ndisc_redirect *na, struct ip6_hdr *ret);

_SD_END_DECLARATIONS;

#endif
