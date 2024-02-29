/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdndiscprotocolfoo
#define foosdndiscprotocolfoo

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

/* Neighbor Discovery Options, RFC 4861, Section 4.6 and
 * https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-5 */
enum {
        SD_NDISC_OPTION_SOURCE_LL_ADDRESS  = 1,
        SD_NDISC_OPTION_TARGET_LL_ADDRESS  = 2,
        SD_NDISC_OPTION_PREFIX_INFORMATION = 3,
        SD_NDISC_OPTION_REDIRECTED_HEADER  = 4,
        SD_NDISC_OPTION_MTU                = 5,
        SD_NDISC_OPTION_ROUTE_INFORMATION  = 24,
        SD_NDISC_OPTION_RDNSS              = 25,
        SD_NDISC_OPTION_FLAGS_EXTENSION    = 26,
        SD_NDISC_OPTION_DNSSL              = 31,
        SD_NDISC_OPTION_CAPTIVE_PORTAL     = 37,
        SD_NDISC_OPTION_PREF64             = 38
};

/* Route preference, RFC 4191, Section 2.1 */
enum {
        SD_NDISC_PREFERENCE_MEDIUM   = 0U,
        SD_NDISC_PREFERENCE_HIGH     = 1U,
        SD_NDISC_PREFERENCE_RESERVED = 2U,
        SD_NDISC_PREFERENCE_LOW      = 3U
};

_SD_END_DECLARATIONS;

#endif
