/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosddhcpoptionhfoo
#define foosddhcpoptionhfoo

/***
  Copyright © 2013 Intel Corporation. All rights reserved.
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
#include <sys/types.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_dhcp_option sd_dhcp_option;

int sd_dhcp_option_new(uint8_t option, const void *data, size_t length, sd_dhcp_option **ret);
sd_dhcp_option *sd_dhcp_option_ref(sd_dhcp_option *ra);
sd_dhcp_option *sd_dhcp_option_unref(sd_dhcp_option *ra);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp_option, sd_dhcp_option_unref);

_SD_END_DECLARATIONS;

#endif
