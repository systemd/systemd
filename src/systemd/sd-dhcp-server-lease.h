/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosddhcpserverleasehfoo
#define foosddhcpserverleasehfoo

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

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_dhcp_server_lease sd_dhcp_server_lease;

sd_dhcp_server_lease *sd_dhcp_server_lease_ref(sd_dhcp_server_lease *lease);
sd_dhcp_server_lease *sd_dhcp_server_lease_unref(sd_dhcp_server_lease *lease);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp_server_lease, sd_dhcp_server_lease_unref);

_SD_END_DECLARATIONS;

#endif
