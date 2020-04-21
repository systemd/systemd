/* SPDX-License-Identifier: LGPL-2.1+ */

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
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <inttypes.h>
#include <sys/types.h>

#include "sparse-endian.h"

#include "_sd-common.h"


extern const struct hash_ops dhcp_static_leases_hash_ops;

_SD_BEGIN_DECLARATIONS;

typedef struct sd_dhcp_static_lease sd_dhcp_static_lease;
typedef struct DHCPClientId DHCPClientId;

int sd_dhcp_static_lease_new(DHCPClientId *client_id, be32_t address, sd_dhcp_static_lease **ret);
sd_dhcp_static_lease *sd_dhcp_static_lease_ref(sd_dhcp_static_lease *ra);
sd_dhcp_static_lease *sd_dhcp_static_lease_unref(sd_dhcp_static_lease *ra);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp_static_lease, sd_dhcp_static_lease_unref);

_SD_END_DECLARATIONS;
