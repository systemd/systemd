/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosddhcpclientidhfoo
#define foosddhcpclientidhfoo

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

#include "sd-dhcp-duid.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_dhcp_client_id sd_dhcp_client_id;

int sd_dhcp_client_id_new(sd_dhcp_client_id **ret);
sd_dhcp_client_id* sd_dhcp_client_id_free(sd_dhcp_client_id *client_id);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp_client_id, sd_dhcp_client_id_free);

int sd_dhcp_client_id_clear(sd_dhcp_client_id *client_id);

int sd_dhcp_client_id_is_set(const sd_dhcp_client_id *client_id);

int sd_dhcp_client_id_get(const sd_dhcp_client_id *client_id, uint8_t *ret_type, const void **ret_data, size_t *ret_size);
int sd_dhcp_client_id_get_raw(const sd_dhcp_client_id *client_id, const void **ret_data, size_t *ret_size);

int sd_dhcp_client_id_set(
                sd_dhcp_client_id *client_id,
                uint8_t type,
                const void *data,
                size_t data_size);
int sd_dhcp_client_id_set_raw(
                sd_dhcp_client_id *client_id,
                const void *data,
                size_t data_size);
int sd_dhcp_client_id_set_iaid_duid(
                sd_dhcp_client_id *client_id,
                uint32_t iaid,
                sd_dhcp_duid *duid);

_SD_END_DECLARATIONS;

#endif
