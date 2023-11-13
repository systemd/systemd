/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosddhcpduidhfoo
#define foosddhcpduidhfoo

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

enum {
        SD_DUID_TYPE_LLT        = 1,
        SD_DUID_TYPE_EN         = 2,
        SD_DUID_TYPE_LL         = 3,
        SD_DUID_TYPE_UUID       = 4
};

typedef struct sd_dhcp_duid sd_dhcp_duid;

int sd_dhcp_duid_clear(sd_dhcp_duid *duid);

int sd_dhcp_duid_is_set(const sd_dhcp_duid *duid);

int sd_dhcp_duid_get(const sd_dhcp_duid *duid, uint16_t *ret_type, const void **ret_data, size_t *ret_size);
int sd_dhcp_duid_get_raw(const sd_dhcp_duid *duid, const void **ret_data, size_t *ret_size);

int sd_dhcp_duid_set(
                sd_dhcp_duid *duid,
                uint16_t duid_type,
                const void *data,
                size_t data_size);
int sd_dhcp_duid_set_raw(
                sd_dhcp_duid *duid,
                const void *data,
                size_t data_size);
int sd_dhcp_duid_set_llt(
                sd_dhcp_duid *duid,
                const void *hw_addr,
                size_t hw_addr_size,
                uint16_t arp_type,
                uint64_t usec);
int sd_dhcp_duid_set_ll(
                sd_dhcp_duid *duid,
                const void *hw_addr,
                size_t hw_addr_size,
                uint16_t arp_type);
int sd_dhcp_duid_set_en(sd_dhcp_duid *duid);
int sd_dhcp_duid_set_uuid(sd_dhcp_duid *duid);

_SD_END_DECLARATIONS;

#endif
