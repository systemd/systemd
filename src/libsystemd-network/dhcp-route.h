/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"

#include "in-addr-util.h"  /* IWYU pragma: keep */

struct sd_dhcp_route {
        struct in_addr dst_addr;
        struct in_addr gw_addr;
        uint8_t dst_prefixlen;
};
