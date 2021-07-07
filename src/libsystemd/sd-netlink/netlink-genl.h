/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

int nlmsg_type_to_genl_family(const sd_netlink *nl, uint16_t type, sd_genl_family_t *ret);
