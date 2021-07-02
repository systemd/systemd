/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

#include "netlink-types.h"

#define CTRL_GENL_NAME "nlctrl"

void genl_clear_family(sd_netlink *nl);

int genl_get_type_system_by_id(sd_netlink *nl, uint16_t id, const NLTypeSystem **ret);
