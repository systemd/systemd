/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

#define CTRL_GENL_NAME "nlctrl"

void genl_clear_family(sd_netlink *nl);

int genl_family_get_name(sd_netlink *nl, uint16_t id, const char **ret);
