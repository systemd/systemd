/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

#define CTRL_GENL_NAME "nlctrl"

void genl_clear_family(sd_netlink *nl);
