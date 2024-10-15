/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-hwdb.h"
#include "sd-netlink.h"

int system_status(sd_netlink *rtnl, sd_hwdb *hwdb);
