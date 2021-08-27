/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "udev-builtin-net_id-netlink.h"

void link_info_clear(LinkInfo *info) {
        if (!info)
                return;

        info->ifname = mfree(info->ifname);
        info->phys_port_name = mfree(info->phys_port_name);
}

int link_info_get(sd_netlink **rtnl, LinkInfo *info) {
        return 0;
}
