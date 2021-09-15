/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h"
#include "sd-netlink.h"

#include "ether-addr-util.h"

typedef struct LinkInfo {
        int ifindex;
        uint16_t iftype;             /* ARPHRD_* */

        struct hw_addr_data hw_addr; /* IFLA_ADDRESS */
        char *ifname;                /* IFLA_IFNAME */
        uint32_t iflink;             /* IFLA_LINK */
        char *phys_port_name;        /* IFLA_PHYS_PORT_NAME */

        bool support_phys_port_name;
} LinkInfo;

#define LINK_INFO_NULL ((LinkInfo) {})

void link_info_clear(LinkInfo *info);
int link_info_get(sd_netlink **rtnl, int ifindex, LinkInfo *ret);
int device_cache_sysattr_from_link_info(sd_device *device, LinkInfo *info);
int device_get_sysattr_value_maybe_from_netlink(
                sd_device *device,
                sd_netlink **rtnl,
                const char *sysattr,
                const char **ret_value);
