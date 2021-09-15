/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h"
#include "sd-netlink.h"

#include "ether-addr-util.h"

typedef struct LinkInfo {
        int ifindex;
        uint16_t iftype;             /* ARPHRD_* (type) */

        struct hw_addr_data hw_addr;   /* IFLA_ADDRESS (address, addr_len) */
        struct hw_addr_data broadcast; /* IFLA_BROADCAST (broadcast) */
        char *ifname;                  /* IFLA_IFNAME */
        uint32_t mtu;                  /* IFLA_MTU (mtu) */
        uint32_t iflink;               /* IFLA_LINK (iflink) */
        uint8_t link_mode;             /* IFLA_LINKMODE (link_mode) */
        char *ifalias;                 /* IFLA_IFALIAS (ifalias) */
        uint32_t group;                /* IFLA_GROUP (netdev_group) */
        uint8_t *phys_port_id;         /* IFLA_PHYS_PORT_ID (phys_port_id) */
        size_t phys_port_id_len;
        uint8_t *phys_switch_id;       /* IFLA_PHYS_SWITCH_ID (phys_switch_id) */
        size_t phys_switch_id_len;
        char *phys_port_name;          /* IFLA_PHYS_PORT_NAME (phys_port_name) */

        bool phys_port_id_supported;
        bool phys_switch_id_supported;
        bool phys_port_name_supported;
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
