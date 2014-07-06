/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
    This file is part of systemd.

    Copyright 2014 Susant Sahani <susant@redhat.com>

    systemd is free software; you can redistribute it and/or modify it
    under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2.1 of the License, or
    (at your option) any later version.

    systemd is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <netinet/ether.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "sd-rtnl.h"
#include "networkd-netdev-vxlan.h"
#include "missing.h"

static int netdev_vxlan_fill_message_create(NetDev *netdev, Link *link, sd_rtnl_message *m) {
        int r;

        assert(netdev);
        assert(link);
        assert(link->ifname);
        assert(m);

        r = sd_rtnl_message_append_string(m, IFLA_IFNAME, netdev->ifname);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IFNAME, attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_open_container(m, IFLA_LINKINFO);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_LINKINFO attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_open_container_union(m, IFLA_INFO_DATA, "vxlan");
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_INFO_DATA attribute: %s",
                                 strerror(-r));
                return r;
        }

        if (netdev->vlanid <= VXLAN_VID_MAX) {
                r = sd_rtnl_message_append_u32(m, IFLA_VXLAN_ID, netdev->vxlanid);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_VXLAN_ID attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_VXLAN_GROUP, &netdev->group.in);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_VXLAN_GROUP attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u32(m, IFLA_VXLAN_LINK, link->ifindex);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_VXLAN_LINK attribute: %s",
                                 strerror(-r));
                return r;
        }

        if(netdev->ttl) {
                r = sd_rtnl_message_append_u8(m, IFLA_VXLAN_TTL, netdev->ttl);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_VXLAN_TTL attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        if(netdev->tos) {
                r = sd_rtnl_message_append_u8(m, IFLA_VXLAN_TOS, netdev->tos);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_VXLAN_TOS attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        r = sd_rtnl_message_append_u8(m, IFLA_VXLAN_LEARNING, netdev->learning);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_VXLAN_LEARNING attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_close_container(m);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_LINKINFO attribute: %s",
                                 strerror(-r));
                return r;
        }

        return r;
}

static int netdev_vxlan_verify(NetDev *netdev, const char *filename) {
        assert(netdev);
        assert(filename);

        if (netdev->vxlanid > VXLAN_VID_MAX) {
                log_warning("VXLAN without valid Id configured in %s. Ignoring", filename);
                return -EINVAL;
        }

        return 0;
}

const NetDevVTable vxlan_vtable = {
        .fill_message_create_on_link = netdev_vxlan_fill_message_create,
        .config_verify = netdev_vxlan_verify,
};
