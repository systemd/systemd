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
#include "networkd.h"
#include "missing.h"


static int netdev_fill_vxlan_rtnl_message(NetDev *netdev, Link *link, sd_rtnl_message *m) {
        int r;

        assert(link);
        assert(link->network);
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

        r = sd_rtnl_message_open_container_union(m, IFLA_INFO_DATA,
                                                 netdev_kind_to_string(netdev->kind));
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

int netdev_create_vxlan(NetDev *netdev, Link *link, sd_rtnl_message_handler_t callback) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
        int r;

        assert(netdev);
        assert(!(netdev->kind == NETDEV_KIND_VXLAN) || (link && callback));
        assert(netdev->ifname);
        assert(netdev->manager);
        assert(netdev->manager->rtnl);

        r = sd_rtnl_message_new_link(netdev->manager->rtnl, &m, RTM_NEWLINK, 0);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not allocate RTM_NEWLINK message: %s",
                                 strerror(-r));
                return r;
        }

        r = netdev_fill_vxlan_rtnl_message(netdev, link, m);
        if(r < 0)
                return r;

        r = sd_rtnl_call_async(netdev->manager->rtnl, m, callback, link, 0, NULL);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        link_ref(link);

        log_debug_netdev(netdev, "Creating vxlan netdev: %s",
                         netdev_kind_to_string(netdev->kind));

        netdev->state = NETDEV_STATE_CREATING;

        return 0;
}
