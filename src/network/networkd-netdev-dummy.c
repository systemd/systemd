/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
    This file is part of systemd.

    Copyright 2014 Susant Sahani <susant@redhat.com>
    Copyright 2014 Tom Gundersen

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
#include <linux/veth.h>

#include "sd-rtnl.h"
#include "networkd-netdev-dummy.h"

static int netdev_dummy_fill_message_create(NetDev *netdev, sd_rtnl_message *m) {
        int r;

        assert(netdev);
        assert(netdev->ifname);
        assert(m);

        r = sd_rtnl_message_append_string(m, IFLA_IFNAME, netdev->ifname);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IFNAME, attribute: %s",
                                 strerror(-r));
                return r;
        }

        if (netdev->mac) {
                r = sd_rtnl_message_append_ether_addr(m, IFLA_ADDRESS, netdev->mac);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_ADDRESS attribute: %s",
                                         strerror(-r));
                    return r;
                }
        }

        r = sd_rtnl_message_open_container(m, IFLA_LINKINFO);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_LINKINFO attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_open_container_union(m, IFLA_INFO_DATA, "dummy");
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_INFO_DATA attribute: %s",
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

const NetDevVTable dummy_vtable = {
        .fill_message_create = netdev_dummy_fill_message_create,
};
