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
#include <linux/veth.h>

#include "sd-rtnl.h"
#include "networkd-netdev-veth.h"

static int netdev_veth_fill_message_create(NetDev *netdev, sd_rtnl_message *m) {
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

        r = sd_rtnl_message_open_container_union(m, IFLA_INFO_DATA, "veth");
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_INFO_DATA attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_open_container(m, VETH_INFO_PEER);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_LINK attribute: %s",
                                 strerror(-r));
                return r;
        }

        if (netdev->ifname_peer) {
                r = sd_rtnl_message_append_string(m, IFLA_IFNAME, netdev->ifname_peer);
                if (r < 0) {
                        log_error("Failed to add netlink interface name: %s", strerror(-r));
                        return r;
                }
        }

        if (netdev->mac_peer) {
                r = sd_rtnl_message_append_ether_addr(m, IFLA_ADDRESS, netdev->mac_peer);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_ADDRESS attribute: %s",
                                         strerror(-r));
                    return r;
                }
        }

        r = sd_rtnl_message_close_container(m);
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

static int netdev_veth_verify(NetDev *netdev, const char *filename) {
        int r;

        assert(netdev);
        assert(filename);

        if (!netdev->ifname_peer) {
                log_warning("Veth NetDev without peer name configured in %s. Ignoring",
                            filename);
                return -EINVAL;
        }

        if (!netdev->mac_peer) {
                r = netdev_get_mac(netdev->ifname_peer, &netdev->mac_peer);
                if (r < 0) {
                        log_warning("Failed to generate predictable MAC address for %s. Ignoring",
                                  netdev->ifname_peer);
                        return -EINVAL;
                }
        }

        return 0;
}

const NetDevVTable veth_vtable = {
        .fill_message_create = netdev_veth_fill_message_create,
        .config_verify = netdev_veth_verify,
};
