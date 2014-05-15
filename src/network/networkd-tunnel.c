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
#include <linux/ip.h>
#include <linux/if_tunnel.h>
#include <libkmod.h>

#include "sd-rtnl.h"
#include "networkd.h"
#include "network-internal.h"
#include "util.h"


static int netdev_fill_ipip_rtnl_message(Link *link, sd_rtnl_message *m) {
        NetDev *netdev;
        int r;

        assert(link);
        assert(link->network);
        assert(link->network->tunnel);
        assert(m);

        netdev = link->network->tunnel;

        r = sd_rtnl_message_append_string(m, IFLA_IFNAME, netdev->ifname);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IFNAME, attribute: %s",
                                 strerror(-r));
                return r;
        }

        if(netdev->mtu) {
                r = sd_rtnl_message_append_u32(m, IFLA_MTU, netdev->mtu);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_MTU attribute: %s",
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

        r = sd_rtnl_message_open_container_union(m, IFLA_INFO_DATA,
                                                 netdev_kind_to_string(netdev->kind));
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_INFO_DATA attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u32(m, IFLA_IPTUN_LINK, link->ifindex);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_LINK attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_IPTUN_LOCAL, &netdev->tunnel_local);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_LOCAL attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_IPTUN_REMOTE, &netdev->tunnel_remote);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_REMOTE attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u8(m, IFLA_IPTUN_TTL, netdev->tunnel_ttl);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_TTL  attribute: %s",
                                 strerror(-r));
                return r;
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

static int netdev_fill_sit_rtnl_message(Link *link, sd_rtnl_message *m) {
        NetDev *netdev;
        int r;

        assert(link);
        assert(link->network);
        assert(link->network->tunnel);
        assert(m);

        netdev = link->network->tunnel;

        r = sd_rtnl_message_append_string(m, IFLA_IFNAME, netdev->ifname);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IFNAME, attribute: %s",
                                 strerror(-r));
                return r;
        }

        if(netdev->mtu) {
                r = sd_rtnl_message_append_u32(m, IFLA_MTU, netdev->mtu);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_MTU attribute: %s",
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

        r = sd_rtnl_message_open_container_union(m, IFLA_INFO_DATA,
                                                 netdev_kind_to_string(netdev->kind));
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_INFO_DATA attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u32(m, IFLA_IPTUN_LINK, link->ifindex);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_LINK attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_IPTUN_LOCAL, &netdev->tunnel_local);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_LOCAL attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_IPTUN_REMOTE, &netdev->tunnel_remote);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_REMOTE attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u8(m, IFLA_IPTUN_TOS, netdev->tunnel_tos);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_TOS attribute: %s",
                                 strerror(-r));
                return r;
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

int netdev_create_tunnel(Link *link, sd_rtnl_message_handler_t callback) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
        NetDev *netdev;
        int r;

        assert(link);
        assert(link->network);
        assert(link->network->tunnel);

        netdev = link->network->tunnel;

        assert(netdev);
        assert(netdev->ifname);
        assert(netdev->manager);
        assert(netdev->manager->rtnl);
        assert(netdev->manager->kmod_ctx);

        /* Load kernel module first */
        switch(netdev->kind) {
        case NETDEV_KIND_IPIP:
        case NETDEV_KIND_GRE:
        case NETDEV_KIND_SIT:
                r = load_module(netdev->manager->kmod_ctx,
                                netdev_kind_to_string(netdev->kind));
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not load Kernel module: %s . Ignoring",
                                         netdev_kind_to_string(netdev->kind));
                        return r;
                }
                break;
        default:
                return -ENOTSUP;
        }

        r = sd_rtnl_message_new_link(netdev->manager->rtnl, &m, RTM_NEWLINK, 0);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not allocate RTM_NEWLINK message: %s",
                                 strerror(-r));
                return r;
        }

        switch(netdev->kind) {
        case NETDEV_KIND_IPIP:
                r = netdev_fill_ipip_rtnl_message(link, m);
                if(r < 0)
                        return r;
                break;
        case NETDEV_KIND_SIT:
                r = netdev_fill_sit_rtnl_message(link, m);
                if(r < 0)
                        return r;
                break;
        case NETDEV_KIND_GRE:
        default:
                return -ENOTSUP;
        }

        r = sd_rtnl_call_async(netdev->manager->rtnl, m, callback, netdev, 0, NULL);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        log_debug_netdev(netdev, "Creating tunnel netdev: %s",
                         netdev_kind_to_string(netdev->kind));

        netdev->state = NETDEV_STATE_CREATING;

        return 0;
}
