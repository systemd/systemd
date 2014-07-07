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

#include "sd-rtnl.h"
#include "networkd.h"
#include "network-internal.h"
#include "util.h"
#include "missing.h"
#include "conf-parser.h"


static int netdev_fill_ipip_rtnl_message(Link *link, sd_rtnl_message *m) {
        NetDev *netdev;
        int r;

        assert(link);
        assert(link->network);
        assert(link->network->tunnel);
        assert(m);

        netdev = link->network->tunnel;

        assert(netdev->family == AF_INET);

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

        if (netdev->mac) {
                r = sd_rtnl_message_append_ether_addr(m, IFLA_ADDRESS, netdev->mac);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Colud not append IFLA_ADDRESS attribute: %s",
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

        r = sd_rtnl_message_append_in_addr(m, IFLA_IPTUN_LOCAL, &netdev->local.in);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_LOCAL attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_IPTUN_REMOTE, &netdev->remote.in);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_REMOTE attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u8(m, IFLA_IPTUN_TTL, netdev->ttl);
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

        assert(netdev->family == AF_INET);

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

        if (netdev->mac) {
                r = sd_rtnl_message_append_ether_addr(m, IFLA_ADDRESS, netdev->mac);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Colud not append IFLA_ADDRESS attribute: %s",
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

        r = sd_rtnl_message_append_in_addr(m, IFLA_IPTUN_LOCAL, &netdev->local.in);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_LOCAL attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_IPTUN_REMOTE, &netdev->remote.in);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_REMOTE attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u8(m, IFLA_IPTUN_TOS, netdev->tos);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_TOS attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u8(m, IFLA_IPTUN_PMTUDISC, netdev->tunnel_pmtudisc);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_PMTUDISC attribute: %s",
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

static int netdev_fill_ipgre_rtnl_message(Link *link, sd_rtnl_message *m) {
        NetDev *netdev;
        int r;

        assert(link);
        assert(link->network);
        assert(link->network->tunnel);
        assert(m);

        netdev = link->network->tunnel;

        assert(netdev->family == AF_INET);

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

        if (netdev->mac) {
                r = sd_rtnl_message_append_ether_addr(m, IFLA_ADDRESS, netdev->mac);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Colud not append IFLA_ADDRESS attribute: %s",
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

        r = sd_rtnl_message_append_u32(m, IFLA_GRE_LINK, link->ifindex);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_GRE_LINK attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_GRE_LOCAL, &netdev->local.in);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_GRE_LOCAL attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_GRE_REMOTE, &netdev->remote.in);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_GRE_REMOTE attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u8(m, IFLA_GRE_TTL, netdev->ttl);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_GRE_TTL attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u8(m, IFLA_GRE_TOS, netdev->tos);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_GRE_TOS attribute: %s",
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

static int netdev_fill_vti_rtnl_message(Link *link, sd_rtnl_message *m) {
        NetDev *netdev;
        int r;

        assert(link);
        assert(link->network);
        assert(link->network->tunnel);
        assert(m);

        netdev = link->network->tunnel;

        assert(netdev->family == AF_INET);

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

        if (netdev->mac) {
                r = sd_rtnl_message_append_ether_addr(m, IFLA_ADDRESS, netdev->mac);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Colud not append IFLA_ADDRESS attribute: %s",
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

        r = sd_rtnl_message_append_u32(m, IFLA_VTI_LINK, link->ifindex);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_LINK attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_VTI_LOCAL, &netdev->local.in);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_LOCAL attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_VTI_REMOTE, &netdev->remote.in);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IPTUN_REMOTE attribute: %s",
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

int netdev_create_tunnel(NetDev *netdev, Link *link, sd_rtnl_message_handler_t callback) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
        int r;

        assert(netdev);
        assert(netdev->ifname);
        assert(netdev->manager);
        assert(netdev->manager->rtnl);
        assert(link);
        assert(link->network);
        assert(link->network->tunnel == netdev);

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
        case NETDEV_KIND_VTI:
                netdev_fill_vti_rtnl_message(link, m);
                if(r < 0)
                        return r;
                break;
        case NETDEV_KIND_GRE:
                r = netdev_fill_ipgre_rtnl_message(link, m);
                if(r < 0)
                        return r;
                break;
        default:
                return -ENOTSUP;
        }

        r = sd_rtnl_call_async(netdev->manager->rtnl, m, callback, link, 0, NULL);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        link_ref(link);

        log_debug_netdev(netdev, "Creating tunnel netdev: %s",
                         netdev_kind_to_string(netdev->kind));

        netdev->state = NETDEV_STATE_CREATING;

        return 0;
}

int config_parse_tunnel_address(const char *unit,
                                const char *filename,
                                unsigned line,
                                const char *section,
                                unsigned section_line,
                                const char *lvalue,
                                int ltype,
                                const char *rvalue,
                                void *data,
                                void *userdata) {
        NetDev *n = userdata;
        union in_addr_union *addr = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = net_parse_inaddr(rvalue, &n->family, addr);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Tunnel address is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        return 0;
}
