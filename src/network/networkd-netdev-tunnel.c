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
#include "networkd-netdev-tunnel.h"
#include "network-internal.h"
#include "util.h"
#include "missing.h"
#include "conf-parser.h"

static int netdev_ipip_fill_message_create(NetDev *netdev, Link *link, sd_rtnl_message *m) {
        int r;

        assert(netdev);
        assert(netdev->kind == NETDEV_KIND_IPIP);
        assert(netdev->ifname);
        assert(netdev->manager);
        assert(netdev->manager->rtnl);
        assert(link);
        assert(m);
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

static int netdev_sit_fill_message_create(NetDev *netdev, Link *link, sd_rtnl_message *m) {
        int r;

        assert(netdev);
        assert(netdev->kind == NETDEV_KIND_SIT);
        assert(netdev->ifname);
        assert(netdev->manager);
        assert(netdev->manager->rtnl);
        assert(link);
        assert(m);
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

static int netdev_gre_fill_message_create(NetDev *netdev, Link *link, sd_rtnl_message *m) {
        int r;

        assert(netdev);
        assert(netdev->kind == NETDEV_KIND_GRE);
        assert(netdev->ifname);
        assert(netdev->manager);
        assert(netdev->manager->rtnl);
        assert(link);
        assert(m);
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

static int netdev_vti_fill_message_create(NetDev *netdev, Link *link, sd_rtnl_message *m) {
        int r;

        assert(netdev);
        assert(netdev->kind == NETDEV_KIND_VTI);
        assert(netdev->ifname);
        assert(netdev->manager);
        assert(netdev->manager->rtnl);
        assert(link);
        assert(m);
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

static int netdev_tunnel_verify(NetDev *netdev, const char *filename) {
        assert(netdev);
        assert(filename);

        if (netdev->local.in.s_addr == INADDR_ANY) {
               log_warning("Tunnel without local address configured in %s. Ignoring", filename);
               return -EINVAL;
        }

        if (netdev->remote.in.s_addr == INADDR_ANY) {
               log_warning("Tunnel without remote address configured in %s. Ignoring", filename);
               return -EINVAL;
        }

        if (netdev->family != AF_INET) {
              log_warning("Tunnel with invalid address family configured in %s. Ignoring", filename);
              return -EINVAL;
        }

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

const NetDevVTable ipip_vtable = {
        .fill_message_create_on_link = netdev_ipip_fill_message_create,
        .config_verify = netdev_tunnel_verify,
};

const NetDevVTable sit_vtable = {
        .fill_message_create_on_link = netdev_sit_fill_message_create,
        .config_verify = netdev_tunnel_verify,
};

const NetDevVTable vti_vtable = {
        .fill_message_create_on_link = netdev_vti_fill_message_create,
        .config_verify = netdev_tunnel_verify,
};

const NetDevVTable gre_vtable = {
        .fill_message_create_on_link = netdev_gre_fill_message_create,
        .config_verify = netdev_tunnel_verify,
};
