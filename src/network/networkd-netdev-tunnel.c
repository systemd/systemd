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
#include "networkd-link.h"
#include "network-internal.h"
#include "util.h"
#include "missing.h"
#include "conf-parser.h"

static int netdev_ipip_fill_message_create(NetDev *netdev, Link *link, sd_rtnl_message *m) {
        Tunnel *t = IPIP(netdev);
        int r;

        assert(netdev);
        assert(link);
        assert(m);
        assert(t);
        assert(t->family == AF_INET);

        r = sd_rtnl_message_append_u32(m, IFLA_IPTUN_LINK, link->ifindex);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_IPTUN_LINK attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_IPTUN_LOCAL, &t->local.in);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_IPTUN_LOCAL attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_IPTUN_REMOTE, &t->remote.in);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_IPTUN_REMOTE attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u8(m, IFLA_IPTUN_TTL, t->ttl);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_IPTUN_TTL  attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u8(m, IFLA_IPTUN_PMTUDISC, t->pmtudisc);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_IPTUN_PMTUDISC attribute: %s",
                                 strerror(-r));
                return r;
        }

        return r;
}

static int netdev_sit_fill_message_create(NetDev *netdev, Link *link, sd_rtnl_message *m) {
        Tunnel *t = SIT(netdev);
        int r;

        assert(netdev);
        assert(link);
        assert(m);
        assert(t);
        assert(t->family == AF_INET);

        r = sd_rtnl_message_append_u32(m, IFLA_IPTUN_LINK, link->ifindex);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_IPTUN_LINK attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_IPTUN_LOCAL, &t->local.in);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_IPTUN_LOCAL attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_IPTUN_REMOTE, &t->remote.in);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_IPTUN_REMOTE attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u8(m, IFLA_IPTUN_TTL, t->ttl);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_IPTUN_TTL attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u8(m, IFLA_IPTUN_PMTUDISC, t->pmtudisc);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_IPTUN_PMTUDISC attribute: %s",
                                 strerror(-r));
                return r;
        }

        return r;
}

static int netdev_gre_fill_message_create(NetDev *netdev, Link *link, sd_rtnl_message *m) {
        Tunnel *t = GRE(netdev);
        int r;

        assert(netdev);
        assert(link);
        assert(m);
        assert(t);
        assert(t->family == AF_INET);

        r = sd_rtnl_message_append_u32(m, IFLA_GRE_LINK, link->ifindex);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_GRE_LINK attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_GRE_LOCAL, &t->local.in);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_GRE_LOCAL attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_GRE_REMOTE, &t->remote.in);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_GRE_REMOTE attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u8(m, IFLA_GRE_TTL, t->ttl);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_GRE_TTL attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u8(m, IFLA_GRE_TOS, t->tos);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_GRE_TOS attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u8(m, IFLA_GRE_PMTUDISC, t->pmtudisc);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_GRE_PMTUDISC attribute: %s",
                                 strerror(-r));
                return r;
        }

        return r;
}

static int netdev_vti_fill_message_create(NetDev *netdev, Link *link, sd_rtnl_message *m) {
        Tunnel *t = VTI(netdev);
        int r;

        assert(netdev);
        assert(link);
        assert(m);
        assert(t);
        assert(t->family == AF_INET);

        r = sd_rtnl_message_append_u32(m, IFLA_VTI_LINK, link->ifindex);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_IPTUN_LINK attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_VTI_LOCAL, &t->local.in);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_IPTUN_LOCAL attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_VTI_REMOTE, &t->remote.in);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_IPTUN_REMOTE attribute: %s",
                                 strerror(-r));
                return r;
        }

        return r;
}

static int netdev_tunnel_verify(NetDev *netdev, const char *filename) {
        Tunnel *t = NULL;

        assert(netdev);
        assert(filename);

        switch (netdev->kind) {
        case NETDEV_KIND_IPIP:
                t = IPIP(netdev);
                break;
        case NETDEV_KIND_SIT:
                t = SIT(netdev);
                break;
        case NETDEV_KIND_GRE:
                t = GRE(netdev);
                break;
        case NETDEV_KIND_VTI:
                t = VTI(netdev);
                break;
        default:
                assert_not_reached("Invalid tunnel kind");
        }

        assert(t);

        if (t->remote.in.s_addr == INADDR_ANY) {
               log_warning("Tunnel without remote address configured in %s. Ignoring", filename);
               return -EINVAL;
        }

        if (t->family != AF_INET) {
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
        Tunnel *t = userdata;
        union in_addr_union *addr = data, buffer;
        int r, f;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = in_addr_from_string_auto(rvalue, &f, &buffer);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Tunnel address is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (t->family != AF_UNSPEC && t->family != f) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Tunnel addresses incompatible, ignoring assignment: %s", rvalue);
                return 0;
        }

        t->family = f;
        *addr = buffer;

        return 0;
}

static void ipip_init(NetDev *n) {
        Tunnel *t = IPIP(n);

        assert(n);
        assert(t);

        t->pmtudisc = true;
}

static void sit_init(NetDev *n) {
        Tunnel *t = SIT(n);

        assert(n);
        assert(t);

        t->pmtudisc = true;
}

static void vti_init(NetDev *n) {
        Tunnel *t = VTI(n);

        assert(n);
        assert(t);

        t->pmtudisc = true;
}

static void gre_init(NetDev *n) {
        Tunnel *t = GRE(n);

        assert(n);
        assert(t);

        t->pmtudisc = true;
}

const NetDevVTable ipip_vtable = {
        .object_size = sizeof(Tunnel),
        .init = ipip_init,
        .sections = "Match\0NetDev\0Tunnel\0",
        .fill_message_create = netdev_ipip_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .config_verify = netdev_tunnel_verify,
};

const NetDevVTable sit_vtable = {
        .object_size = sizeof(Tunnel),
        .init = sit_init,
        .sections = "Match\0NetDev\0Tunnel\0",
        .fill_message_create = netdev_sit_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .config_verify = netdev_tunnel_verify,
};

const NetDevVTable vti_vtable = {
        .object_size = sizeof(Tunnel),
        .init = vti_init,
        .sections = "Match\0NetDev\0Tunnel\0",
        .fill_message_create = netdev_vti_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .config_verify = netdev_tunnel_verify,
};

const NetDevVTable gre_vtable = {
        .object_size = sizeof(Tunnel),
        .init = gre_init,
        .sections = "Match\0NetDev\0Tunnel\0",
        .fill_message_create = netdev_gre_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .config_verify = netdev_tunnel_verify,
};
