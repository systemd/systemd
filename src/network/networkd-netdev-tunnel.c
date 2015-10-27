/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
    This file is part of systemd.

    Copyright 2014 Susant Sahani

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

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/ip.h>
#include <linux/if_tunnel.h>
#include <linux/ip6_tunnel.h>

#include "sd-netlink.h"

#include "conf-parser.h"
#include "missing.h"
#include "networkd-link.h"
#include "networkd-netdev-tunnel.h"
#include "parse-util.h"
#include "string-table.h"
#include "string-util.h"
#include "util.h"

#define DEFAULT_TNL_HOP_LIMIT   64
#define IP6_FLOWINFO_FLOWLABEL  htonl(0x000FFFFF)

static const char* const ip6tnl_mode_table[_NETDEV_IP6_TNL_MODE_MAX] = {
        [NETDEV_IP6_TNL_MODE_IP6IP6] = "ip6ip6",
        [NETDEV_IP6_TNL_MODE_IPIP6] = "ipip6",
        [NETDEV_IP6_TNL_MODE_ANYIP6] = "any",
};

DEFINE_STRING_TABLE_LOOKUP(ip6tnl_mode, Ip6TnlMode);
DEFINE_CONFIG_PARSE_ENUM(config_parse_ip6tnl_mode, ip6tnl_mode, Ip6TnlMode, "Failed to parse ip6 tunnel Mode");

static int netdev_ipip_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        Tunnel *t = IPIP(netdev);
        int r;

        assert(netdev);
        assert(link);
        assert(m);
        assert(t);
        assert(t->family == AF_INET);

        r = sd_netlink_message_append_u32(m, IFLA_IPTUN_LINK, link->ifindex);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_LINK attribute: %m");

        r = sd_netlink_message_append_in_addr(m, IFLA_IPTUN_LOCAL, &t->local.in);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_LOCAL attribute: %m");

        r = sd_netlink_message_append_in_addr(m, IFLA_IPTUN_REMOTE, &t->remote.in);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_REMOTE attribute: %m");

        r = sd_netlink_message_append_u8(m, IFLA_IPTUN_TTL, t->ttl);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_TTL  attribute: %m");

        r = sd_netlink_message_append_u8(m, IFLA_IPTUN_PMTUDISC, t->pmtudisc);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_PMTUDISC attribute: %m");

        return r;
}

static int netdev_sit_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        Tunnel *t = SIT(netdev);
        int r;

        assert(netdev);
        assert(link);
        assert(m);
        assert(t);
        assert(t->family == AF_INET);

        r = sd_netlink_message_append_u32(m, IFLA_IPTUN_LINK, link->ifindex);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_LINK attribute: %m");

        r = sd_netlink_message_append_in_addr(m, IFLA_IPTUN_LOCAL, &t->local.in);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_LOCAL attribute: %m");

        r = sd_netlink_message_append_in_addr(m, IFLA_IPTUN_REMOTE, &t->remote.in);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_REMOTE attribute: %m");

        r = sd_netlink_message_append_u8(m, IFLA_IPTUN_TTL, t->ttl);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_TTL attribute: %m");

        r = sd_netlink_message_append_u8(m, IFLA_IPTUN_PMTUDISC, t->pmtudisc);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_PMTUDISC attribute: %m");

        return r;
}

static int netdev_gre_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        Tunnel *t;
        int r;

        assert(netdev);

        if (netdev->kind == NETDEV_KIND_GRE)
                t = GRE(netdev);
        else
                t = GRETAP(netdev);

        assert(t);
        assert(t->family == AF_INET);
        assert(link);
        assert(m);

        r = sd_netlink_message_append_u32(m, IFLA_GRE_LINK, link->ifindex);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_GRE_LINK attribute: %m");

        r = sd_netlink_message_append_in_addr(m, IFLA_GRE_LOCAL, &t->local.in);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_GRE_LOCAL attribute: %m");

        r = sd_netlink_message_append_in_addr(m, IFLA_GRE_REMOTE, &t->remote.in);
        if (r < 0)
                log_netdev_error_errno(netdev, r, "Could not append IFLA_GRE_REMOTE attribute: %m");

        r = sd_netlink_message_append_u8(m, IFLA_GRE_TTL, t->ttl);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_GRE_TTL attribute: %m");

        r = sd_netlink_message_append_u8(m, IFLA_GRE_TOS, t->tos);
        if (r < 0)
                log_netdev_error_errno(netdev, r, "Could not append IFLA_GRE_TOS attribute: %m");

        r = sd_netlink_message_append_u8(m, IFLA_GRE_PMTUDISC, t->pmtudisc);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_GRE_PMTUDISC attribute: %m");

        return r;
}

static int netdev_ip6gre_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        Tunnel *t;
        int r;

        assert(netdev);

        if (netdev->kind == NETDEV_KIND_IP6GRE)
                t = IP6GRE(netdev);
        else
                t = IP6GRETAP(netdev);

        assert(t);
        assert(t->family == AF_INET6);
        assert(link);
        assert(m);

        r = sd_netlink_message_append_u32(m, IFLA_GRE_LINK, link->ifindex);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_GRE_LINK attribute: %m");

        r = sd_netlink_message_append_in6_addr(m, IFLA_GRE_LOCAL, &t->local.in6);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_GRE_LOCAL attribute: %m");

        r = sd_netlink_message_append_in6_addr(m, IFLA_GRE_REMOTE, &t->remote.in6);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_GRE_REMOTE attribute: %m");

        r = sd_netlink_message_append_u8(m, IFLA_GRE_TTL, t->ttl);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_GRE_TTL attribute: %m");

        if (t->ipv6_flowlabel != _NETDEV_IPV6_FLOWLABEL_INVALID) {
                r = sd_netlink_message_append_u32(m, IFLA_GRE_FLOWINFO, t->ipv6_flowlabel);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_GRE_FLOWINFO attribute: %m");
        }

        r = sd_netlink_message_append_u32(m, IFLA_GRE_FLAGS, t->flags);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_GRE_FLAGS attribute: %m");

        return r;
}

static int netdev_vti_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        Tunnel *t = VTI(netdev);
        int r;

        assert(netdev);
        assert(link);
        assert(m);
        assert(t);
        assert(t->family == AF_INET);

        r = sd_netlink_message_append_u32(m, IFLA_VTI_LINK, link->ifindex);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_LINK attribute: %m");

        r = sd_netlink_message_append_in_addr(m, IFLA_VTI_LOCAL, &t->local.in);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_LOCAL attribute: %m");

        r = sd_netlink_message_append_in_addr(m, IFLA_VTI_REMOTE, &t->remote.in);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_REMOTE attribute: %m");

        return r;
}

static int netdev_vti6_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        Tunnel *t = VTI6(netdev);
        int r;

        assert(netdev);
        assert(link);
        assert(m);
        assert(t);
        assert(t->family == AF_INET6);

        r = sd_netlink_message_append_u32(m, IFLA_VTI_LINK, link->ifindex);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_LINK attribute: %m");

        r = sd_netlink_message_append_in6_addr(m, IFLA_VTI_LOCAL, &t->local.in6);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_LOCAL attribute: %m");

        r = sd_netlink_message_append_in6_addr(m, IFLA_VTI_REMOTE, &t->remote.in6);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_REMOTE attribute: %m");

        return r;
}

static int netdev_ip6tnl_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        Tunnel *t = IP6TNL(netdev);
        uint8_t proto;
        int r;

        assert(netdev);
        assert(link);
        assert(m);
        assert(t);
        assert(t->family == AF_INET6);

        r = sd_netlink_message_append_u32(m, IFLA_IPTUN_LINK, link->ifindex);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_LINK attribute: %m");

        r = sd_netlink_message_append_in6_addr(m, IFLA_IPTUN_LOCAL, &t->local.in6);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_LOCAL attribute: %m");

        r = sd_netlink_message_append_in6_addr(m, IFLA_IPTUN_REMOTE, &t->remote.in6);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_REMOTE attribute: %m");

        r = sd_netlink_message_append_u8(m, IFLA_IPTUN_TTL, t->ttl);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_TTL attribute: %m");

        if (t->ipv6_flowlabel != _NETDEV_IPV6_FLOWLABEL_INVALID) {
                r = sd_netlink_message_append_u32(m, IFLA_IPTUN_FLOWINFO, t->ipv6_flowlabel);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_FLOWINFO attribute: %m");
        }

        if (t->copy_dscp)
                t->flags |= IP6_TNL_F_RCV_DSCP_COPY;

        if (t->encap_limit != IPV6_DEFAULT_TNL_ENCAP_LIMIT) {
                r = sd_netlink_message_append_u8(m, IFLA_IPTUN_ENCAP_LIMIT, t->encap_limit);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_ENCAP_LIMIT attribute: %m");
        }

        r = sd_netlink_message_append_u32(m, IFLA_IPTUN_FLAGS, t->flags);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_FLAGS attribute: %m");

        switch (t->ip6tnl_mode) {
        case NETDEV_IP6_TNL_MODE_IP6IP6:
                proto = IPPROTO_IPV6;
                break;
        case NETDEV_IP6_TNL_MODE_IPIP6:
                proto = IPPROTO_IPIP;
                break;
        case NETDEV_IP6_TNL_MODE_ANYIP6:
        default:
                proto = 0;
                break;
        }

        r = sd_netlink_message_append_u8(m, IFLA_IPTUN_PROTO, proto);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPTUN_MODE attribute: %m");

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
        case NETDEV_KIND_GRETAP:
                t = GRETAP(netdev);
                break;
        case NETDEV_KIND_IP6GRE:
                t = IP6GRE(netdev);
                break;
        case NETDEV_KIND_IP6GRETAP:
                t = IP6GRETAP(netdev);
                break;
        case NETDEV_KIND_VTI:
                t = VTI(netdev);
                break;
        case NETDEV_KIND_VTI6:
                t = VTI6(netdev);
                break;
        case NETDEV_KIND_IP6TNL:
                t = IP6TNL(netdev);
                break;
        default:
                assert_not_reached("Invalid tunnel kind");
        }

        assert(t);

        if (t->remote.in.s_addr == INADDR_ANY) {
                log_warning("Tunnel without remote address configured in %s. Ignoring", filename);
                return -EINVAL;
        }

        if (t->family != AF_INET && t->family != AF_INET6) {
                log_warning("Tunnel with invalid address family configured in %s. Ignoring", filename);
                return -EINVAL;
        }

        if (netdev->kind == NETDEV_KIND_IP6TNL) {
                if (t->ip6tnl_mode == _NETDEV_IP6_TNL_MODE_INVALID) {
                        log_warning("IP6 Tunnel without mode configured in %s. Ignoring", filename);
                        return -EINVAL;
                }
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
                log_syntax(unit, LOG_ERR, filename, line, r, "Tunnel address is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (t->family != AF_UNSPEC && t->family != f) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Tunnel addresses incompatible, ignoring assignment: %s", rvalue);
                return 0;
        }

        t->family = f;
        *addr = buffer;

        return 0;
}

int config_parse_ipv6_flowlabel(const char* unit,
                                const char *filename,
                                unsigned line,
                                const char *section,
                                unsigned section_line,
                                const char *lvalue,
                                int ltype,
                                const char *rvalue,
                                void *data,
                                void *userdata) {
        IPv6FlowLabel *ipv6_flowlabel = data;
        Tunnel *t = userdata;
        int k = 0;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(ipv6_flowlabel);

        if (streq(rvalue, "inherit")) {
                *ipv6_flowlabel = IP6_FLOWINFO_FLOWLABEL;
                t->flags |= IP6_TNL_F_USE_ORIG_FLOWLABEL;
        } else {
                r = config_parse_int(unit, filename, line, section, section_line, lvalue, ltype, rvalue, &k, userdata);
                if (r < 0)
                        return r;

                if (k > 0xFFFFF)
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse IPv6 flowlabel option, ignoring: %s", rvalue);
                else {
                        *ipv6_flowlabel = htonl(k) & IP6_FLOWINFO_FLOWLABEL;
                        t->flags &= ~IP6_TNL_F_USE_ORIG_FLOWLABEL;
                }
        }

        return 0;
}

int config_parse_encap_limit(const char* unit,
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
        int k = 0;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (streq(rvalue, "none"))
                t->flags |= IP6_TNL_F_IGN_ENCAP_LIMIT;
        else {
                r = safe_atoi(rvalue, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse Tunnel Encapsulation Limit option, ignoring: %s", rvalue);
                        return 0;
                }

                if (k > 255 || k < 0)
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid Tunnel Encapsulation value, ignoring: %d", k);
                else {
                        t->encap_limit = k;
                        t->flags &= ~IP6_TNL_F_IGN_ENCAP_LIMIT;
                }
        }

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
        Tunnel *t;

        assert(n);

        if (n->kind == NETDEV_KIND_VTI)
                t = VTI(n);
        else
                t = VTI6(n);

        assert(t);

        t->pmtudisc = true;
}

static void gre_init(NetDev *n) {
        Tunnel *t;

        assert(n);

        if (n->kind == NETDEV_KIND_GRE)
                t = GRE(n);
        else
                t = GRETAP(n);

        assert(t);

        t->pmtudisc = true;
}

static void ip6gre_init(NetDev *n) {
        Tunnel *t;

        assert(n);

        if (n->kind == NETDEV_KIND_IP6GRE)
                t = IP6GRE(n);
        else
                t = IP6GRETAP(n);

        assert(t);

        t->ttl = DEFAULT_TNL_HOP_LIMIT;
}

static void ip6tnl_init(NetDev *n) {
        Tunnel *t = IP6TNL(n);

        assert(n);
        assert(t);

        t->ttl = DEFAULT_TNL_HOP_LIMIT;
        t->encap_limit = IPV6_DEFAULT_TNL_ENCAP_LIMIT;
        t->ip6tnl_mode = _NETDEV_IP6_TNL_MODE_INVALID;
        t->ipv6_flowlabel = _NETDEV_IPV6_FLOWLABEL_INVALID;
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

const NetDevVTable vti6_vtable = {
        .object_size = sizeof(Tunnel),
        .init = vti_init,
        .sections = "Match\0NetDev\0Tunnel\0",
        .fill_message_create = netdev_vti6_fill_message_create,
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

const NetDevVTable gretap_vtable = {
        .object_size = sizeof(Tunnel),
        .init = gre_init,
        .sections = "Match\0NetDev\0Tunnel\0",
        .fill_message_create = netdev_gre_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .config_verify = netdev_tunnel_verify,
};

const NetDevVTable ip6gre_vtable = {
        .object_size = sizeof(Tunnel),
        .init = ip6gre_init,
        .sections = "Match\0NetDev\0Tunnel\0",
        .fill_message_create = netdev_ip6gre_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .config_verify = netdev_tunnel_verify,
};

const NetDevVTable ip6gretap_vtable = {
        .object_size = sizeof(Tunnel),
        .init = ip6gre_init,
        .sections = "Match\0NetDev\0Tunnel\0",
        .fill_message_create = netdev_ip6gre_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .config_verify = netdev_tunnel_verify,
};

const NetDevVTable ip6tnl_vtable = {
        .object_size = sizeof(Tunnel),
        .init = ip6tnl_init,
        .sections = "Match\0NetDev\0Tunnel\0",
        .fill_message_create = netdev_ip6tnl_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .config_verify = netdev_tunnel_verify,
};
