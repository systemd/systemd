/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/fou.h>
#include <linux/if_arp.h>
#include <linux/if_tunnel.h>
#include <linux/ip.h>
#include <linux/ip6_tunnel.h>

#include "af-list.h"
#include "conf-parser.h"
#include "hexdecoct.h"
#include "missing_network.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "siphash24.h"
#include "string-table.h"
#include "string-util.h"
#include "tunnel.h"

#define DEFAULT_IPV6_TTL   64
#define IP6_FLOWINFO_FLOWLABEL  htobe32(0x000FFFFF)
#define IP6_TNL_F_ALLOW_LOCAL_REMOTE 0x40

static const char* const ip6tnl_mode_table[_NETDEV_IP6_TNL_MODE_MAX] = {
        [NETDEV_IP6_TNL_MODE_IP6IP6] = "ip6ip6",
        [NETDEV_IP6_TNL_MODE_IPIP6]  = "ipip6",
        [NETDEV_IP6_TNL_MODE_ANYIP6] = "any",
};

DEFINE_STRING_TABLE_LOOKUP(ip6tnl_mode, Ip6TnlMode);
DEFINE_CONFIG_PARSE_ENUM(config_parse_ip6tnl_mode, ip6tnl_mode, Ip6TnlMode);

#define HASH_KEY SD_ID128_MAKE(74,c4,de,12,f3,d9,41,34,bb,3d,c1,a4,42,93,50,87)

static int dhcp4_pd_create_6rd_tunnel_name(Link *link) {
        _cleanup_free_ char *ifname_alloc = NULL;
        uint8_t ipv4masklen, sixrd_prefixlen, *buf, *p;
        struct in_addr ipv4address;
        struct in6_addr sixrd_prefix;
        char ifname[IFNAMSIZ];
        uint64_t result;
        size_t sz;
        int r;

        assert(link);
        assert(link->dhcp_lease);

        if (link->dhcp4_6rd_tunnel_name)
                return 0; /* Already set. Do not change even if the 6rd option is changed. */

        r = sd_dhcp_lease_get_address(link->dhcp_lease, &ipv4address);
        if (r < 0)
                return r;

        r = sd_dhcp_lease_get_6rd(link->dhcp_lease, &ipv4masklen, &sixrd_prefixlen, &sixrd_prefix, NULL, NULL);
        if (r < 0)
                return r;

        sz = sizeof(uint8_t) * 2 + sizeof(struct in6_addr) + sizeof(struct in_addr);
        buf = newa(uint8_t, sz);
        p = buf;
        p = mempcpy(p, &ipv4masklen, sizeof(uint8_t));
        p = mempcpy(p, &ipv4address, sizeof(struct in_addr));
        p = mempcpy(p, &sixrd_prefixlen, sizeof(uint8_t));
        p = mempcpy(p, &sixrd_prefix, sizeof(struct in6_addr));

        result = siphash24(buf, sz, HASH_KEY.bytes);
        memcpy(ifname, "6rd-", STRLEN("6rd-"));
        ifname[STRLEN("6rd-")    ] = urlsafe_base64char(result >> 54);
        ifname[STRLEN("6rd-") + 1] = urlsafe_base64char(result >> 48);
        ifname[STRLEN("6rd-") + 2] = urlsafe_base64char(result >> 42);
        ifname[STRLEN("6rd-") + 3] = urlsafe_base64char(result >> 36);
        ifname[STRLEN("6rd-") + 4] = urlsafe_base64char(result >> 30);
        ifname[STRLEN("6rd-") + 5] = urlsafe_base64char(result >> 24);
        ifname[STRLEN("6rd-") + 6] = urlsafe_base64char(result >> 18);
        ifname[STRLEN("6rd-") + 7] = urlsafe_base64char(result >> 12);
        ifname[STRLEN("6rd-") + 8] = urlsafe_base64char(result >> 6);
        ifname[STRLEN("6rd-") + 9] = urlsafe_base64char(result);
        ifname[STRLEN("6rd-") + 10] = '\0';
        assert_cc(STRLEN("6rd-") + 10 <= IFNAMSIZ);

        ifname_alloc = strdup(ifname);
        if (!ifname_alloc)
                return -ENOMEM;

        link->dhcp4_6rd_tunnel_name = TAKE_PTR(ifname_alloc);
        return 0;
}

int dhcp4_pd_create_6rd_tunnel(Link *link, link_netlink_message_handler_t callback) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        uint8_t ipv4masklen, sixrd_prefixlen;
        struct in_addr ipv4address;
        struct in6_addr sixrd_prefix;
        Link *sit = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->dhcp_lease);
        assert(callback);

        r = sd_dhcp_lease_get_address(link->dhcp_lease, &ipv4address);
        if (r < 0)
                return r;

        r = sd_dhcp_lease_get_6rd(link->dhcp_lease, &ipv4masklen, &sixrd_prefixlen, &sixrd_prefix, NULL, NULL);
        if (r < 0)
                return r;

        r = dhcp4_pd_create_6rd_tunnel_name(link);
        if (r < 0)
                return r;

        (void) link_get_by_name(link->manager, link->dhcp4_6rd_tunnel_name, &sit);

        r = sd_rtnl_message_new_link(link->manager->rtnl, &m, RTM_NEWLINK, sit ? sit->ifindex : 0);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, IFLA_IFNAME, link->dhcp4_6rd_tunnel_name);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(m, IFLA_LINKINFO);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container_union(m, IFLA_INFO_DATA, "sit");
        if (r < 0)
                return r;

        r = sd_netlink_message_append_in_addr(m, IFLA_IPTUN_LOCAL, &ipv4address);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_IPTUN_TTL, 64);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_in6_addr(m, IFLA_IPTUN_6RD_PREFIX, &sixrd_prefix);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, IFLA_IPTUN_6RD_PREFIXLEN, sixrd_prefixlen);
        if (r < 0)
                return r;

        struct in_addr relay_prefix = ipv4address;
        (void) in4_addr_mask(&relay_prefix, ipv4masklen);
        r = sd_netlink_message_append_u32(m, IFLA_IPTUN_6RD_RELAY_PREFIX, relay_prefix.s_addr);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, IFLA_IPTUN_6RD_RELAY_PREFIXLEN, ipv4masklen);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        r = netlink_call_async(link->manager->rtnl, NULL, m, callback,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return r;

        link_ref(link);
        return 0;
}

static int tunnel_get_local_address(Tunnel *t, Link *link, union in_addr_union *ret) {
        assert(t);

        if (t->local_type < 0) {
                if (ret)
                        *ret = t->local;
                return 0;
        }

        return link_get_local_address(link, t->local_type, t->family, NULL, ret);
}

static int netdev_ipip_sit_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        assert(m);

        union in_addr_union local;
        Tunnel *t = ASSERT_PTR(netdev)->kind == NETDEV_KIND_IPIP ? IPIP(netdev) : SIT(netdev);
        int r;

        if (t->external) {
                r = sd_netlink_message_append_flag(m, IFLA_IPTUN_COLLECT_METADATA);
                if (r < 0)
                        return r;

                /* If external mode is enabled, then the following settings should not be appended. */
                return 0;
        }

        if (link || t->assign_to_loopback) {
                r = sd_netlink_message_append_u32(m, IFLA_IPTUN_LINK, link ? link->ifindex : LOOPBACK_IFINDEX);
                if (r < 0)
                        return r;
        }

        r = tunnel_get_local_address(t, link, &local);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not find local address: %m");

        r = sd_netlink_message_append_in_addr(m, IFLA_IPTUN_LOCAL, &local.in);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_in_addr(m, IFLA_IPTUN_REMOTE, &t->remote.in);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_IPTUN_TTL, t->ttl);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_IPTUN_PMTUDISC, t->pmtudisc);
        if (r < 0)
                return r;

        if (t->fou_tunnel) {
                r = sd_netlink_message_append_u16(m, IFLA_IPTUN_ENCAP_TYPE, t->fou_encap_type);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_u16(m, IFLA_IPTUN_ENCAP_SPORT, htobe16(t->encap_src_port));
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_u16(m, IFLA_IPTUN_ENCAP_DPORT, htobe16(t->fou_destination_port));
                if (r < 0)
                        return r;
        }

        if (netdev->kind == NETDEV_KIND_SIT) {
                if (t->sixrd_prefixlen > 0) {
                        r = sd_netlink_message_append_in6_addr(m, IFLA_IPTUN_6RD_PREFIX, &t->sixrd_prefix);
                        if (r < 0)
                                return r;

                        /* u16 is deliberate here, even though we're passing a netmask that can never be
                         * >128. The kernel is expecting to receive the prefixlen as a u16.
                         */
                        r = sd_netlink_message_append_u16(m, IFLA_IPTUN_6RD_PREFIXLEN, t->sixrd_prefixlen);
                        if (r < 0)
                                return r;
                }

                if (t->isatap >= 0) {
                        uint16_t flags = 0;

                        SET_FLAG(flags, SIT_ISATAP, t->isatap);

                        r = sd_netlink_message_append_u16(m, IFLA_IPTUN_FLAGS, flags);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int netdev_gre_erspan_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        union in_addr_union local;
        uint32_t ikey = 0;
        uint32_t okey = 0;
        uint16_t iflags = 0;
        uint16_t oflags = 0;
        Tunnel *t;
        int r;

        assert(netdev);
        assert(m);

        switch (netdev->kind) {
        case NETDEV_KIND_GRE:
                t = GRE(netdev);
                break;
        case NETDEV_KIND_ERSPAN:
                t = ERSPAN(netdev);
                break;
        case NETDEV_KIND_GRETAP:
                t = GRETAP(netdev);
                break;
        default:
                assert_not_reached();
        }

        if (t->external) {
                r = sd_netlink_message_append_flag(m, IFLA_GRE_COLLECT_METADATA);
                if (r < 0)
                        return r;

                /* If external mode is enabled, then the following settings should not be appended. */
                return 0;
        }

        if (link || t->assign_to_loopback) {
                r = sd_netlink_message_append_u32(m, IFLA_GRE_LINK, link ? link->ifindex : LOOPBACK_IFINDEX);
                if (r < 0)
                        return r;
        }

        if (netdev->kind == NETDEV_KIND_ERSPAN) {
                r = sd_netlink_message_append_u8(m, IFLA_GRE_ERSPAN_VER, t->erspan_version);
                if (r < 0)
                        return r;

                if (t->erspan_version == 1) {
                        r = sd_netlink_message_append_u32(m, IFLA_GRE_ERSPAN_INDEX, t->erspan_index);
                        if (r < 0)
                                return r;

                } else if (t->erspan_version == 2) {
                        r = sd_netlink_message_append_u8(m, IFLA_GRE_ERSPAN_DIR, t->erspan_direction);
                        if (r < 0)
                                return r;

                        r = sd_netlink_message_append_u16(m, IFLA_GRE_ERSPAN_HWID, t->erspan_hwid);
                        if (r < 0)
                                return r;
                }
        }

        r = tunnel_get_local_address(t, link, &local);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not find local address: %m");

        r = sd_netlink_message_append_in_addr(m, IFLA_GRE_LOCAL, &local.in);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_in_addr(m, IFLA_GRE_REMOTE, &t->remote.in);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_GRE_TTL, t->ttl);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_GRE_TOS, t->tos);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_GRE_PMTUDISC, t->pmtudisc);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_GRE_IGNORE_DF, t->ignore_df);
        if (r < 0)
                return r;

        if (t->key != 0) {
                ikey = okey = htobe32(t->key);
                iflags |= GRE_KEY;
                oflags |= GRE_KEY;
        }

        if (t->ikey != 0) {
                ikey = htobe32(t->ikey);
                iflags |= GRE_KEY;
        }

        if (t->okey != 0) {
                okey = htobe32(t->okey);
                oflags |= GRE_KEY;
        }

        if (t->gre_erspan_sequence > 0) {
                iflags |= GRE_SEQ;
                oflags |= GRE_SEQ;
        } else if (t->gre_erspan_sequence == 0) {
                iflags &= ~GRE_SEQ;
                oflags &= ~GRE_SEQ;
        }

        r = sd_netlink_message_append_u32(m, IFLA_GRE_IKEY, ikey);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, IFLA_GRE_OKEY, okey);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, IFLA_GRE_IFLAGS, iflags);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, IFLA_GRE_OFLAGS, oflags);
        if (r < 0)
                return r;

        if (t->fou_tunnel) {
                r = sd_netlink_message_append_u16(m, IFLA_GRE_ENCAP_TYPE, t->fou_encap_type);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_u16(m, IFLA_GRE_ENCAP_SPORT, htobe16(t->encap_src_port));
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_u16(m, IFLA_GRE_ENCAP_DPORT, htobe16(t->fou_destination_port));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int netdev_ip6gre_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        union in_addr_union local;
        uint32_t ikey = 0, okey = 0;
        uint16_t iflags = 0, oflags = 0;
        Tunnel *t;
        int r;

        assert(netdev);
        assert(m);

        if (netdev->kind == NETDEV_KIND_IP6GRE)
                t = IP6GRE(netdev);
        else
                t = IP6GRETAP(netdev);

        if (t->external) {
                r = sd_netlink_message_append_flag(m, IFLA_GRE_COLLECT_METADATA);
                if (r < 0)
                        return r;

                /* If external mode is enabled, then the following settings should not be appended. */
                return 0;
        }

        if (link || t->assign_to_loopback) {
                r = sd_netlink_message_append_u32(m, IFLA_GRE_LINK, link ? link->ifindex : LOOPBACK_IFINDEX);
                if (r < 0)
                        return r;
        }

        r = tunnel_get_local_address(t, link, &local);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not find local address: %m");

        r = sd_netlink_message_append_in6_addr(m, IFLA_GRE_LOCAL, &local.in6);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_in6_addr(m, IFLA_GRE_REMOTE, &t->remote.in6);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_GRE_TTL, t->ttl);
        if (r < 0)
                return r;

        if (t->ipv6_flowlabel != _NETDEV_IPV6_FLOWLABEL_INVALID) {
                r = sd_netlink_message_append_u32(m, IFLA_GRE_FLOWINFO, t->ipv6_flowlabel);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_append_u32(m, IFLA_GRE_FLAGS, t->flags);
        if (r < 0)
                return r;

        if (t->key != 0) {
                ikey = okey = htobe32(t->key);
                iflags |= GRE_KEY;
                oflags |= GRE_KEY;
        }

        if (t->ikey != 0) {
                ikey = htobe32(t->ikey);
                iflags |= GRE_KEY;
        }

        if (t->okey != 0) {
                okey = htobe32(t->okey);
                oflags |= GRE_KEY;
        }

        r = sd_netlink_message_append_u32(m, IFLA_GRE_IKEY, ikey);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, IFLA_GRE_OKEY, okey);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, IFLA_GRE_IFLAGS, iflags);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, IFLA_GRE_OFLAGS, oflags);
        if (r < 0)
                return r;

        return 0;
}

static int netdev_vti_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        assert(netdev);
        assert(m);

        union in_addr_union local;
        uint32_t ikey, okey;
        Tunnel *t = netdev->kind == NETDEV_KIND_VTI ? VTI(netdev) : VTI6(netdev);
        int r;

        if (link || t->assign_to_loopback) {
                r = sd_netlink_message_append_u32(m, IFLA_VTI_LINK, link ? link->ifindex : LOOPBACK_IFINDEX);
                if (r < 0)
                        return r;
        }

        if (t->key != 0)
                ikey = okey = htobe32(t->key);
        else {
                ikey = htobe32(t->ikey);
                okey = htobe32(t->okey);
        }

        r = sd_netlink_message_append_u32(m, IFLA_VTI_IKEY, ikey);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, IFLA_VTI_OKEY, okey);
        if (r < 0)
                return r;

        r = tunnel_get_local_address(t, link, &local);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not find local address: %m");

        r = netlink_message_append_in_addr_union(m, IFLA_VTI_LOCAL, t->family, &local);
        if (r < 0)
                return r;

        r = netlink_message_append_in_addr_union(m, IFLA_VTI_REMOTE, t->family, &t->remote);
        if (r < 0)
                return r;

        return 0;
}

static int netdev_ip6tnl_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        assert(netdev);
        assert(m);

        union in_addr_union local;
        uint8_t proto;
        Tunnel *t = IP6TNL(netdev);
        int r;

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
                return r;

        if (t->external) {
                r = sd_netlink_message_append_flag(m, IFLA_IPTUN_COLLECT_METADATA);
                if (r < 0)
                        return r;

                /* If external mode is enabled, then the following settings should not be appended. */
                return 0;
        }

        if (link || t->assign_to_loopback) {
                r = sd_netlink_message_append_u32(m, IFLA_IPTUN_LINK, link ? link->ifindex : LOOPBACK_IFINDEX);
                if (r < 0)
                        return r;
        }

        r = tunnel_get_local_address(t, link, &local);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not find local address: %m");

        r = sd_netlink_message_append_in6_addr(m, IFLA_IPTUN_LOCAL, &local.in6);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_in6_addr(m, IFLA_IPTUN_REMOTE, &t->remote.in6);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_IPTUN_TTL, t->ttl);
        if (r < 0)
                return r;

        if (t->ipv6_flowlabel != _NETDEV_IPV6_FLOWLABEL_INVALID) {
                r = sd_netlink_message_append_u32(m, IFLA_IPTUN_FLOWINFO, t->ipv6_flowlabel);
                if (r < 0)
                        return r;
        }

        if (t->copy_dscp)
                t->flags |= IP6_TNL_F_RCV_DSCP_COPY;

        if (t->allow_localremote >= 0)
                SET_FLAG(t->flags, IP6_TNL_F_ALLOW_LOCAL_REMOTE, t->allow_localremote);

        r = sd_netlink_message_append_u32(m, IFLA_IPTUN_FLAGS, t->flags);
        if (r < 0)
                return r;

        if (t->encap_limit != 0) {
                r = sd_netlink_message_append_u8(m, IFLA_IPTUN_ENCAP_LIMIT, t->encap_limit);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int netdev_tunnel_is_ready_to_create(NetDev *netdev, Link *link) {
        assert(netdev);

        Tunnel *t = ASSERT_PTR(TUNNEL(netdev));

        if (t->independent)
                return true;

        return tunnel_get_local_address(t, link, NULL) >= 0;
}

static int netdev_tunnel_verify(NetDev *netdev, const char *filename) {
        assert(netdev);
        assert(filename);

        Tunnel *t = ASSERT_PTR(TUNNEL(netdev));

        if (netdev->kind == NETDEV_KIND_IP6TNL &&
            t->ip6tnl_mode == _NETDEV_IP6_TNL_MODE_INVALID)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "ip6tnl without mode configured in %s. Ignoring", filename);

        if (t->external) {
                if (IN_SET(netdev->kind, NETDEV_KIND_VTI, NETDEV_KIND_VTI6))
                        log_netdev_debug(netdev, "vti/vti6 tunnel do not support external mode, ignoring.");
                else {
                        /* tunnel with external mode does not require underlying interface. */
                        t->independent = true;

                        /* tunnel with external mode does not require any settings checked below. */
                        return 0;
                }
        }

        if (IN_SET(netdev->kind, NETDEV_KIND_VTI, NETDEV_KIND_IPIP, NETDEV_KIND_SIT, NETDEV_KIND_GRE, NETDEV_KIND_GRETAP, NETDEV_KIND_ERSPAN)) {
                if (!IN_SET(t->family, AF_UNSPEC, AF_INET))
                        return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                      "%s tunnel without a local/remote IPv4 address configured in %s, ignoring.",
                                                      netdev_kind_to_string(netdev->kind), filename);

                t->family = AF_INET; /* For netlink_message_append_in_addr_union(). */
        }

        if (IN_SET(netdev->kind, NETDEV_KIND_VTI6, NETDEV_KIND_IP6TNL, NETDEV_KIND_IP6GRE, NETDEV_KIND_IP6GRETAP)) {
                if (!IN_SET(t->family, AF_UNSPEC, AF_INET6))
                        return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                      "%s tunnel without a local/remote IPv6 address configured in %s, ignoring,",
                                                      netdev_kind_to_string(netdev->kind), filename);
                t->family = AF_INET6; /* For netlink_message_append_in_addr_union(). */
        }

        if (t->fou_tunnel && t->fou_destination_port <= 0)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "FooOverUDP missing port configured in %s. Ignoring", filename);

        if (t->assign_to_loopback)
                t->independent = true;

        if (t->independent && t->local_type >= 0)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "The local address cannot be '%s' when Independent= or AssignToLoopback= is enabled, ignoring.",
                                              strna(netdev_local_address_type_to_string(t->local_type)));

        if (t->pmtudisc > 0 && t->ignore_df)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "IgnoreDontFragment= cannot be enabled when DiscoverPathMTU= is enabled");
        if (t->pmtudisc < 0)
                t->pmtudisc = !t->ignore_df;
        return 0;
}

static bool tunnel_needs_reconfigure(NetDev *netdev, NetDevLocalAddressType type) {
        assert(type >= 0 && type < _NETDEV_LOCAL_ADDRESS_TYPE_MAX);

        Tunnel *t = ASSERT_PTR(TUNNEL(netdev));

        return t->local_type == type;
}

static int unset_local(Tunnel *t) {
        assert(t);

        /* Unset the previous assignment. */
        t->local = IN_ADDR_NULL;
        t->local_type = _NETDEV_LOCAL_ADDRESS_TYPE_INVALID;

        /* If the remote address is not specified, also clear the address family. */
        if (!in_addr_is_set(t->family, &t->remote))
                t->family = AF_UNSPEC;

        return 0;
}

int config_parse_tunnel_local_address(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        union in_addr_union buffer = IN_ADDR_NULL;
        NetDevLocalAddressType type;
        Tunnel *t = ASSERT_PTR(userdata);
        int r, f;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue) || streq(rvalue, "any"))
                return unset_local(t);

        type = netdev_local_address_type_from_string(rvalue);
        if (IN_SET(type, NETDEV_LOCAL_ADDRESS_IPV4LL, NETDEV_LOCAL_ADDRESS_DHCP4))
                f = AF_INET;
        else if (IN_SET(type, NETDEV_LOCAL_ADDRESS_IPV6LL, NETDEV_LOCAL_ADDRESS_DHCP6, NETDEV_LOCAL_ADDRESS_SLAAC))
                f = AF_INET6;
        else {
                type = _NETDEV_LOCAL_ADDRESS_TYPE_INVALID;
                r = in_addr_from_string_auto(rvalue, &f, &buffer);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Tunnel address \"%s\" invalid, ignoring assignment: %m", rvalue);
                        return 0;
                }

                if (in_addr_is_null(f, &buffer))
                        return unset_local(t);
        }

        if (t->family != AF_UNSPEC && t->family != f) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Address family does not match the previous assignment, ignoring assignment: %s", rvalue);
                return 0;
        }

        t->family = f;
        t->local = buffer;
        t->local_type = type;
        return 0;
}

static int unset_remote(Tunnel *t) {
        assert(t);

        /* Unset the previous assignment. */
        t->remote = IN_ADDR_NULL;

        /* If the local address is not specified, also clear the address family. */
        if (t->local_type == _NETDEV_LOCAL_ADDRESS_TYPE_INVALID &&
            !in_addr_is_set(t->family, &t->local))
                t->family = AF_UNSPEC;

        return 0;
}

int config_parse_tunnel_remote_address(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        union in_addr_union buffer;
        Tunnel *t = ASSERT_PTR(userdata);
        int r, f;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue) || streq(rvalue, "any"))
                return unset_remote(t);

        r = in_addr_from_string_auto(rvalue, &f, &buffer);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Tunnel address \"%s\" invalid, ignoring assignment: %m", rvalue);
                return 0;
        }

        if (in_addr_is_null(f, &buffer))
                return unset_remote(t);

        if (t->family != AF_UNSPEC && t->family != f) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Address family does not match the previous assignment, ignoring assignment: %s", rvalue);
                return 0;
        }

        t->family = f;
        t->remote = buffer;
        return 0;
}

int config_parse_tunnel_key(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint32_t *dest = ASSERT_PTR(data), k;
        union in_addr_union buffer;
        int r;

        assert(filename);
        assert(rvalue);

        r = in_addr_from_string(AF_INET, rvalue, &buffer);
        if (r < 0) {
                r = safe_atou32(rvalue, &k);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse tunnel key ignoring assignment: %s", rvalue);
                        return 0;
                }
        } else
                k = be32toh(buffer.in.s_addr);

        *dest = k;
        return 0;
}

int config_parse_ipv6_flowlabel(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Tunnel *t = ASSERT_PTR(userdata);
        uint32_t k;
        int r;

        assert(filename);
        assert(rvalue);

        if (streq(rvalue, "inherit")) {
                t->ipv6_flowlabel = IP6_FLOWINFO_FLOWLABEL;
                t->flags |= IP6_TNL_F_USE_ORIG_FLOWLABEL;
                return 0;
        }

        r = config_parse_uint32_bounded(
                        unit, filename, line, section, section_line, lvalue, rvalue,
                        0, 0xFFFFF, true,
                        &k);
        if (r <= 0)
                return r;
        t->ipv6_flowlabel = htobe32(k) & IP6_FLOWINFO_FLOWLABEL;
        t->flags &= ~IP6_TNL_F_USE_ORIG_FLOWLABEL;

        return 0;
}

int config_parse_encap_limit(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        assert(filename);
        assert(rvalue);

        Tunnel *t = ASSERT_PTR(userdata);
        int r;

        if (streq(rvalue, "none")) {
                t->encap_limit = 0;
                t->flags |= IP6_TNL_F_IGN_ENCAP_LIMIT;
                return 0;
        }

        r = config_parse_uint8_bounded(
                        unit, filename, line, section, section_line, lvalue, rvalue,
                        0, UINT8_MAX, true,
                        &t->encap_limit);
        if (r <= 0)
                return r;
        t->flags &= ~IP6_TNL_F_IGN_ENCAP_LIMIT;

        return 0;
}

int config_parse_6rd_prefix(
                const char* unit,
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
        union in_addr_union p;
        uint8_t l;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = in_addr_prefix_from_string(rvalue, AF_INET6, &p, &l);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse 6rd prefix \"%s\", ignoring: %m", rvalue);
                return 0;
        }
        if (l == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "6rd prefix length of \"%s\" must be greater than zero, ignoring", rvalue);
                return 0;
        }

        t->sixrd_prefix = p.in6;
        t->sixrd_prefixlen = l;

        return 0;
}

int config_parse_erspan_version(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        uint8_t *v = ASSERT_PTR(data);

        if (isempty(rvalue)) {
                *v = 1; /* defaults to 1 */
                return 0;
        }

        return config_parse_uint8_bounded(
                        unit, filename, line, section, section_line, lvalue, rvalue,
                        0, 2, true,
                        v);
}

int config_parse_erspan_index(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        uint32_t *v = ASSERT_PTR(data);

        if (isempty(rvalue)) {
                *v = 0; /* defaults to 0 */
                return 0;
        }

        return config_parse_uint32_bounded(
                        unit, filename, line, section, section_line, lvalue, rvalue,
                        0, 0x100000 - 1, true,
                        v);
}

int config_parse_erspan_direction(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        uint8_t *v = ASSERT_PTR(data);

        if (isempty(rvalue) || streq(rvalue, "ingress"))
                *v = 0; /* defaults to ingress */
        else if (streq(rvalue, "egress"))
                *v = 1;
        else
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid erspan direction \"%s\", which must be \"ingress\" or \"egress\", ignoring.", rvalue);

        return 0;
}

int config_parse_erspan_hwid(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        uint16_t *v = ASSERT_PTR(data);

        if (isempty(rvalue)) {
                *v = 0; /* defaults to 0 */
                return 0;
        }

        return config_parse_uint16_bounded(
                        unit, filename, line, section, section_line, lvalue, rvalue,
                        0, 63, true,
                        v);
}

static void netdev_tunnel_init(NetDev *netdev) {
        Tunnel *t = ASSERT_PTR(TUNNEL(netdev));

        t->local_type = _NETDEV_LOCAL_ADDRESS_TYPE_INVALID;
        t->pmtudisc = -1;
        t->fou_encap_type = NETDEV_FOO_OVER_UDP_ENCAP_DIRECT;
        t->isatap = -1;
        t->gre_erspan_sequence = -1;
        t->encap_limit = IPV6_DEFAULT_TNL_ENCAP_LIMIT;
        t->ip6tnl_mode = _NETDEV_IP6_TNL_MODE_INVALID;
        t->ipv6_flowlabel = _NETDEV_IPV6_FLOWLABEL_INVALID;
        t->allow_localremote = -1;
        t->erspan_version = 1;

        if (IN_SET(netdev->kind, NETDEV_KIND_IP6GRE, NETDEV_KIND_IP6GRETAP, NETDEV_KIND_IP6TNL))
                t->ttl = DEFAULT_IPV6_TTL;
}

static bool tunnel_can_set_mac(NetDev *netdev, const struct hw_addr_data *hw_addr) {
        assert(IN_SET(netdev->kind, NETDEV_KIND_GRETAP, NETDEV_KIND_IP6GRETAP, NETDEV_KIND_ERSPAN));
        return true;
}

const NetDevVTable ipip_vtable = {
        .object_size = sizeof(Tunnel),
        .init = netdev_tunnel_init,
        .sections = NETDEV_COMMON_SECTIONS "Tunnel\0",
        .fill_message_create = netdev_ipip_sit_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .is_ready_to_create = netdev_tunnel_is_ready_to_create,
        .config_verify = netdev_tunnel_verify,
        .needs_reconfigure = tunnel_needs_reconfigure,
        .iftype = ARPHRD_TUNNEL,
};

const NetDevVTable sit_vtable = {
        .object_size = sizeof(Tunnel),
        .init = netdev_tunnel_init,
        .sections = NETDEV_COMMON_SECTIONS "Tunnel\0",
        .fill_message_create = netdev_ipip_sit_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .is_ready_to_create = netdev_tunnel_is_ready_to_create,
        .config_verify = netdev_tunnel_verify,
        .needs_reconfigure = tunnel_needs_reconfigure,
        .iftype = ARPHRD_SIT,
};

const NetDevVTable vti_vtable = {
        .object_size = sizeof(Tunnel),
        .init = netdev_tunnel_init,
        .sections = NETDEV_COMMON_SECTIONS "Tunnel\0",
        .fill_message_create = netdev_vti_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .is_ready_to_create = netdev_tunnel_is_ready_to_create,
        .config_verify = netdev_tunnel_verify,
        .needs_reconfigure = tunnel_needs_reconfigure,
        .iftype = ARPHRD_TUNNEL,
};

const NetDevVTable vti6_vtable = {
        .object_size = sizeof(Tunnel),
        .init = netdev_tunnel_init,
        .sections = NETDEV_COMMON_SECTIONS "Tunnel\0",
        .fill_message_create = netdev_vti_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .is_ready_to_create = netdev_tunnel_is_ready_to_create,
        .config_verify = netdev_tunnel_verify,
        .needs_reconfigure = tunnel_needs_reconfigure,
        .iftype = ARPHRD_TUNNEL6,
};

const NetDevVTable gre_vtable = {
        .object_size = sizeof(Tunnel),
        .init = netdev_tunnel_init,
        .sections = NETDEV_COMMON_SECTIONS "Tunnel\0",
        .fill_message_create = netdev_gre_erspan_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .is_ready_to_create = netdev_tunnel_is_ready_to_create,
        .config_verify = netdev_tunnel_verify,
        .needs_reconfigure = tunnel_needs_reconfigure,
        .iftype = ARPHRD_IPGRE,
};

const NetDevVTable gretap_vtable = {
        .object_size = sizeof(Tunnel),
        .init = netdev_tunnel_init,
        .sections = NETDEV_COMMON_SECTIONS "Tunnel\0",
        .fill_message_create = netdev_gre_erspan_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .is_ready_to_create = netdev_tunnel_is_ready_to_create,
        .config_verify = netdev_tunnel_verify,
        .needs_reconfigure = tunnel_needs_reconfigure,
        .can_set_mac = tunnel_can_set_mac,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
};

const NetDevVTable ip6gre_vtable = {
        .object_size = sizeof(Tunnel),
        .init = netdev_tunnel_init,
        .sections = NETDEV_COMMON_SECTIONS "Tunnel\0",
        .fill_message_create = netdev_ip6gre_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .is_ready_to_create = netdev_tunnel_is_ready_to_create,
        .config_verify = netdev_tunnel_verify,
        .needs_reconfigure = tunnel_needs_reconfigure,
        .iftype = ARPHRD_IP6GRE,
};

const NetDevVTable ip6gretap_vtable = {
        .object_size = sizeof(Tunnel),
        .init = netdev_tunnel_init,
        .sections = NETDEV_COMMON_SECTIONS "Tunnel\0",
        .fill_message_create = netdev_ip6gre_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .is_ready_to_create = netdev_tunnel_is_ready_to_create,
        .config_verify = netdev_tunnel_verify,
        .needs_reconfigure = tunnel_needs_reconfigure,
        .can_set_mac = tunnel_can_set_mac,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
};

const NetDevVTable ip6tnl_vtable = {
        .object_size = sizeof(Tunnel),
        .init = netdev_tunnel_init,
        .sections = NETDEV_COMMON_SECTIONS "Tunnel\0",
        .fill_message_create = netdev_ip6tnl_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .is_ready_to_create = netdev_tunnel_is_ready_to_create,
        .config_verify = netdev_tunnel_verify,
        .needs_reconfigure = tunnel_needs_reconfigure,
        .iftype = ARPHRD_TUNNEL6,
};

const NetDevVTable erspan_vtable = {
        .object_size = sizeof(Tunnel),
        .init = netdev_tunnel_init,
        .sections = NETDEV_COMMON_SECTIONS "Tunnel\0",
        .fill_message_create = netdev_gre_erspan_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .is_ready_to_create = netdev_tunnel_is_ready_to_create,
        .config_verify = netdev_tunnel_verify,
        .needs_reconfigure = tunnel_needs_reconfigure,
        .can_set_mac = tunnel_can_set_mac,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
};
