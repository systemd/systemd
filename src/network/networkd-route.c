/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/icmpv6.h>
#include <linux/ipv6_route.h>

#include "alloc-util.h"
#include "netlink-util.h"
#include "networkd-ipv4ll.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-nexthop.h"
#include "networkd-route.h"
#include "networkd-routing-policy-rule.h"
#include "parse-util.h"
#include "socket-netlink.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "strxcpyx.h"
#include "sysctl-util.h"
#include "vrf.h"

#define ROUTES_DEFAULT_MAX_PER_FAMILY 4096U

static uint32_t link_get_vrf_table(const Link *link) {
        return link->network->vrf ? VRF(link->network->vrf)->table : RT_TABLE_MAIN;
}

uint32_t link_get_dhcp_route_table(const Link *link) {
        /* When the interface is part of an VRF use the VRFs routing table, unless
         * another table is explicitly specified. */
        if (link->network->dhcp_route_table_set)
                return link->network->dhcp_route_table;
        return link_get_vrf_table(link);
}

uint32_t link_get_ipv6_accept_ra_route_table(const Link *link) {
        if (link->network->ipv6_accept_ra_route_table_set)
                return link->network->ipv6_accept_ra_route_table;
        return link_get_vrf_table(link);
}

static const char * const route_type_table[__RTN_MAX] = {
        [RTN_UNICAST]     = "unicast",
        [RTN_LOCAL]       = "local",
        [RTN_BROADCAST]   = "broadcast",
        [RTN_ANYCAST]     = "anycast",
        [RTN_MULTICAST]   = "multicast",
        [RTN_BLACKHOLE]   = "blackhole",
        [RTN_UNREACHABLE] = "unreachable",
        [RTN_PROHIBIT]    = "prohibit",
        [RTN_THROW]       = "throw",
        [RTN_NAT]         = "nat",
        [RTN_XRESOLVE]    = "xresolve",
};

assert_cc(__RTN_MAX <= UCHAR_MAX);
DEFINE_PRIVATE_STRING_TABLE_LOOKUP(route_type, int);

static const char * const route_scope_table[] = {
        [RT_SCOPE_UNIVERSE] = "global",
        [RT_SCOPE_SITE]     = "site",
        [RT_SCOPE_LINK]     = "link",
        [RT_SCOPE_HOST]     = "host",
        [RT_SCOPE_NOWHERE]  = "nowhere",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(route_scope, int);
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING_FALLBACK(route_scope, int, UINT8_MAX);

static const char * const route_table_table[] = {
        [RT_TABLE_DEFAULT] = "default",
        [RT_TABLE_MAIN]    = "main",
        [RT_TABLE_LOCAL]   = "local",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(route_table, int);

int manager_get_route_table_from_string(const Manager *m, const char *s, uint32_t *ret) {
        uint32_t t;
        int r;

        assert(m);
        assert(s);
        assert(ret);

        r = route_table_from_string(s);
        if (r >= 0) {
                *ret = (uint32_t) r;
                return 0;
        }

        t = PTR_TO_UINT32(hashmap_get(m->route_table_numbers_by_name, s));
        if (t != 0) {
                *ret = t;
                return 0;
        }

        r = safe_atou32(s, &t);
        if (r < 0)
                return r;

        if (t == 0)
                return -ERANGE;

        *ret = t;
        return 0;
}

int manager_get_route_table_to_string(const Manager *m, uint32_t table, char **ret) {
        _cleanup_free_ char *str = NULL;
        const char *s;

        assert(m);
        assert(ret);

        if (table == 0)
                return -EINVAL;

        s = route_table_to_string(table);
        if (!s)
                s = hashmap_get(m->route_table_names_by_number, UINT32_TO_PTR(table));

        if (s) {
                /* Currently, this is only used in debugging logs. To not confuse any bug
                 * reports, let's include the table number. */
                if (asprintf(&str, "%s(%" PRIu32 ")", s, table) < 0)
                        return -ENOMEM;

                *ret = TAKE_PTR(str);
                return 0;
        }

        if (asprintf(&str, "%" PRIu32, table) < 0)
                return -ENOMEM;

        *ret = TAKE_PTR(str);
        return 0;
}

static const char * const route_protocol_table[] = {
        [RTPROT_KERNEL] = "kernel",
        [RTPROT_BOOT]   = "boot",
        [RTPROT_STATIC] = "static",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_FALLBACK(route_protocol, int, UINT8_MAX);

static const char * const route_protocol_full_table[] = {
        [RTPROT_REDIRECT] = "redirect",
        [RTPROT_KERNEL]   = "kernel",
        [RTPROT_BOOT]     = "boot",
        [RTPROT_STATIC]   = "static",
        [RTPROT_GATED]    = "gated",
        [RTPROT_RA]       = "ra",
        [RTPROT_MRT]      = "mrt",
        [RTPROT_ZEBRA]    = "zebra",
        [RTPROT_BIRD]     = "bird",
        [RTPROT_DNROUTED] = "dnrouted",
        [RTPROT_XORP]     = "xorp",
        [RTPROT_NTK]      = "ntk",
        [RTPROT_DHCP]     = "dhcp",
        [RTPROT_MROUTED]  = "mrouted",
        [RTPROT_BABEL]    = "babel",
        [RTPROT_BGP]      = "bgp",
        [RTPROT_ISIS]     = "isis",
        [RTPROT_OSPF]     = "ospf",
        [RTPROT_RIP]      = "rip",
        [RTPROT_EIGRP]    = "eigrp",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING_FALLBACK(route_protocol_full, int, UINT8_MAX);

static unsigned routes_max(void) {
        static thread_local unsigned cached = 0;
        _cleanup_free_ char *s4 = NULL, *s6 = NULL;
        unsigned val4 = ROUTES_DEFAULT_MAX_PER_FAMILY, val6 = ROUTES_DEFAULT_MAX_PER_FAMILY;

        if (cached > 0)
                return cached;

        if (sysctl_read_ip_property(AF_INET, NULL, "route/max_size", &s4) >= 0)
                if (safe_atou(s4, &val4) >= 0 && val4 == 2147483647U)
                        /* This is the default "no limit" value in the kernel */
                        val4 = ROUTES_DEFAULT_MAX_PER_FAMILY;

        if (sysctl_read_ip_property(AF_INET6, NULL, "route/max_size", &s6) >= 0)
                (void) safe_atou(s6, &val6);

        cached = MAX(ROUTES_DEFAULT_MAX_PER_FAMILY, val4) +
                 MAX(ROUTES_DEFAULT_MAX_PER_FAMILY, val6);
        return cached;
}

int route_new(Route **ret) {
        _cleanup_(route_freep) Route *route = NULL;

        route = new(Route, 1);
        if (!route)
                return -ENOMEM;

        *route = (Route) {
                .family = AF_UNSPEC,
                .scope = RT_SCOPE_UNIVERSE,
                .protocol = RTPROT_UNSPEC,
                .type = RTN_UNICAST,
                .table = RT_TABLE_MAIN,
                .lifetime = USEC_INFINITY,
                .quickack = -1,
                .fast_open_no_cookie = -1,
                .gateway_onlink = -1,
                .ttl_propagate = -1,
        };

        *ret = TAKE_PTR(route);

        return 0;
}

static int route_new_static(Network *network, const char *filename, unsigned section_line, Route **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(route_freep) Route *route = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        route = hashmap_get(network->routes_by_section, n);
        if (route) {
                *ret = TAKE_PTR(route);
                return 0;
        }

        if (hashmap_size(network->routes_by_section) >= routes_max())
                return -E2BIG;

        r = route_new(&route);
        if (r < 0)
                return r;

        route->protocol = RTPROT_STATIC;
        route->network = network;
        route->section = TAKE_PTR(n);

        r = hashmap_ensure_put(&network->routes_by_section, &network_config_hash_ops, route->section, route);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(route);
        return 0;
}

Route *route_free(Route *route) {
        if (!route)
                return NULL;

        if (route->network) {
                assert(route->section);
                hashmap_remove(route->network->routes_by_section, route->section);
        }

        network_config_section_free(route->section);

        if (route->link) {
                NDiscRoute *n;

                set_remove(route->link->routes, route);
                set_remove(route->link->routes_foreign, route);
                set_remove(route->link->dhcp_routes, route);
                set_remove(route->link->dhcp_routes_old, route);
                set_remove(route->link->dhcp6_routes, route);
                set_remove(route->link->dhcp6_routes_old, route);
                set_remove(route->link->dhcp6_pd_routes, route);
                set_remove(route->link->dhcp6_pd_routes_old, route);
                SET_FOREACH(n, route->link->ndisc_routes)
                        if (n->route == route)
                                free(set_remove(route->link->ndisc_routes, n));
        }

        if (route->manager) {
                set_remove(route->manager->routes, route);
                set_remove(route->manager->routes_foreign, route);
        }

        ordered_set_free_free(route->multipath_routes);

        sd_event_source_unref(route->expire);

        return mfree(route);
}

void route_hash_func(const Route *route, struct siphash *state) {
        assert(route);

        siphash24_compress(&route->family, sizeof(route->family), state);

        switch (route->family) {
        case AF_INET:
        case AF_INET6:
                siphash24_compress(&route->dst_prefixlen, sizeof(route->dst_prefixlen), state);
                siphash24_compress(&route->dst, FAMILY_ADDRESS_SIZE(route->family), state);

                siphash24_compress(&route->src_prefixlen, sizeof(route->src_prefixlen), state);
                siphash24_compress(&route->src, FAMILY_ADDRESS_SIZE(route->family), state);

                siphash24_compress(&route->gw_family, sizeof(route->gw_family), state);
                if (IN_SET(route->gw_family, AF_INET, AF_INET6)) {
                        siphash24_compress(&route->gw, FAMILY_ADDRESS_SIZE(route->gw_family), state);
                        siphash24_compress(&route->gw_weight, sizeof(route->gw_weight), state);
                }

                siphash24_compress(&route->prefsrc, FAMILY_ADDRESS_SIZE(route->family), state);

                siphash24_compress(&route->tos, sizeof(route->tos), state);
                siphash24_compress(&route->priority, sizeof(route->priority), state);
                siphash24_compress(&route->table, sizeof(route->table), state);
                siphash24_compress(&route->protocol, sizeof(route->protocol), state);
                siphash24_compress(&route->scope, sizeof(route->scope), state);
                siphash24_compress(&route->type, sizeof(route->type), state);

                siphash24_compress(&route->initcwnd, sizeof(route->initcwnd), state);
                siphash24_compress(&route->initrwnd, sizeof(route->initrwnd), state);

                siphash24_compress(&route->advmss, sizeof(route->advmss), state);
                siphash24_compress(&route->nexthop_id, sizeof(route->nexthop_id), state);

                break;
        default:
                /* treat any other address family as AF_UNSPEC */
                break;
        }
}

int route_compare_func(const Route *a, const Route *b) {
        int r;

        r = CMP(a->family, b->family);
        if (r != 0)
                return r;

        switch (a->family) {
        case AF_INET:
        case AF_INET6:
                r = CMP(a->dst_prefixlen, b->dst_prefixlen);
                if (r != 0)
                        return r;

                r = memcmp(&a->dst, &b->dst, FAMILY_ADDRESS_SIZE(a->family));
                if (r != 0)
                        return r;

                r = CMP(a->src_prefixlen, b->src_prefixlen);
                if (r != 0)
                        return r;

                r = memcmp(&a->src, &b->src, FAMILY_ADDRESS_SIZE(a->family));
                if (r != 0)
                        return r;

                r = CMP(a->gw_family, b->gw_family);
                if (r != 0)
                        return r;

                if (IN_SET(a->gw_family, AF_INET, AF_INET6)) {
                        r = memcmp(&a->gw, &b->gw, FAMILY_ADDRESS_SIZE(a->family));
                        if (r != 0)
                                return r;

                        r = CMP(a->gw_weight, b->gw_weight);
                        if (r != 0)
                                return r;
                }

                r = memcmp(&a->prefsrc, &b->prefsrc, FAMILY_ADDRESS_SIZE(a->family));
                if (r != 0)
                        return r;

                r = CMP(a->tos, b->tos);
                if (r != 0)
                        return r;

                r = CMP(a->priority, b->priority);
                if (r != 0)
                        return r;

                r = CMP(a->table, b->table);
                if (r != 0)
                        return r;

                r = CMP(a->protocol, b->protocol);
                if (r != 0)
                        return r;

                r = CMP(a->scope, b->scope);
                if (r != 0)
                        return r;

                r = CMP(a->type, b->type);
                if (r != 0)
                        return r;

                r = CMP(a->initcwnd, b->initcwnd);
                if (r != 0)
                        return r;

                r = CMP(a->initrwnd, b->initrwnd);
                if (r != 0)
                        return r;

                r = CMP(a->advmss, b->advmss);
                if (r != 0)
                        return r;

                r = CMP(a->nexthop_id, b->nexthop_id);
                if (r != 0)
                        return r;

                return 0;
        default:
                /* treat any other address family as AF_UNSPEC */
                return 0;
        }
}

DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                route_hash_ops,
                Route,
                route_hash_func,
                route_compare_func,
                route_free);

static bool route_equal(const Route *r1, const Route *r2) {
        if (r1 == r2)
                return true;

        if (!r1 || !r2)
                return false;

        return route_compare_func(r1, r2) == 0;
}

static int route_get(const Manager *manager, const Link *link, const Route *in, Route **ret) {
        Route *existing;

        assert(manager || link);
        assert(in);

        existing = set_get(link ? link->routes : manager->routes, in);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 1;
        }

        existing = set_get(link ? link->routes_foreign : manager->routes_foreign, in);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 0;
        }

        return -ENOENT;
}

static void route_copy(Route *dest, const Route *src, const MultipathRoute *m, const NextHop *nh) {
        assert(dest);
        assert(src);

        /* This only copies entries used by the above hash and compare functions. */

        dest->family = src->family;
        dest->src = src->src;
        dest->src_prefixlen = src->src_prefixlen;
        dest->dst = src->dst;
        dest->dst_prefixlen = src->dst_prefixlen;
        dest->prefsrc = src->prefsrc;
        dest->scope = src->scope;
        dest->protocol = src->protocol;
        if (nh && nh->blackhole)
                dest->type = RTN_BLACKHOLE;
        else
                dest->type = src->type;
        dest->tos = src->tos;
        dest->priority = src->priority;
        dest->table = src->table;
        dest->initcwnd = src->initcwnd;
        dest->initrwnd = src->initrwnd;
        dest->lifetime = src->lifetime;
        dest->advmss = src->advmss;
        dest->nexthop_id = src->nexthop_id;

        if (nh) {
                dest->gw_family = nh->family;
                dest->gw = nh->gw;
                dest->gw_weight = src->gw_weight;
        } else if (m) {
                dest->gw_family = m->gateway.family;
                dest->gw = m->gateway.address;
                dest->gw_weight = m->weight;
        } else {
                dest->gw_family = src->gw_family;
                dest->gw = src->gw;
                dest->gw_weight = src->gw_weight;
        }
}

static int route_add_internal(Manager *manager, Link *link, Set **routes, const Route *in, Route **ret) {
        _cleanup_(route_freep) Route *route = NULL;
        int r;

        assert(manager || link);
        assert(routes);
        assert(in);

        r = route_new(&route);
        if (r < 0)
                return r;

        route_copy(route, in, NULL, NULL);

        r = set_ensure_put(routes, &route_hash_ops, route);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        route->link = link;
        route->manager = manager;

        if (ret)
                *ret = route;

        route = NULL;

        return 0;
}

static int route_add_foreign(Manager *manager, Link *link, const Route *in, Route **ret) {
        assert(manager || link);
        return route_add_internal(manager, link, link ? &link->routes_foreign : &manager->routes_foreign, in, ret);
}

static int route_add(Manager *manager, Link *link, const Route *in, const MultipathRoute *m, const NextHop *nh, Route **ret) {
        _cleanup_(route_freep) Route *tmp = NULL;
        bool is_new = false;
        Route *route;
        int r;

        assert(manager || link);
        assert(in);

        if (nh) {
                r = route_new(&tmp);
                if (r < 0)
                        return r;

                route_copy(tmp, in, NULL, nh);
                in = tmp;
        } else if (m) {
                assert(link && (m->ifindex == 0 || m->ifindex == link->ifindex));

                r = route_new(&tmp);
                if (r < 0)
                        return r;

                route_copy(tmp, in, m, NULL);
                in = tmp;
        }

        r = route_get(manager, link, in, &route);
        if (r == -ENOENT) {
                /* Route does not exist, create a new one */
                r = route_add_internal(manager, link, link ? &link->routes : &manager->routes, in, &route);
                if (r < 0)
                        return r;
                is_new = true;
        } else if (r == 0) {
                /* Take over a foreign route */
                r = set_ensure_put(link ? &link->routes : &manager->routes, &route_hash_ops, route);
                if (r < 0)
                        return r;

                set_remove(link ? link->routes_foreign : manager->routes_foreign, route);
        } else if (r == 1) {
                /* Route exists, do nothing */
                ;
        } else
                return r;

        if (ret)
                *ret = route;
        return is_new;
}

static bool route_type_is_reject(const Route *route) {
        assert(route);

        return IN_SET(route->type, RTN_UNREACHABLE, RTN_PROHIBIT, RTN_BLACKHOLE, RTN_THROW);
}

static void log_route_debug(const Route *route, const char *str, const Link *link, const Manager *m) {
        assert(route);
        assert(str);
        assert(m);

        /* link may be NULL. */

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *dst = NULL, *src = NULL, *gw = NULL, *prefsrc = NULL,
                        *table = NULL, *scope = NULL, *proto = NULL;

                if (in_addr_is_set(route->family, &route->dst))
                        (void) in_addr_prefix_to_string(route->family, &route->dst, route->dst_prefixlen, &dst);
                if (in_addr_is_set(route->family, &route->src))
                        (void) in_addr_to_string(route->family, &route->src, &src);
                if (in_addr_is_set(route->gw_family, &route->gw))
                        (void) in_addr_to_string(route->gw_family, &route->gw, &gw);
                if (in_addr_is_set(route->family, &route->prefsrc))
                        (void) in_addr_to_string(route->family, &route->prefsrc, &prefsrc);
                (void) route_scope_to_string_alloc(route->scope, &scope);
                (void) manager_get_route_table_to_string(m, route->table, &table);
                (void) route_protocol_full_to_string_alloc(route->protocol, &proto);

                log_link_debug(link,
                               "%s route: dst: %s, src: %s, gw: %s, prefsrc: %s, scope: %s, table: %s, proto: %s, type: %s, nexthop: %"PRIu32,
                               str, strna(dst), strna(src), strna(gw), strna(prefsrc),
                               strna(scope), strna(table), strna(proto),
                               strna(route_type_to_string(route->type)),
                               route->nexthop_id);
        }
}

static int route_set_netlink_message(const Route *route, sd_netlink_message *req, Link *link) {
        unsigned flags;
        int r;

        assert(route);
        assert(req);

        /* link may be NULL */

        if (in_addr_is_set(route->gw_family, &route->gw)) {
                if (route->gw_family == route->family) {
                        r = netlink_message_append_in_addr_union(req, RTA_GATEWAY, route->gw_family, &route->gw);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not append RTA_GATEWAY attribute: %m");
                } else {
                        RouteVia rtvia = {
                                .family = route->gw_family,
                                .address = route->gw,
                        };

                        r = sd_netlink_message_append_data(req, RTA_VIA, &rtvia, sizeof(rtvia));
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not append RTA_VIA attribute: %m");
                }
        }

        if (route->dst_prefixlen > 0) {
                r = netlink_message_append_in_addr_union(req, RTA_DST, route->family, &route->dst);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTA_DST attribute: %m");

                r = sd_rtnl_message_route_set_dst_prefixlen(req, route->dst_prefixlen);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set destination prefix length: %m");
        }

        if (route->src_prefixlen > 0) {
                r = netlink_message_append_in_addr_union(req, RTA_SRC, route->family, &route->src);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTA_SRC attribute: %m");

                r = sd_rtnl_message_route_set_src_prefixlen(req, route->src_prefixlen);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set source prefix length: %m");
        }

        if (in_addr_is_set(route->family, &route->prefsrc)) {
                r = netlink_message_append_in_addr_union(req, RTA_PREFSRC, route->family, &route->prefsrc);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTA_PREFSRC attribute: %m");
        }

        r = sd_rtnl_message_route_set_scope(req, route->scope);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set scope: %m");

        flags = route->flags;
        if (route->gateway_onlink >= 0)
                SET_FLAG(flags, RTNH_F_ONLINK, route->gateway_onlink);

        r = sd_rtnl_message_route_set_flags(req, flags);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set flags: %m");

        if (route->table != RT_TABLE_MAIN) {
                if (route->table < 256) {
                        r = sd_rtnl_message_route_set_table(req, route->table);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not set route table: %m");
                } else {
                        r = sd_rtnl_message_route_set_table(req, RT_TABLE_UNSPEC);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not set route table: %m");

                        /* Table attribute to allow more than 256. */
                        r = sd_netlink_message_append_data(req, RTA_TABLE, &route->table, sizeof(route->table));
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not append RTA_TABLE attribute: %m");
                }
        }

        r = sd_rtnl_message_route_set_type(req, route->type);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set route type: %m");

        if (!route_type_is_reject(route) && route->nexthop_id == 0) {
                assert(link); /* Those routes must be attached to a specific link */

                r = sd_netlink_message_append_u32(req, RTA_OIF, link->ifindex);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTA_OIF attribute: %m");
        }

        if (route->nexthop_id > 0) {
                r = sd_netlink_message_append_u32(req, RTA_NH_ID, route->nexthop_id);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTA_NH_ID attribute: %m");
        }

        r = sd_netlink_message_append_u8(req, RTA_PREF, route->pref);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append RTA_PREF attribute: %m");

        r = sd_netlink_message_append_u32(req, RTA_PRIORITY, route->priority);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append RTA_PRIORITY attribute: %m");

        return 0;
}

static int route_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);

        /* Note that link may be NULL. */
        if (link && IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -ESRCH)
                log_link_message_warning_errno(link, m, r, "Could not drop route, ignoring");

        return 1;
}

int route_remove(
                const Route *route,
                Manager *manager,
                Link *link,
                link_netlink_message_handler_t callback) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link || manager);
        assert(IN_SET(route->family, AF_INET, AF_INET6));

        if (!manager)
                manager = link->manager;
        /* link may be NULL! */

        log_route_debug(route, "Removing", link, manager);

        r = sd_rtnl_message_new_route(manager->rtnl, &req,
                                      RTM_DELROUTE, route->family,
                                      route->protocol);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create RTM_DELROUTE message: %m");

        r = route_set_netlink_message(route, req, link);
        if (r < 0)
                return r;

        r = netlink_call_async(manager->rtnl, NULL, req,
                               callback ?: route_remove_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link); /* link may be NULL, link_ref() is OK with that */

        return 0;
}

static bool link_has_route(const Link *link, const Route *route) {
        Route *net_route;

        assert(link);
        assert(route);

        if (!link->network)
                return false;

        HASHMAP_FOREACH(net_route, link->network->routes_by_section)
                if (route_equal(net_route, route))
                        return true;

        return false;
}

static bool links_have_route(const Manager *manager, const Route *route, const Link *except) {
        Link *link;

        assert(manager);

        HASHMAP_FOREACH(link, manager->links) {
                if (link == except)
                        continue;

                if (link_has_route(link, route))
                        return true;
        }

        return false;
}

static int manager_drop_routes_internal(Manager *manager, bool foreign, const Link *except) {
        Route *route;
        int k, r = 0;
        Set *routes;

        assert(manager);

        routes = foreign ? manager->routes_foreign : manager->routes;
        SET_FOREACH(route, routes) {
                /* Do not touch routes managed by the kernel. */
                if (route->protocol == RTPROT_KERNEL)
                        continue;

                /* The route will be configured later, or already configured by a link. */
                if (links_have_route(manager, route, except))
                        continue;

                /* The existing links do not have the route. Let's drop this now. It may be
                 * re-configured later. */
                k = route_remove(route, manager, NULL, NULL);
                if (k < 0 && r >= 0)
                        r = k;
        }

        return r;
}

static int manager_drop_foreign_routes(Manager *manager) {
        return manager_drop_routes_internal(manager, true, NULL);
}

static int manager_drop_routes(Manager *manager, const Link *except) {
        return manager_drop_routes_internal(manager, false, except);
}

int link_drop_foreign_routes(Link *link) {
        Route *route;
        int k, r = 0;

        assert(link);
        assert(link->manager);

        SET_FOREACH(route, link->routes_foreign) {
                /* do not touch routes managed by the kernel */
                if (route->protocol == RTPROT_KERNEL)
                        continue;

                /* do not touch multicast route added by kernel */
                /* FIXME: Why the kernel adds this route with protocol RTPROT_BOOT??? We need to investigate that.
                 * https://tools.ietf.org/html/rfc4862#section-5.4 may explain why. */
                if (route->protocol == RTPROT_BOOT &&
                    route->family == AF_INET6 &&
                    route->dst_prefixlen == 8 &&
                    in_addr_equal(AF_INET6, &route->dst, &(union in_addr_union) { .in6 = {{{ 0xff,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 }}} }))
                        continue;

                if (route->protocol == RTPROT_STATIC && link->network &&
                    FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_STATIC))
                        continue;

                if (route->protocol == RTPROT_DHCP && link->network &&
                    FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP))
                        continue;

                if (link_has_route(link, route))
                        k = route_add(NULL, link, route, NULL, NULL, NULL);
                else
                        k = route_remove(route, NULL, link, NULL);
                if (k < 0 && r >= 0)
                        r = k;
        }

        k = manager_drop_foreign_routes(link->manager);
        if (k < 0 && r >= 0)
                r = k;

        return r;
}

int link_drop_routes(Link *link) {
        Route *route;
        int k, r = 0;

        assert(link);

        SET_FOREACH(route, link->routes) {
                /* do not touch routes managed by the kernel */
                if (route->protocol == RTPROT_KERNEL)
                        continue;

                k = route_remove(route, NULL, link, NULL);
                if (k < 0 && r >= 0)
                        r = k;
        }

        k = manager_drop_routes(link->manager, link);
        if (k < 0 && r >= 0)
                r = k;

        return r;
}

static int route_expire_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        Route *route = userdata;
        int r;

        assert(route);

        r = route_remove(route, route->manager, route->link, NULL);
        if (r < 0) {
                log_link_warning_errno(route->link, r, "Could not remove route: %m");
                route_free(route);
        }

        return 1;
}

static int route_add_and_setup_timer(Link *link, const Route *route, const MultipathRoute *m, Route **ret) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *expire = NULL;
        NextHop *nh = NULL;
        Route *nr;
        int r, k;

        assert(link);
        assert(link->manager);
        assert(route);

        (void) manager_get_nexthop_by_id(link->manager, route->nexthop_id, &nh);

        if (route_type_is_reject(route) || (nh && nh->blackhole))
                k = route_add(link->manager, NULL, route, NULL, nh, &nr);
        else if (!m || m->ifindex == 0 || m->ifindex == link->ifindex)
                k = route_add(NULL, link, route, m, nh, &nr);
        else {
                Link *link_gw;

                r = link_get(link->manager, m->ifindex, &link_gw);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to get link with ifindex %d: %m", m->ifindex);

                k = route_add(NULL, link_gw, route, m, NULL, &nr);
        }
        if (k < 0)
                return log_link_error_errno(link, k, "Could not add route: %m");

        /* TODO: drop expiration handling once it can be pushed into the kernel */
        if (nr->lifetime != USEC_INFINITY && !kernel_route_expiration_supported()) {
                r = sd_event_add_time(link->manager->event, &expire, clock_boottime_or_monotonic(),
                                      nr->lifetime, 0, route_expire_handler, nr);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not arm expiration timer: %m");
        }

        sd_event_source_unref(nr->expire);
        nr->expire = TAKE_PTR(expire);

        if (ret)
                *ret = nr;

        return k;
}

static int append_nexthop_one(const Route *route, const MultipathRoute *m, struct rtattr **rta, size_t offset) {
        struct rtnexthop *rtnh;
        struct rtattr *new_rta;
        int r;

        assert(route);
        assert(m);
        assert(rta);
        assert(*rta);

        new_rta = realloc(*rta, RTA_ALIGN((*rta)->rta_len) + RTA_SPACE(sizeof(struct rtnexthop)));
        if (!new_rta)
                return -ENOMEM;
        *rta = new_rta;

        rtnh = (struct rtnexthop *)((uint8_t *) *rta + offset);
        *rtnh = (struct rtnexthop) {
                .rtnh_len = sizeof(*rtnh),
                .rtnh_ifindex = m->ifindex,
                .rtnh_hops = m->weight > 0 ? m->weight - 1 : 0,
        };

        (*rta)->rta_len += sizeof(struct rtnexthop);

        if (route->family == m->gateway.family) {
                r = rtattr_append_attribute(rta, RTA_GATEWAY, &m->gateway.address, FAMILY_ADDRESS_SIZE(m->gateway.family));
                if (r < 0)
                        goto clear;
                rtnh = (struct rtnexthop *)((uint8_t *) *rta + offset);
                rtnh->rtnh_len += RTA_SPACE(FAMILY_ADDRESS_SIZE(m->gateway.family));
        } else {
                r = rtattr_append_attribute(rta, RTA_VIA, &m->gateway, FAMILY_ADDRESS_SIZE(m->gateway.family) + sizeof(m->gateway.family));
                if (r < 0)
                        goto clear;
                rtnh = (struct rtnexthop *)((uint8_t *) *rta + offset);
                rtnh->rtnh_len += RTA_SPACE(FAMILY_ADDRESS_SIZE(m->gateway.family) + sizeof(m->gateway.family));
        }

        return 0;

clear:
        (*rta)->rta_len -= sizeof(struct rtnexthop);
        return r;
}

static int append_nexthops(const Route *route, sd_netlink_message *req) {
        _cleanup_free_ struct rtattr *rta = NULL;
        struct rtnexthop *rtnh;
        MultipathRoute *m;
        size_t offset;
        int r;

        if (ordered_set_isempty(route->multipath_routes))
                return 0;

        rta = new(struct rtattr, 1);
        if (!rta)
                return -ENOMEM;

        *rta = (struct rtattr) {
                .rta_type = RTA_MULTIPATH,
                .rta_len = RTA_LENGTH(0),
        };
        offset = (uint8_t *) RTA_DATA(rta) - (uint8_t *) rta;

        ORDERED_SET_FOREACH(m, route->multipath_routes) {
                r = append_nexthop_one(route, m, &rta, offset);
                if (r < 0)
                        return r;

                rtnh = (struct rtnexthop *)((uint8_t *) rta + offset);
                offset = (uint8_t *) RTNH_NEXT(rtnh) - (uint8_t *) rta;
        }

        r = sd_netlink_message_append_data(req, RTA_MULTIPATH, RTA_DATA(rta), RTA_PAYLOAD(rta));
        if (r < 0)
                return r;

        return 0;
}

int route_configure(
                const Route *route,
                Link *link,
                link_netlink_message_handler_t callback,
                Route **ret) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r, k = 0;
        Route *nr;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(IN_SET(route->family, AF_INET, AF_INET6));
        assert(callback);

        if (route_get(link->manager, link, route, NULL) <= 0 &&
            set_size(link->routes) >= routes_max())
                return log_link_error_errno(link, SYNTHETIC_ERRNO(E2BIG),
                                            "Too many routes are configured, refusing: %m");

        log_route_debug(route, "Configuring", link, link->manager);

        r = sd_rtnl_message_new_route(link->manager->rtnl, &req,
                                      RTM_NEWROUTE, route->family,
                                      route->protocol);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create RTM_NEWROUTE message: %m");

        r = route_set_netlink_message(route, req, link);
        if (r < 0)
                return r;

        if (route->lifetime != USEC_INFINITY && kernel_route_expiration_supported()) {
                r = sd_netlink_message_append_u32(req, RTA_EXPIRES,
                        DIV_ROUND_UP(usec_sub_unsigned(route->lifetime, now(clock_boottime_or_monotonic())), USEC_PER_SEC));
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTA_EXPIRES attribute: %m");
        }

        if (route->ttl_propagate >= 0) {
                r = sd_netlink_message_append_u8(req, RTA_TTL_PROPAGATE, route->ttl_propagate);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTA_TTL_PROPAGATE attribute: %m");
        }

        r = sd_netlink_message_open_container(req, RTA_METRICS);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append RTA_METRICS attribute: %m");

        if (route->mtu > 0) {
                r = sd_netlink_message_append_u32(req, RTAX_MTU, route->mtu);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTAX_MTU attribute: %m");
        }

        if (route->initcwnd > 0) {
                r = sd_netlink_message_append_u32(req, RTAX_INITCWND, route->initcwnd);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTAX_INITCWND attribute: %m");
        }

        if (route->initrwnd > 0) {
                r = sd_netlink_message_append_u32(req, RTAX_INITRWND, route->initrwnd);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTAX_INITRWND attribute: %m");
        }

        if (route->quickack >= 0) {
                r = sd_netlink_message_append_u32(req, RTAX_QUICKACK, route->quickack);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTAX_QUICKACK attribute: %m");
        }

        if (route->fast_open_no_cookie >= 0) {
                r = sd_netlink_message_append_u32(req, RTAX_FASTOPEN_NO_COOKIE, route->fast_open_no_cookie);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTAX_FASTOPEN_NO_COOKIE attribute: %m");
        }

        if (route->advmss > 0) {
                r = sd_netlink_message_append_u32(req, RTAX_ADVMSS, route->advmss);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTAX_ADVMSS attribute: %m");
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append RTA_METRICS attribute: %m");

        r = append_nexthops(route, req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append RTA_MULTIPATH attribute: %m");

        if (ordered_set_isempty(route->multipath_routes)) {
                k = route_add_and_setup_timer(link, route, NULL, &nr);
                if (k < 0)
                        return k;
        } else {
                MultipathRoute *m;

                assert(!ret);

                ORDERED_SET_FOREACH(m, route->multipath_routes) {
                        r = route_add_and_setup_timer(link, route, m, NULL);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                k = 1;
                }
        }

        r = netlink_call_async(link->manager->rtnl, NULL, req, callback,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        if (ret)
                *ret = nr;

        return k;
}

static int route_handler_with_gateway(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->route_messages > 0);

        link->route_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not set route with gateway");
                link_enter_failed(link);
                return 1;
        }

        if (link->route_messages == 0) {
                log_link_debug(link, "Routes with gateway set");
                link->static_routes_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int route_handler_without_gateway(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->route_messages > 0);

        link->route_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not set route without gateway");
                link_enter_failed(link);
                return 1;
        }

        if (link->route_messages == 0) {
                log_link_debug(link, "Routes set without gateway");
                /* Now, we can talk to gateways, let's configure nexthops. */
                r = link_set_nexthops(link);
                if (r < 0)
                        link_enter_failed(link);
        }

        return 1;
}

static bool route_has_gateway(const Route *route) {
        assert(route);

        if (in_addr_is_set(route->gw_family, &route->gw))
                return true;

        if (!ordered_set_isempty(route->multipath_routes))
                return true;

        if (route->nexthop_id > 0)
                return true;

        return false;
}

static int link_set_routes_internal(Link *link, bool with_gateway) {
        Route *rt;
        int r;

        assert(link);
        assert(link->network);

        HASHMAP_FOREACH(rt, link->network->routes_by_section) {
                if (rt->gateway_from_dhcp_or_ra)
                        continue;

                if (route_has_gateway(rt) != with_gateway)
                        continue;

                r = route_configure(rt, link, with_gateway ? route_handler_with_gateway : route_handler_without_gateway, NULL);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not set routes: %m");

                link->route_messages++;
        }

        return 0;
}

int link_set_routes_with_gateway(Link *link) {
        int r;

        assert(link);
        assert(link->network);

        if (!link_has_carrier(link) && !link->network->configure_without_carrier)
                /* During configuring addresses, the link lost its carrier. As networkd is dropping
                 * the addresses now, let's not configure the routes either. */
                return 0;

        /* Finally, add routes that needs a gateway. */
        r = link_set_routes_internal(link, true);
        if (r < 0)
                return r;

        if (link->route_messages == 0) {
                link->static_routes_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Setting routes with gateway");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

int link_set_routes(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->state != _LINK_STATE_INVALID);

        link->static_routes_configured = false;

        if (!link->addresses_ready)
                return 0;

        if (!link_has_carrier(link) && !link->network->configure_without_carrier)
                /* During configuring addresses, the link lost its carrier. As networkd is dropping
                 * the addresses now, let's not configure the routes either. */
                return 0;

        if (link->route_messages != 0) {
                log_link_debug(link, "Static routes are configuring.");
                return 0;
        }

        r = link_set_routing_policy_rules(link);
        if (r < 0)
                return r;

        /* First, add the routes that enable us to talk to gateways. */
        r = link_set_routes_internal(link, false);
        if (r < 0)
                return r;

        if (link->route_messages == 0)
                /* If no route is configured, then configure nexthops. */
                return link_set_nexthops(link);

        log_link_debug(link, "Setting routes without gateway");
        link_set_state(link, LINK_STATE_CONFIGURING);

        return 0;
}

static int process_route_one(Manager *manager, Link *link, uint16_t type, const Route *tmp, const MultipathRoute *m) {
        _cleanup_(route_freep) Route *nr = NULL;
        Route *route = NULL;
        NextHop *nh = NULL;
        int r;

        assert(manager);
        assert(tmp);
        assert(IN_SET(type, RTM_NEWROUTE, RTM_DELROUTE));

        (void) manager_get_nexthop_by_id(manager, tmp->nexthop_id, &nh);

        if (nh) {
                if (link && link != nh->link)
                        return log_link_warning_errno(link, SYNTHETIC_ERRNO(EINVAL),
                                                      "rtnl: received RTA_OIF and ifindex of nexthop corresponding to RTA_NH_ID do not match, ignoring.");

                link = nh->link;

                r = route_new(&nr);
                if (r < 0)
                        return log_oom();

                route_copy(nr, tmp, NULL, nh);

                tmp = nr;
        } else if (m) {
                if (link)
                        return log_link_warning_errno(link, SYNTHETIC_ERRNO(EINVAL),
                                                "rtnl: received route contains both RTA_OIF and RTA_MULTIPATH, ignoring.");

                if (m->ifindex <= 0)
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "rtnl: received multipath route with invalid ifindex, ignoring.");

                r = link_get(manager, m->ifindex, &link);
                if (r < 0) {
                        log_warning_errno(r, "rtnl: received multipath route for link (%d) we do not know, ignoring: %m", m->ifindex);
                        return 0;
                }

                r = route_new(&nr);
                if (r < 0)
                        return log_oom();

                route_copy(nr, tmp, m, NULL);

                tmp = nr;
        }

        (void) route_get(manager, link, tmp, &route);

        switch (type) {
        case RTM_NEWROUTE:
                if (!route) {
                        if (!manager->manage_foreign_routes)
                                log_route_debug(tmp, "Ignoring received foreign", link, manager);
                        else {
                                /* A route appeared that we did not request */
                                log_route_debug(tmp, "Remembering foreign", link, manager);
                                r = route_add_foreign(manager, link, tmp, NULL);
                                if (r < 0) {
                                        log_link_warning_errno(link, r, "Failed to remember foreign route, ignoring: %m");
                                        return 0;
                                }
                        }
                } else
                        log_route_debug(tmp, "Received remembered", link, manager);

                break;

        case RTM_DELROUTE:
                log_route_debug(tmp,
                                route ? "Forgetting" :
                                manager->manage_foreign_routes ? "Kernel removed unknown" : "Ignoring received foreign",
                                link, manager);
                route_free(route);
                break;

        default:
                assert_not_reached("Received route message with invalid RTNL message type");
        }

        return 1;
}

int manager_rtnl_process_route(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        _cleanup_ordered_set_free_free_ OrderedSet *multipath_routes = NULL;
        _cleanup_(route_freep) Route *tmp = NULL;
        _cleanup_free_ void *rta_multipath = NULL;
        Link *link = NULL;
        uint32_t ifindex;
        uint16_t type;
        unsigned char table;
        size_t rta_len;
        int r;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_message_warning_errno(message, r, "rtnl: failed to receive route message, ignoring");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWROUTE, RTM_DELROUTE)) {
                log_warning("rtnl: received unexpected message type %u when processing route, ignoring.", type);
                return 0;
        }

        r = sd_netlink_message_read_u32(message, RTA_OIF, &ifindex);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get ifindex from route message, ignoring: %m");
                return 0;
        } else if (r >= 0) {
                if (ifindex <= 0) {
                        log_warning("rtnl: received route message with invalid ifindex %d, ignoring.", ifindex);
                        return 0;
                }

                r = link_get(m, ifindex, &link);
                if (r < 0 || !link) {
                        /* when enumerating we might be out of sync, but we will
                         * get the route again, so just ignore it */
                        if (!m->enumerating)
                                log_warning("rtnl: received route message for link (%d) we do not know about, ignoring", ifindex);
                        return 0;
                }
        }

        r = route_new(&tmp);
        if (r < 0)
                return log_oom();

        r = sd_rtnl_message_route_get_family(message, &tmp->family);
        if (r < 0) {
                log_link_warning(link, "rtnl: received route message without family, ignoring");
                return 0;
        } else if (!IN_SET(tmp->family, AF_INET, AF_INET6)) {
                log_link_debug(link, "rtnl: received route message with invalid family '%i', ignoring", tmp->family);
                return 0;
        }

        r = sd_rtnl_message_route_get_protocol(message, &tmp->protocol);
        if (r < 0) {
                log_warning_errno(r, "rtnl: received route message without route protocol: %m");
                return 0;
        }

        r = netlink_message_read_in_addr_union(message, RTA_DST, tmp->family, &tmp->dst);
        if (r < 0 && r != -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: received route message without valid destination, ignoring: %m");
                return 0;
        }

        r = netlink_message_read_in_addr_union(message, RTA_GATEWAY, tmp->family, &tmp->gw);
        if (r < 0 && r != -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: received route message without valid gateway, ignoring: %m");
                return 0;
        } else if (r >= 0)
                tmp->gw_family = tmp->family;
        else if (tmp->family == AF_INET) {
                RouteVia via;

                r = sd_netlink_message_read(message, RTA_VIA, sizeof(via), &via);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid gateway, ignoring: %m");
                        return 0;
                } else if (r >= 0) {
                        tmp->gw_family = via.family;
                        tmp->gw = via.address;
                }
        }

        r = netlink_message_read_in_addr_union(message, RTA_SRC, tmp->family, &tmp->src);
        if (r < 0 && r != -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: received route message without valid source, ignoring: %m");
                return 0;
        }

        r = netlink_message_read_in_addr_union(message, RTA_PREFSRC, tmp->family, &tmp->prefsrc);
        if (r < 0 && r != -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: received route message without valid preferred source, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_dst_prefixlen(message, &tmp->dst_prefixlen);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route message with invalid destination prefixlen, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_src_prefixlen(message, &tmp->src_prefixlen);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route message with invalid source prefixlen, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_scope(message, &tmp->scope);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route message with invalid scope, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_tos(message, &tmp->tos);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route message with invalid tos, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_type(message, &tmp->type);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route message with invalid type, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_table(message, &table);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route message with invalid table, ignoring: %m");
                return 0;
        }
        tmp->table = table;

        r = sd_netlink_message_read_u32(message, RTA_PRIORITY, &tmp->priority);
        if (r < 0 && r != -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: received route message with invalid priority, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_u32(message, RTA_NH_ID, &tmp->nexthop_id);
        if (r < 0 && r != -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: received route message with invalid nexthop id, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_enter_container(message, RTA_METRICS);
        if (r < 0 && r != -ENODATA) {
                log_link_error_errno(link, r, "rtnl: Could not enter RTA_METRICS container: %m");
                return 0;
        }
        if (r >= 0) {
                r = sd_netlink_message_read_u32(message, RTAX_INITCWND, &tmp->initcwnd);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message with invalid initcwnd, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_u32(message, RTAX_INITRWND, &tmp->initrwnd);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message with invalid initrwnd, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_u32(message, RTAX_ADVMSS, &tmp->advmss);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message with invalid advmss, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_exit_container(message);
                if (r < 0) {
                        log_link_error_errno(link, r, "rtnl: Could not exit from RTA_METRICS container: %m");
                        return 0;
                }
        }

        r = sd_netlink_message_read_data(message, RTA_MULTIPATH, &rta_len, &rta_multipath);
        if (r < 0 && r != -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: failed to read RTA_MULTIPATH attribute, ignoring: %m");
                return 0;
        } else if (r >= 0) {
                r = rtattr_read_nexthop(rta_multipath, rta_len, tmp->family, &multipath_routes);
                if (r < 0) {
                        log_link_warning_errno(link, r, "rtnl: failed to parse RTA_MULTIPATH attribute, ignoring: %m");
                        return 0;
                }
        }

        /* IPv6 routes with reject type are always assigned to the loopback interface. See kernel's
         * fib6_nh_init() in net/ipv6/route.c. However, we'd like to manage them by Manager. Hence, set
         * link to NULL here. */
        if (route_type_is_reject(tmp))
                link = NULL;

        if (ordered_set_isempty(multipath_routes))
                (void) process_route_one(m, link, type, tmp, NULL);
        else {
                MultipathRoute *mr;

                ORDERED_SET_FOREACH(mr, multipath_routes) {
                        r = process_route_one(m, link, type, tmp, mr);
                        if (r < 0)
                                break;
                }
        }

        return 1;
}

int network_add_ipv4ll_route(Network *network) {
        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        unsigned section_line;
        int r;

        assert(network);

        if (!network->ipv4ll_route)
                return 0;

        section_line = hashmap_find_free_section_line(network->routes_by_section);

        /* IPv4LLRoute= is in [Network] section. */
        r = route_new_static(network, network->filename, section_line, &n);
        if (r < 0)
                return r;

        r = in_addr_from_string(AF_INET, "169.254.0.0", &n->dst);
        if (r < 0)
                return r;

        n->family = AF_INET;
        n->dst_prefixlen = 16;
        n->scope = RT_SCOPE_LINK;
        n->scope_set = true;
        n->table_set = true;
        n->priority = IPV4LL_ROUTE_METRIC;
        n->protocol = RTPROT_STATIC;

        TAKE_PTR(n);
        return 0;
}

int network_add_default_route_on_device(Network *network) {
        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        unsigned section_line;
        int r;

        assert(network);

        if (!network->default_route_on_device)
                return 0;

        section_line = hashmap_find_free_section_line(network->routes_by_section);

        /* DefaultRouteOnDevice= is in [Network] section. */
        r = route_new_static(network, network->filename, section_line, &n);
        if (r < 0)
                return r;

        n->family = AF_INET;
        n->scope = RT_SCOPE_LINK;
        n->scope_set = true;
        n->protocol = RTPROT_STATIC;

        TAKE_PTR(n);
        return 0;
}

int config_parse_gateway(
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

        Network *network = userdata;
        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(section, "Network")) {
                /* we are not in an Route section, so use line number instead */
                r = route_new_static(network, filename, line, &n);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to allocate route, ignoring assignment: %m");
                        return 0;
                }
        } else {
                r = route_new_static(network, filename, section_line, &n);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to allocate route, ignoring assignment: %m");
                        return 0;
                }

                if (isempty(rvalue)) {
                        n->gateway_from_dhcp_or_ra = false;
                        n->gw_family = AF_UNSPEC;
                        n->gw = IN_ADDR_NULL;
                        TAKE_PTR(n);
                        return 0;
                }

                if (streq(rvalue, "_dhcp")) {
                        n->gateway_from_dhcp_or_ra = true;
                        TAKE_PTR(n);
                        return 0;
                }

                if (streq(rvalue, "_dhcp4")) {
                        n->gw_family = AF_INET;
                        n->gateway_from_dhcp_or_ra = true;
                        TAKE_PTR(n);
                        return 0;
                }

                if (streq(rvalue, "_ipv6ra")) {
                        n->gw_family = AF_INET6;
                        n->gateway_from_dhcp_or_ra = true;
                        TAKE_PTR(n);
                        return 0;
                }
        }

        r = in_addr_from_string_auto(rvalue, &n->gw_family, &n->gw);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid %s='%s', ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        n->gateway_from_dhcp_or_ra = false;
        TAKE_PTR(n);
        return 0;
}

int config_parse_preferred_src(
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

        Network *network = userdata;
        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        if (n->family == AF_UNSPEC)
                r = in_addr_from_string_auto(rvalue, &n->family, &n->prefsrc);
        else
                r = in_addr_from_string(n->family, rvalue, &n->prefsrc);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, EINVAL,
                           "Invalid %s='%s', ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(n);
        return 0;
}

int config_parse_destination(
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

        Network *network = userdata;
        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        union in_addr_union *buffer;
        unsigned char *prefixlen;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        if (streq(lvalue, "Destination")) {
                buffer = &n->dst;
                prefixlen = &n->dst_prefixlen;
        } else if (streq(lvalue, "Source")) {
                buffer = &n->src;
                prefixlen = &n->src_prefixlen;
        } else
                assert_not_reached(lvalue);

        if (n->family == AF_UNSPEC)
                r = in_addr_prefix_from_string_auto(rvalue, &n->family, buffer, prefixlen);
        else
                r = in_addr_prefix_from_string(rvalue, n->family, buffer, prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, EINVAL,
                           "Invalid %s='%s', ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(n);
        return 0;
}

int config_parse_route_priority(
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

        Network *network = userdata;
        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        r = safe_atou32(rvalue, &n->priority);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse route priority \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        n->priority_set = true;
        TAKE_PTR(n);
        return 0;
}

int config_parse_route_scope(
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

        Network *network = userdata;
        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        r = route_scope_from_string(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Unknown route scope: %s", rvalue);
                return 0;
        }

        n->scope = r;
        n->scope_set = true;
        TAKE_PTR(n);
        return 0;
}

int config_parse_route_nexthop(
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

        Network *network = userdata;
        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        uint32_t id;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                n->nexthop_id = 0;
                TAKE_PTR(n);
                return 0;
        }

        r = safe_atou32(rvalue, &id);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse nexthop ID, ignoring assignment: %s", rvalue);
                return 0;
        }
        if (id == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid nexthop ID, ignoring assignment: %s", rvalue);
                return 0;
        }

        n->nexthop_id = id;
        TAKE_PTR(n);
        return 0;
}

int config_parse_route_table(
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

        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        r = manager_get_route_table_from_string(network->manager, rvalue, &n->table);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse route table number \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        n->table_set = true;
        TAKE_PTR(n);
        return 0;
}

int config_parse_route_boolean(
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

        Network *network = userdata;
        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse %s=\"%s\", ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        if (STR_IN_SET(lvalue, "GatewayOnLink", "GatewayOnlink"))
                n->gateway_onlink = r;
        else if (streq(lvalue, "QuickAck"))
                n->quickack = r;
        else if (streq(lvalue, "FastOpenNoCookie"))
                n->fast_open_no_cookie = r;
        else if (streq(lvalue, "TTLPropagate"))
                n->ttl_propagate = r;
        else
                assert_not_reached("Invalid lvalue");

        TAKE_PTR(n);
        return 0;
}

int config_parse_ipv6_route_preference(
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

        Network *network = userdata;
        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        int r;

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        if (streq(rvalue, "low"))
                n->pref = ICMPV6_ROUTER_PREF_LOW;
        else if (streq(rvalue, "medium"))
                n->pref = ICMPV6_ROUTER_PREF_MEDIUM;
        else if (streq(rvalue, "high"))
                n->pref = ICMPV6_ROUTER_PREF_HIGH;
        else {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Unknown route preference: %s", rvalue);
                return 0;
        }

        n->pref_set = true;
        TAKE_PTR(n);
        return 0;
}

int config_parse_route_protocol(
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

        Network *network = userdata;
        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        int r;

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        r = route_protocol_from_string(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse route protocol \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        n->protocol = r;

        TAKE_PTR(n);
        return 0;
}

int config_parse_route_type(
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

        Network *network = userdata;
        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        int t, r;

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        t = route_type_from_string(rvalue);
        if (t < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse route type \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        n->type = (unsigned char) t;

        TAKE_PTR(n);
        return 0;
}

int config_parse_tcp_advmss(
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

        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        Network *network = userdata;
        uint64_t u;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                n->advmss = 0;
                TAKE_PTR(n);
                return 0;
        }

        r = parse_size(rvalue, 1024, &u);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse TCPAdvertisedMaximumSegmentSize= \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        if (u == 0 || u > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid TCPAdvertisedMaximumSegmentSize= \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        n->advmss = u;

        TAKE_PTR(n);
        return 0;
}

int config_parse_tcp_window(
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

        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        Network *network = userdata;
        uint32_t k;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse TCP %s \"%s\", ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }
        if (k >= 1024) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified TCP %s \"%s\" is too large, ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }
        if (k == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid TCP %s \"%s\", ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        if (streq(lvalue, "InitialCongestionWindow"))
                n->initcwnd = k;
        else if (streq(lvalue, "InitialAdvertisedReceiveWindow"))
                n->initrwnd = k;
        else
                assert_not_reached("Invalid TCP window type.");

        TAKE_PTR(n);
        return 0;
}

int config_parse_route_mtu(
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

        Network *network = userdata;
        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        r = config_parse_mtu(unit, filename, line, section, section_line, lvalue, ltype, rvalue, &n->mtu, userdata);
        if (r < 0)
                return r;

        TAKE_PTR(n);
        return 0;
}

int config_parse_multipath_route(
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

        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        _cleanup_free_ char *word = NULL, *buf = NULL;
        _cleanup_free_ MultipathRoute *m = NULL;
        Network *network = userdata;
        const char *p, *ip, *dev;
        union in_addr_union a;
        int family, r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                n->multipath_routes = ordered_set_free_free(n->multipath_routes);
                return 0;
        }

        m = new0(MultipathRoute, 1);
        if (!m)
                return log_oom();

        p = rvalue;
        r = extract_first_word(&p, &word, NULL, 0);
        if (r == -ENOMEM)
                return log_oom();
        if (r <= 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid multipath route option, ignoring assignment: %s", rvalue);
                return 0;
        }

        dev = strchr(word, '@');
        if (dev) {
                buf = strndup(word, dev - word);
                if (!buf)
                        return log_oom();
                ip = buf;
                dev++;
        } else
                ip = word;

        r = in_addr_from_string_auto(ip, &family, &a);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid multipath route gateway '%s', ignoring assignment: %m", rvalue);
                return 0;
        }
        m->gateway.address = a;
        m->gateway.family = family;

        if (dev) {
                r = resolve_interface(NULL, dev);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid interface name or index, ignoring assignment: %s", dev);
                        return 0;
                }
                m->ifindex = r;
        }

        if (!isempty(p)) {
                r = safe_atou32(p, &m->weight);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid multipath route weight, ignoring assignment: %s", p);
                        return 0;
                }
                if (m->weight == 0 || m->weight > 256) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid multipath route weight, ignoring assignment: %s", p);
                        return 0;
                }
        }

        r = ordered_set_ensure_put(&n->multipath_routes, NULL, m);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to store multipath route, ignoring assignment: %m");
                return 0;
        }

        TAKE_PTR(m);
        TAKE_PTR(n);
        return 0;
}

int config_parse_route_table_names(
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

        Manager *m = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(userdata);

        if (isempty(rvalue)) {
                m->route_table_names_by_number = hashmap_free(m->route_table_names_by_number);
                m->route_table_numbers_by_name = hashmap_free(m->route_table_numbers_by_name);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *name = NULL;
                uint32_t table;
                char *num;

                r = extract_first_word(&p, &name, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid RouteTable=, ignoring assignment: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                num = strchr(name, ':');
                if (!num) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid route table name and number pair, ignoring assignment: %s", name);
                        continue;
                }

                *num++ = '\0';

                if (STR_IN_SET(name, "default", "main", "local")) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Route table name %s already predefined. Ignoring assignment: %s:%s", name, name, num);
                        continue;
                }

                r = safe_atou32(num, &table);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse route table number '%s', ignoring assignment: %s:%s", num, name, num);
                        continue;
                }
                if (table == 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid route table number, ignoring assignment: %s:%s", name, num);
                        continue;
                }

                r = hashmap_ensure_put(&m->route_table_numbers_by_name, &string_hash_ops_free, name, UINT32_TO_PTR(table));
                if (r == -ENOMEM)
                        return log_oom();
                if (r == -EEXIST) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Specified route table name and number pair conflicts with others, ignoring assignment: %s:%s", name, num);
                        continue;
                }
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to store route table name and number pair, ignoring assignment: %s:%s", name, num);
                        continue;
                }
                if (r == 0)
                        /* The entry is duplicated. It should not be added to route_table_names_by_number hashmap. */
                        continue;

                r = hashmap_ensure_put(&m->route_table_names_by_number, NULL, UINT32_TO_PTR(table), name);
                if (r < 0) {
                        hashmap_remove(m->route_table_numbers_by_name, name);

                        if (r == -ENOMEM)
                                return log_oom();
                        if (r == -EEXIST)
                                log_syntax(unit, LOG_WARNING, filename, line, r,
                                           "Specified route table name and number pair conflicts with others, ignoring assignment: %s:%s", name, num);
                        else
                                log_syntax(unit, LOG_WARNING, filename, line, r,
                                           "Failed to store route table name and number pair, ignoring assignment: %s:%s", name, num);
                        continue;
                }
                assert(r > 0);

                TAKE_PTR(name);
        }
}

static int route_section_verify(Route *route, Network *network) {
        if (section_is_invalid(route->section))
                return -EINVAL;

        if (route->gateway_from_dhcp_or_ra) {
                if (route->gw_family == AF_UNSPEC) {
                        /* When deprecated Gateway=_dhcp is set, then assume gateway family based on other settings. */
                        switch (route->family) {
                        case AF_UNSPEC:
                                log_warning("%s: Deprecated value \"_dhcp\" is specified for Gateway= in [Route] section from line %u. "
                                            "Please use \"_dhcp4\" or \"_ipv6ra\" instead. Assuming \"_dhcp4\".",
                                            route->section->filename, route->section->line);
                                route->family = AF_INET;
                                break;
                        case AF_INET:
                        case AF_INET6:
                                log_warning("%s: Deprecated value \"_dhcp\" is specified for Gateway= in [Route] section from line %u. "
                                            "Assuming \"%s\" based on Destination=, Source=, or PreferredSource= setting.",
                                            route->section->filename, route->section->line, route->family == AF_INET ? "_dhcp4" : "_ipv6ra");
                                break;
                        default:
                                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                         "%s: Invalid route family. Ignoring [Route] section from line %u.",
                                                         route->section->filename, route->section->line);
                        }
                        route->gw_family = route->family;
                }

                if (route->gw_family == AF_INET && !FLAGS_SET(network->dhcp, ADDRESS_FAMILY_IPV4))
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: Gateway=\"_dhcp4\" is specified but DHCPv4 client is disabled. "
                                                 "Ignoring [Route] section from line %u.",
                                                 route->section->filename, route->section->line);

                if (route->gw_family == AF_INET6 && !network->ipv6_accept_ra)
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: Gateway=\"_ipv6ra\" is specified but IPv6AcceptRA= is disabled. "
                                                 "Ignoring [Route] section from line %u.",
                                                 route->section->filename, route->section->line);
        }

        /* When only Gateway= is specified, assume the route family based on the Gateway address. */
        if (route->family == AF_UNSPEC)
                route->family = route->gw_family;

        if (route->family == AF_UNSPEC) {
                assert(route->section);

                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Route section without Gateway=, Destination=, Source=, "
                                         "or PreferredSource= field configured. "
                                         "Ignoring [Route] section from line %u.",
                                         route->section->filename, route->section->line);
        }

        if (route->family == AF_INET6 && route->gw_family == AF_INET)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: IPv4 gateway is configured for IPv6 route. "
                                         "Ignoring [Route] section from line %u.",
                                         route->section->filename, route->section->line);

        if (!route->table_set && network->vrf) {
                route->table = VRF(network->vrf)->table;
                route->table_set = true;
        }

        if (!route->table_set && IN_SET(route->type, RTN_LOCAL, RTN_BROADCAST, RTN_ANYCAST, RTN_NAT))
                route->table = RT_TABLE_LOCAL;

        if (!route->scope_set && route->family != AF_INET6) {
                if (IN_SET(route->type, RTN_LOCAL, RTN_NAT))
                        route->scope = RT_SCOPE_HOST;
                else if (IN_SET(route->type, RTN_BROADCAST, RTN_ANYCAST, RTN_MULTICAST))
                        route->scope = RT_SCOPE_LINK;
        }

        if (route->scope != RT_SCOPE_UNIVERSE && route->family == AF_INET6) {
                log_warning("%s: Scope= is specified for IPv6 route. It will be ignored.", route->section->filename);
                route->scope = RT_SCOPE_UNIVERSE;
        }

        if (route->family == AF_INET6 && route->priority == 0)
                route->priority = IP6_RT_PRIO_USER;

        if (route->gateway_onlink < 0 && in_addr_is_set(route->gw_family, &route->gw) &&
            ordered_hashmap_isempty(network->addresses_by_section)) {
                /* If no address is configured, in most cases the gateway cannot be reachable.
                 * TODO: we may need to improve the condition above. */
                log_warning("%s: Gateway= without static address configured. "
                            "Enabling GatewayOnLink= option.",
                            network->filename);
                route->gateway_onlink = true;
        }

        if (route->family == AF_INET6) {
                MultipathRoute *m;

                ORDERED_SET_FOREACH(m, route->multipath_routes)
                        if (m->gateway.family == AF_INET)
                                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                         "%s: IPv4 multipath route is specified for IPv6 route. "
                                                         "Ignoring [Route] section from line %u.",
                                                         route->section->filename, route->section->line);
        }

        if (route->nexthop_id > 0 &&
            (in_addr_is_set(route->gw_family, &route->gw) ||
             !ordered_set_isempty(route->multipath_routes)))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: NextHopId= cannot be specified with Gateway= or MultiPathRoute=. "
                                         "Ignoring [Route] section from line %u.",
                                         route->section->filename, route->section->line);

        return 0;
}

void network_drop_invalid_routes(Network *network) {
        Route *route;

        assert(network);

        HASHMAP_FOREACH(route, network->routes_by_section)
                if (route_section_verify(route, network) < 0)
                        route_free(route);
}
