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

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(route_scope, int);

#define ROUTE_SCOPE_STR_MAX CONST_MAX(DECIMAL_STR_MAX(int), STRLEN("nowhere") + 1)
static const char *format_route_scope(int scope, char *buf, size_t size) {
        const char *s;
        char *p = buf;

        s = route_scope_to_string(scope);
        if (s)
                strpcpy(&p, size, s);
        else
                strpcpyf(&p, size, "%d", scope);

        return buf;
}

static const char * const route_table_table[] = {
        [RT_TABLE_DEFAULT] = "default",
        [RT_TABLE_MAIN]    = "main",
        [RT_TABLE_LOCAL]   = "local",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(route_table, int);

#define ROUTE_TABLE_STR_MAX CONST_MAX(DECIMAL_STR_MAX(int), STRLEN("default") + 1)
static const char *format_route_table(int table, char *buf, size_t size) {
        const char *s;
        char *p = buf;

        s = route_table_to_string(table);
        if (s)
                strpcpy(&p, size, s);
        else
                strpcpyf(&p, size, "%d", table);

        return buf;
}

static const char * const route_protocol_table[] = {
        [RTPROT_KERNEL] = "kernel",
        [RTPROT_BOOT]   = "boot",
        [RTPROT_STATIC] = "static",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(route_protocol, int);

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

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(route_protocol_full, int);

#define ROUTE_PROTOCOL_STR_MAX CONST_MAX(DECIMAL_STR_MAX(int), STRLEN("redirect") + 1)
static const char *format_route_protocol(int protocol, char *buf, size_t size) {
        const char *s;
        char *p = buf;

        s = route_protocol_full_to_string(protocol);
        if (s)
                strpcpy(&p, size, s);
        else
                strpcpyf(&p, size, "%d", protocol);

        return buf;
}

static unsigned routes_max(void) {
        static thread_local unsigned cached = 0;

        _cleanup_free_ char *s4 = NULL, *s6 = NULL;
        unsigned val4 = ROUTES_DEFAULT_MAX_PER_FAMILY, val6 = ROUTES_DEFAULT_MAX_PER_FAMILY;

        if (cached > 0)
                return cached;

        if (sysctl_read("net/ipv4/route/max_size", &s4) >= 0) {
                truncate_nl(s4);
                if (safe_atou(s4, &val4) >= 0 &&
                    val4 == 2147483647U)
                        /* This is the default "no limit" value in the kernel */
                        val4 = ROUTES_DEFAULT_MAX_PER_FAMILY;
        }

        if (sysctl_read("net/ipv6/route/max_size", &s6) >= 0) {
                truncate_nl(s6);
                (void) safe_atou(s6, &val6);
        }

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

        r = hashmap_ensure_allocated(&network->routes_by_section, &network_config_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_put(network->routes_by_section, route->section, route);
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

        if (link) {
                existing = set_get(link->routes, in);
                if (existing) {
                        if (ret)
                                *ret = existing;
                        return 1;
                }

                existing = set_get(link->routes_foreign, in);
                if (existing) {
                        if (ret)
                                *ret = existing;
                        return 0;
                }
        } else {
                existing = set_get(manager->routes, in);
                if (existing) {
                        if (ret)
                                *ret = existing;
                        return 1;
                }

                existing = set_get(manager->routes_foreign, in);
                if (existing) {
                        if (ret)
                                *ret = existing;
                        return 0;
                }
        }

        return -ENOENT;
}

static void route_copy(Route *dest, const Route *src, const MultipathRoute *m) {
        assert(dest);
        assert(src);

        dest->family = src->family;
        dest->src = src->src;
        dest->src_prefixlen = src->src_prefixlen;
        dest->dst = src->dst;
        dest->dst_prefixlen = src->dst_prefixlen;
        dest->prefsrc = src->prefsrc;
        dest->scope = src->scope;
        dest->protocol = src->protocol;
        dest->type = src->type;
        dest->tos = src->tos;
        dest->priority = src->priority;
        dest->table = src->table;
        dest->initcwnd = src->initcwnd;
        dest->initrwnd = src->initrwnd;
        dest->lifetime = src->lifetime;

        if (m) {
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

        route_copy(route, in, NULL);

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

static int route_add(Manager *manager, Link *link, const Route *in, const MultipathRoute *m, Route **ret) {
        _cleanup_(route_freep) Route *tmp = NULL;
        Route *route;
        int r;

        assert(manager || link);
        assert(in);

        if (m) {
                assert(link && (m->ifindex == 0 || m->ifindex == link->ifindex));

                r = route_new(&tmp);
                if (r < 0)
                        return r;

                route_copy(tmp, in, m);
                in = tmp;
        }

        r = route_get(manager, link, in, &route);
        if (r == -ENOENT) {
                /* Route does not exist, create a new one */
                r = route_add_internal(manager, link, link ? &link->routes : &manager->routes, in, &route);
                if (r < 0)
                        return r;
        } else if (r == 0) {
                /* Take over a foreign route */
                if (link) {
                        r = set_ensure_put(&link->routes, &route_hash_ops, route);
                        if (r < 0)
                                return r;

                        set_remove(link->routes_foreign, route);
                } else {
                        r = set_ensure_put(&manager->routes, &route_hash_ops, route);
                        if (r < 0)
                                return r;

                        set_remove(manager->routes_foreign, route);
                }
        } else if (r == 1) {
                /* Route exists, do nothing */
                ;
        } else
                return r;

        if (ret)
                *ret = route;

        return 0;
}

static int route_set_netlink_message(const Route *route, sd_netlink_message *req, Link *link) {
        unsigned flags;
        int r;

        assert(route);
        assert(req);

        /* link may be NULL */

        if (in_addr_is_null(route->gw_family, &route->gw) == 0) {
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

        if (in_addr_is_null(route->family, &route->prefsrc) == 0) {
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

        if (!IN_SET(route->type, RTN_UNREACHABLE, RTN_PROHIBIT, RTN_BLACKHOLE, RTN_THROW)) {
                assert(link); /* Those routes must be attached to a specific link */

                r = sd_netlink_message_append_u32(req, RTA_OIF, link->ifindex);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTA_OIF attribute: %m");
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

        r = sd_rtnl_message_new_route(manager->rtnl, &req,
                                      RTM_DELROUTE, route->family,
                                      route->protocol);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create RTM_DELROUTE message: %m");

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *dst = NULL, *dst_prefixlen = NULL, *src = NULL, *gw = NULL, *prefsrc = NULL;
                char scope[ROUTE_SCOPE_STR_MAX], table[ROUTE_TABLE_STR_MAX], protocol[ROUTE_PROTOCOL_STR_MAX];

                if (!in_addr_is_null(route->family, &route->dst)) {
                        (void) in_addr_to_string(route->family, &route->dst, &dst);
                        (void) asprintf(&dst_prefixlen, "/%u", route->dst_prefixlen);
                }
                if (!in_addr_is_null(route->family, &route->src))
                        (void) in_addr_to_string(route->family, &route->src, &src);
                if (!in_addr_is_null(route->gw_family, &route->gw))
                        (void) in_addr_to_string(route->gw_family, &route->gw, &gw);
                if (!in_addr_is_null(route->family, &route->prefsrc))
                        (void) in_addr_to_string(route->family, &route->prefsrc, &prefsrc);

                log_link_debug(link, "Removing route: dst: %s%s, src: %s, gw: %s, prefsrc: %s, scope: %s, table: %s, proto: %s, type: %s",
                               strna(dst), strempty(dst_prefixlen), strna(src), strna(gw), strna(prefsrc),
                               format_route_scope(route->scope, scope, sizeof(scope)),
                               format_route_table(route->table, table, sizeof(table)),
                               format_route_protocol(route->protocol, protocol, sizeof(protocol)),
                               strna(route_type_to_string(route->type)));
        }

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

static bool links_have_route(Manager *manager, const Route *route, const Link *except) {
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

static int manager_drop_foreign_routes(Manager *manager) {
        Route *route;
        int k, r = 0;

        assert(manager);

        SET_FOREACH(route, manager->routes_foreign) {
                /* do not touch routes managed by the kernel */
                if (route->protocol == RTPROT_KERNEL)
                        continue;

                if (links_have_route(manager, route, NULL))
                        /* The route will be configured later. */
                        continue;

                /* The existing links do not have the route. Let's drop this now. It may by
                 * re-configured later. */
                k = route_remove(route, manager, NULL, NULL);
                if (k < 0 && r >= 0)
                        r = k;
        }

        return r;
}

static int manager_drop_routes(Manager *manager, Link *except) {
        Route *route;
        int k, r = 0;

        assert(manager);

        SET_FOREACH(route, manager->routes) {
                /* do not touch routes managed by the kernel */
                if (route->protocol == RTPROT_KERNEL)
                        continue;

                if (links_have_route(manager, route, except))
                        /* The route will be configured later. */
                        continue;

                /* The existing links do not have the route. Let's drop this now. It may by
                 * re-configured later. */
                k = route_remove(route, manager, NULL, NULL);
                if (k < 0 && r >= 0)
                        r = k;
        }

        return r;
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
                        k = route_add(NULL, link, route, NULL, NULL);
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
        Route *nr;
        int r;

        assert(link);
        assert(route);

        if (IN_SET(route->type, RTN_UNREACHABLE, RTN_PROHIBIT, RTN_BLACKHOLE, RTN_THROW))
                r = route_add(link->manager, NULL, route, NULL, &nr);
        else if (!m || m->ifindex == 0 || m->ifindex == link->ifindex)
                r = route_add(NULL, link, route, m, &nr);
        else {
                Link *link_gw;

                r = link_get(link->manager, m->ifindex, &link_gw);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to get link with ifindex %d: %m", m->ifindex);

                r = route_add(NULL, link_gw, route, m, &nr);
        }
        if (r < 0)
                return log_link_error_errno(link, r, "Could not add route: %m");

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

        return 0;
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
        int r;

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

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *dst = NULL, *dst_prefixlen = NULL, *src = NULL, *gw = NULL, *prefsrc = NULL;
                char scope[ROUTE_SCOPE_STR_MAX], table[ROUTE_TABLE_STR_MAX], protocol[ROUTE_PROTOCOL_STR_MAX];

                if (!in_addr_is_null(route->family, &route->dst)) {
                        (void) in_addr_to_string(route->family, &route->dst, &dst);
                        (void) asprintf(&dst_prefixlen, "/%u", route->dst_prefixlen);
                }
                if (!in_addr_is_null(route->family, &route->src))
                        (void) in_addr_to_string(route->family, &route->src, &src);
                if (!in_addr_is_null(route->gw_family, &route->gw))
                        (void) in_addr_to_string(route->gw_family, &route->gw, &gw);
                if (!in_addr_is_null(route->family, &route->prefsrc))
                        (void) in_addr_to_string(route->family, &route->prefsrc, &prefsrc);

                log_link_debug(link, "Configuring route: dst: %s%s, src: %s, gw: %s, prefsrc: %s, scope: %s, table: %s, proto: %s, type: %s",
                               strna(dst), strempty(dst_prefixlen), strna(src), strna(gw), strna(prefsrc),
                               format_route_scope(route->scope, scope, sizeof(scope)),
                               format_route_table(route->table, table, sizeof(table)),
                               format_route_protocol(route->protocol, protocol, sizeof(protocol)),
                               strna(route_type_to_string(route->type)));
        }

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

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append RTA_METRICS attribute: %m");

        r = append_nexthops(route, req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append RTA_MULTIPATH attribute: %m");

        if (ordered_set_isempty(route->multipath_routes)) {
                Route *nr;

                r = route_add_and_setup_timer(link, route, NULL, &nr);
                if (r < 0)
                        return r;

                if (ret)
                        *ret = nr;
        } else {
                MultipathRoute *m;

                assert(!ret);

                ORDERED_SET_FOREACH(m, route->multipath_routes) {
                        r = route_add_and_setup_timer(link, route, m, NULL);
                        if (r < 0)
                                return r;
                }
        }

        r = netlink_call_async(link->manager->rtnl, NULL, req, callback,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

static int route_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->route_messages > 0);
        assert(IN_SET(link->state, LINK_STATE_CONFIGURING,
                      LINK_STATE_FAILED, LINK_STATE_LINGER));

        link->route_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not set route");
                link_enter_failed(link);
                return 1;
        }

        if (link->route_messages == 0) {
                log_link_debug(link, "Routes set");
                link->static_routes_configured = true;
                link_set_nexthop(link);
        }

        return 1;
}

int link_set_routes(Link *link) {
        enum {
                PHASE_NON_GATEWAY, /* First phase: Routes without a gateway */
                PHASE_GATEWAY,     /* Second phase: Routes with a gateway */
                _PHASE_MAX
        } phase;
        Route *rt;
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

        r = link_set_routing_policy_rules(link);
        if (r < 0)
                return r;

        /* First add the routes that enable us to talk to gateways, then add in the others that need a gateway. */
        for (phase = 0; phase < _PHASE_MAX; phase++)
                HASHMAP_FOREACH(rt, link->network->routes_by_section) {
                        if (rt->gateway_from_dhcp_or_ra)
                                continue;

                        if ((in_addr_is_null(rt->gw_family, &rt->gw) && ordered_set_isempty(rt->multipath_routes)) != (phase == PHASE_NON_GATEWAY))
                                continue;

                        r = route_configure(rt, link, route_handler, NULL);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "Could not set routes: %m");

                        link->route_messages++;
                }

        if (link->route_messages == 0) {
                link->static_routes_configured = true;
                link_set_nexthop(link);
        } else {
                log_link_debug(link, "Setting routes");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

static int process_route_one(Manager *manager, Link *link, uint16_t type, const Route *tmp, const MultipathRoute *m) {
        _cleanup_(route_freep) Route *nr = NULL;
        Route *route = NULL;
        int r;

        assert(manager);
        assert(tmp);
        assert(IN_SET(type, RTM_NEWROUTE, RTM_DELROUTE));

        if (m) {
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

                route_copy(nr, tmp, m);

                tmp = nr;
        }

        (void) route_get(manager, link, tmp, &route);

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *buf_dst = NULL, *buf_dst_prefixlen = NULL,
                        *buf_src = NULL, *buf_gw = NULL, *buf_prefsrc = NULL;
                char buf_scope[ROUTE_SCOPE_STR_MAX], buf_table[ROUTE_TABLE_STR_MAX],
                        buf_protocol[ROUTE_PROTOCOL_STR_MAX];

                if (!in_addr_is_null(tmp->family, &tmp->dst)) {
                        (void) in_addr_to_string(tmp->family, &tmp->dst, &buf_dst);
                        (void) asprintf(&buf_dst_prefixlen, "/%u", tmp->dst_prefixlen);
                }
                if (!in_addr_is_null(tmp->family, &tmp->src))
                        (void) in_addr_to_string(tmp->family, &tmp->src, &buf_src);
                if (!in_addr_is_null(tmp->gw_family, &tmp->gw))
                        (void) in_addr_to_string(tmp->gw_family, &tmp->gw, &buf_gw);
                if (!in_addr_is_null(tmp->family, &tmp->prefsrc))
                        (void) in_addr_to_string(tmp->family, &tmp->prefsrc, &buf_prefsrc);

                log_link_debug(link,
                               "%s route: dst: %s%s, src: %s, gw: %s, prefsrc: %s, scope: %s, table: %s, proto: %s, type: %s",
                               (!route && !manager->manage_foreign_routes) ? "Ignoring received foreign" :
                               type == RTM_DELROUTE ? "Forgetting" :
                               route ? "Received remembered" : "Remembering",
                               strna(buf_dst), strempty(buf_dst_prefixlen),
                               strna(buf_src), strna(buf_gw), strna(buf_prefsrc),
                               format_route_scope(tmp->scope, buf_scope, sizeof buf_scope),
                               format_route_table(tmp->table, buf_table, sizeof buf_table),
                               format_route_protocol(tmp->protocol, buf_protocol, sizeof buf_protocol),
                               strna(route_type_to_string(tmp->type)));
        }

        switch (type) {
        case RTM_NEWROUTE:
                if (!route && manager->manage_foreign_routes) {
                        /* A route appeared that we did not request */
                        r = route_add_foreign(manager, link, tmp, NULL);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Failed to remember foreign route, ignoring: %m");
                                return 0;
                        }
                }

                break;

        case RTM_DELROUTE:
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
        RouteVia via;
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

        switch (tmp->family) {
        case AF_INET:
                r = sd_netlink_message_read_in_addr(message, RTA_DST, &tmp->dst.in);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid destination, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_in_addr(message, RTA_GATEWAY, &tmp->gw.in);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid gateway, ignoring: %m");
                        return 0;
                } else if (r >= 0)
                        tmp->gw_family = AF_INET;

                r = sd_netlink_message_read(message, RTA_VIA, sizeof(via), &via);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid gateway, ignoring: %m");
                        return 0;
                } else if (r >= 0) {
                        tmp->gw_family = via.family;
                        tmp->gw = via.address;
                }

                r = sd_netlink_message_read_in_addr(message, RTA_SRC, &tmp->src.in);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid source, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_in_addr(message, RTA_PREFSRC, &tmp->prefsrc.in);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid preferred source, ignoring: %m");
                        return 0;
                }

                break;

        case AF_INET6:
                r = sd_netlink_message_read_in6_addr(message, RTA_DST, &tmp->dst.in6);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid destination, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_in6_addr(message, RTA_GATEWAY, &tmp->gw.in6);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid gateway, ignoring: %m");
                        return 0;
                } else if (r >= 0)
                        tmp->gw_family = AF_INET6;

                r = sd_netlink_message_read_in6_addr(message, RTA_SRC, &tmp->src.in6);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid source, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_in6_addr(message, RTA_PREFSRC, &tmp->prefsrc.in6);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: received route message without valid preferred source, ignoring: %m");
                        return 0;
                }

                break;

        default:
                assert_not_reached("Received route message with unsupported address family");
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

int link_serialize_routes(const Link *link, FILE *f) {
        bool space = false;
        Route *route;

        assert(link);
        assert(link->network);
        assert(f);

        fputs("ROUTES=", f);
        SET_FOREACH(route, link->routes) {
                _cleanup_free_ char *route_str = NULL;

                if (in_addr_to_string(route->family, &route->dst, &route_str) < 0)
                        continue;

                fprintf(f, "%s%s/%hhu/%hhu/%"PRIu32"/%"PRIu32"/"USEC_FMT,
                        space ? " " : "", route_str,
                        route->dst_prefixlen, route->tos, route->priority, route->table, route->lifetime);
                space = true;
        }
        fputc('\n', f);

        return 0;
}

int link_deserialize_routes(Link *link, const char *routes) {
        int r;

        assert(link);

        for (const char *p = routes;; ) {
                _cleanup_(route_freep) Route *tmp = NULL;
                _cleanup_free_ char *route_str = NULL;
                char *prefixlen_str;

                r = extract_first_word(&p, &route_str, NULL, 0);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Failed to parse ROUTES=: %m");
                if (r == 0)
                        return 0;

                prefixlen_str = strchr(route_str, '/');
                if (!prefixlen_str) {
                        log_link_debug(link, "Failed to parse route, ignoring: %s", route_str);
                        continue;
                }
                *prefixlen_str++ = '\0';

                r = route_new(&tmp);
                if (r < 0)
                        return log_oom();

                r = sscanf(prefixlen_str,
                           "%hhu/%hhu/%"SCNu32"/%"PRIu32"/"USEC_FMT,
                           &tmp->dst_prefixlen,
                           &tmp->tos,
                           &tmp->priority,
                           &tmp->table,
                           &tmp->lifetime);
                if (r != 5) {
                        log_link_debug(link,
                                       "Failed to parse destination prefix length, tos, priority, table or expiration: %s",
                                       prefixlen_str);
                        continue;
                }

                r = in_addr_from_string_auto(route_str, &tmp->family, &tmp->dst);
                if (r < 0) {
                        log_link_debug_errno(link, r, "Failed to parse route destination %s: %m", route_str);
                        continue;
                }

                r = route_add_and_setup_timer(link, tmp, NULL, NULL);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Failed to add route: %m");
        }
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
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Unknown route scope: %s", rvalue);
                return 0;
        }

        n->scope = r;
        n->scope_set = true;
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

        r = route_table_from_string(rvalue);
        if (r >= 0)
                n->table = r;
        else {
                r = safe_atou32(rvalue, &n->table);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Could not parse route table number \"%s\", ignoring assignment: %m", rvalue);
                        return 0;
                }
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
        if (r >= 0)
                n->protocol = r;
        else {
                r = safe_atou8(rvalue , &n->protocol);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Could not parse route protocol \"%s\", ignoring assignment: %m", rvalue);
                        return 0;
                }
        }

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
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Could not parse route type \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        n->type = (unsigned char) t;

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

        r = ordered_set_ensure_allocated(&n->multipath_routes, NULL);
        if (r < 0)
                return log_oom();

        r = ordered_set_put(n->multipath_routes, m);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to store multipath route, ignoring assignment: %m");
                return 0;
        }

        TAKE_PTR(m);
        TAKE_PTR(n);
        return 0;
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

        if (ordered_hashmap_isempty(network->addresses_by_section) &&
            in_addr_is_null(route->gw_family, &route->gw) == 0 &&
            route->gateway_onlink < 0) {
                log_warning("%s: Gateway= without static address configured. "
                            "Enabling GatewayOnLink= option.",
                            network->filename);
                route->gateway_onlink = true;
        }

        return 0;
}

void network_drop_invalid_routes(Network *network) {
        Route *route;

        assert(network);

        HASHMAP_FOREACH(route, network->routes_by_section)
                if (route_section_verify(route, network) < 0)
                        route_free(route);
}
