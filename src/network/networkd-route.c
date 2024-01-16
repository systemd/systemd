/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/icmpv6.h>
#include <linux/ipv6_route.h>
#include <linux/nexthop.h>

#include "alloc-util.h"
#include "event-util.h"
#include "netlink-util.h"
#include "networkd-address.h"
#include "networkd-ipv4ll.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-nexthop.h"
#include "networkd-queue.h"
#include "networkd-route-util.h"
#include "networkd-route.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "vrf.h"
#include "wireguard.h"

Route* route_free(Route *route) {
        if (!route)
                return NULL;

        if (route->network) {
                assert(route->section);
                hashmap_remove(route->network->routes_by_section, route->section);
        }

        if (route->link)
                set_remove(route->link->routes, route);

        if (route->manager)
                set_remove(route->manager->routes, route);

        if (route->wireguard)
                set_remove(route->wireguard->routes, route);

        config_section_free(route->section);
        route_nexthops_done(route);
        route_metric_done(&route->metric);
        sd_event_source_disable_unref(route->expire);

        return mfree(route);
}

static void route_hash_func(const Route *route, struct siphash *state) {
        assert(route);

        siphash24_compress_typesafe(route->family, state);

        switch (route->family) {
        case AF_INET:
        case AF_INET6:
                siphash24_compress_typesafe(route->dst_prefixlen, state);
                in_addr_hash_func(&route->dst, route->family, state);

                siphash24_compress_typesafe(route->src_prefixlen, state);
                in_addr_hash_func(&route->src, route->family, state);

                siphash24_compress_typesafe(route->nexthop.family, state);
                if (IN_SET(route->nexthop.family, AF_INET, AF_INET6)) {
                        in_addr_hash_func(&route->nexthop.gw, route->nexthop.family, state);
                        siphash24_compress_typesafe(route->nexthop.weight, state);
                }

                in_addr_hash_func(&route->prefsrc, route->family, state);

                siphash24_compress_typesafe(route->tos, state);
                siphash24_compress_typesafe(route->priority, state);
                siphash24_compress_typesafe(route->table, state);
                siphash24_compress_typesafe(route->protocol, state);
                siphash24_compress_typesafe(route->scope, state);
                siphash24_compress_typesafe(route->type, state);
                route_metric_hash_func(&route->metric, state);
                siphash24_compress_typesafe(route->nexthop_id, state);

                break;
        default:
                /* treat any other address family as AF_UNSPEC */
                break;
        }
}

static int route_compare_func(const Route *a, const Route *b) {
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

                r = CMP(a->nexthop.family, b->nexthop.family);
                if (r != 0)
                        return r;

                if (IN_SET(a->nexthop.family, AF_INET, AF_INET6)) {
                        r = memcmp(&a->nexthop.gw, &b->nexthop.gw, FAMILY_ADDRESS_SIZE(a->family));
                        if (r != 0)
                                return r;

                        r = CMP(a->nexthop.weight, b->nexthop.weight);
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

                r = route_metric_compare_func(&a->metric, &b->metric);
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
                .lifetime_usec = USEC_INFINITY,
                .gateway_onlink = -1,
        };

        *ret = TAKE_PTR(route);

        return 0;
}

int route_new_static(Network *network, const char *filename, unsigned section_line, Route **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(route_freep) Route *route = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
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
        route->source = NETWORK_CONFIG_SOURCE_STATIC;

        r = hashmap_ensure_put(&network->routes_by_section, &config_section_hash_ops, route->section, route);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(route);
        return 0;
}

static int route_add(Manager *manager, Link *link, Route *route) {
        int r;

        assert(route);

        if (route_type_is_reject(route)) {
                assert(manager);

                r = set_ensure_put(&manager->routes, &route_hash_ops, route);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EEXIST;

                route->manager = manager;
        } else {
                assert(link);

                r = set_ensure_put(&link->routes, &route_hash_ops, route);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EEXIST;

                route->link = link;
        }

        return 0;
}

int route_get(Manager *manager, Link *link, const Route *in, Route **ret) {
        Route *route;

        assert(in);

        if (route_type_is_reject(in)) {
                if (!manager)
                        return -ENOENT;

                route = set_get(manager->routes, in);
        } else {
                if (!link)
                        return -ENOENT;

                route = set_get(link->routes, in);
        }
        if (!route)
                return -ENOENT;

        if (ret)
                *ret = route;

        return 0;
}

int route_dup(const Route *src, Route **ret) {
        _cleanup_(route_freep) Route *dest = NULL;
        int r;

        /* This does not copy mulipath routes. */

        assert(src);
        assert(ret);

        dest = newdup(Route, src, 1);
        if (!dest)
                return -ENOMEM;

        /* Unset all pointers */
        dest->manager = NULL;
        dest->network = NULL;
        dest->wireguard = NULL;
        dest->section = NULL;
        dest->link = NULL;
        dest->nexthops = NULL;
        dest->metric = ROUTE_METRIC_NULL;
        dest->expire = NULL;

        r = route_metric_copy(&src->metric, &dest->metric);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(dest);
        return 0;
}

static void route_apply_nexthop(Route *route, const NextHop *nh, uint8_t nh_weight) {
        assert(route);
        assert(nh);
        assert(hashmap_isempty(nh->group));

        route->nexthop.family = nh->family;
        route->nexthop.gw = nh->gw;

        if (nh_weight != UINT8_MAX)
                route->nexthop.weight = nh_weight;

        if (nh->blackhole)
                route->type = RTN_BLACKHOLE;
}

static void route_apply_route_nexthop(Route *route, const RouteNextHop *nh) {
        assert(route);
        assert(nh);

        route->nexthop.family = nh->family;
        route->nexthop.gw = nh->gw;
        route->nexthop.weight = nh->weight;
}

typedef struct ConvertedRoutes {
        size_t n;
        Route **routes;
        Link **links;
} ConvertedRoutes;

static ConvertedRoutes *converted_routes_free(ConvertedRoutes *c) {
        if (!c)
                return NULL;

        for (size_t i = 0; i < c->n; i++)
                route_free(c->routes[i]);

        free(c->routes);
        free(c->links);

        return mfree(c);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(ConvertedRoutes*, converted_routes_free);

static int converted_routes_new(size_t n, ConvertedRoutes **ret) {
        _cleanup_(converted_routes_freep) ConvertedRoutes *c = NULL;
        _cleanup_free_ Route **routes = NULL;
        _cleanup_free_ Link **links = NULL;

        assert(n > 0);
        assert(ret);

        routes = new0(Route*, n);
        if (!routes)
                return -ENOMEM;

        links = new0(Link*, n);
        if (!links)
                return -ENOMEM;

        c = new(ConvertedRoutes, 1);
        if (!c)
                return -ENOMEM;

        *c = (ConvertedRoutes) {
                .n = n,
                .routes = TAKE_PTR(routes),
                .links = TAKE_PTR(links),
        };

        *ret = TAKE_PTR(c);
        return 0;
}

static bool route_needs_convert(const Route *route) {
        assert(route);

        return route->nexthop_id > 0 || !ordered_set_isempty(route->nexthops);
}

static int route_convert(Manager *manager, Link *link, const Route *route, ConvertedRoutes **ret) {
        _cleanup_(converted_routes_freep) ConvertedRoutes *c = NULL;
        int r;

        assert(manager);
        assert(route);
        assert(ret);

        /* link may be NULL */

        if (!route_needs_convert(route)) {
                *ret = NULL;
                return 0;
        }

        if (route->nexthop_id > 0) {
                struct nexthop_grp *nhg;
                NextHop *nh;

                r = nexthop_get_by_id(manager, route->nexthop_id, &nh);
                if (r < 0)
                        return r;

                if (hashmap_isempty(nh->group)) {
                        r = converted_routes_new(1, &c);
                        if (r < 0)
                                return r;

                        r = route_dup(route, &c->routes[0]);
                        if (r < 0)
                                return r;

                        route_apply_nexthop(c->routes[0], nh, UINT8_MAX);
                        (void) link_get_by_index(manager, nh->ifindex, c->links);

                        *ret = TAKE_PTR(c);
                        return 1;
                }

                r = converted_routes_new(hashmap_size(nh->group), &c);
                if (r < 0)
                        return r;

                size_t i = 0;
                HASHMAP_FOREACH(nhg, nh->group) {
                        NextHop *h;

                        r = nexthop_get_by_id(manager, nhg->id, &h);
                        if (r < 0)
                                return r;

                        r = route_dup(route, &c->routes[i]);
                        if (r < 0)
                                return r;

                        route_apply_nexthop(c->routes[i], h, nhg->weight);
                        (void) link_get_by_index(manager, h->ifindex, c->links + i);

                        i++;
                }

                *ret = TAKE_PTR(c);
                return 1;

        }

        assert(!ordered_set_isempty(route->nexthops));

        r = converted_routes_new(ordered_set_size(route->nexthops), &c);
        if (r < 0)
                return r;

        size_t i = 0;
        RouteNextHop *nh;
        ORDERED_SET_FOREACH(nh, route->nexthops) {
                r = route_dup(route, &c->routes[i]);
                if (r < 0)
                        return r;

                route_apply_route_nexthop(c->routes[i], nh);

                r = route_nexthop_get_link(manager, link, nh, &c->links[i]);
                if (r < 0)
                        return r;

                i++;
        }

        *ret = TAKE_PTR(c);
        return 1;
}

void link_mark_routes(Link *link, NetworkConfigSource source) {
        Route *route;

        assert(link);

        SET_FOREACH(route, link->routes) {
                if (route->source != source)
                        continue;

                route_mark(route);
        }
}

static void log_route_debug(const Route *route, const char *str, const Link *link, const Manager *manager) {
        _cleanup_free_ char *state = NULL, *nexthop = NULL, *prefsrc = NULL,
                *table = NULL, *scope = NULL, *proto = NULL, *flags = NULL;
        const char *dst, *src;

        assert(route);
        assert(str);
        assert(manager);

        /* link may be NULL. */

        if (!DEBUG_LOGGING)
                return;

        (void) network_config_state_to_string_alloc(route->state, &state);

        dst = in_addr_is_set(route->family, &route->dst) || route->dst_prefixlen > 0 ?
                IN_ADDR_PREFIX_TO_STRING(route->family, &route->dst, route->dst_prefixlen) : NULL;
        src = in_addr_is_set(route->family, &route->src) || route->src_prefixlen > 0 ?
                IN_ADDR_PREFIX_TO_STRING(route->family, &route->src, route->src_prefixlen) : NULL;

        (void) route_nexthops_to_string(route, &nexthop);

        if (in_addr_is_set(route->family, &route->prefsrc))
                (void) in_addr_to_string(route->family, &route->prefsrc, &prefsrc);
        (void) route_scope_to_string_alloc(route->scope, &scope);
        (void) manager_get_route_table_to_string(manager, route->table, /* append_num = */ true, &table);
        (void) route_protocol_full_to_string_alloc(route->protocol, &proto);
        (void) route_flags_to_string_alloc(route->flags, &flags);

        log_link_debug(link,
                       "%s %s route (%s): dst: %s, src: %s, %s, prefsrc: %s, "
                       "table: %s, priority: %"PRIu32", "
                       "proto: %s, scope: %s, type: %s, flags: %s",
                       str, strna(network_config_source_to_string(route->source)), strna(state),
                       strna(dst), strna(src), strna(nexthop), strna(prefsrc),
                       strna(table), route->priority,
                       strna(proto), strna(scope), strna(route_type_to_string(route->type)), strna(flags));
}

static int route_set_netlink_message(const Route *route, sd_netlink_message *m, Link *link) {
        int r;

        assert(route);
        assert(m);

        /* link may be NULL */

        /* rtmsg header (and relevant attributes) */
        if (route->dst_prefixlen > 0) {
                r = netlink_message_append_in_addr_union(m, RTA_DST, route->family, &route->dst);
                if (r < 0)
                        return r;

                r = sd_rtnl_message_route_set_dst_prefixlen(m, route->dst_prefixlen);
                if (r < 0)
                        return r;
        }

        if (route->src_prefixlen > 0) {
                r = netlink_message_append_in_addr_union(m, RTA_SRC, route->family, &route->src);
                if (r < 0)
                        return r;

                r = sd_rtnl_message_route_set_src_prefixlen(m, route->src_prefixlen);
                if (r < 0)
                        return r;
        }

        r = sd_rtnl_message_route_set_tos(m, route->tos);
        if (r < 0)
                return r;

        r = sd_rtnl_message_route_set_scope(m, route->scope);
        if (r < 0)
                return r;

        r = sd_rtnl_message_route_set_type(m, route->type);
        if (r < 0)
                return r;

        r = sd_rtnl_message_route_set_flags(m, route->flags & ~RTNH_COMPARE_MASK);
        if (r < 0)
                return r;

        /* attributes */
        r = sd_netlink_message_append_u32(m, RTA_PRIORITY, route->priority);
        if (r < 0)
                return r;

        if (in_addr_is_set(route->family, &route->prefsrc)) {
                r = netlink_message_append_in_addr_union(m, RTA_PREFSRC, route->family, &route->prefsrc);
                if (r < 0)
                        return r;
        }

        if (route->table < 256) {
                r = sd_rtnl_message_route_set_table(m, route->table);
                if (r < 0)
                        return r;
        } else {
                r = sd_rtnl_message_route_set_table(m, RT_TABLE_UNSPEC);
                if (r < 0)
                        return r;

                /* Table attribute to allow more than 256. */
                r = sd_netlink_message_append_u32(m, RTA_TABLE, route->table);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_append_u8(m, RTA_PREF, route->pref);
        if (r < 0)
                return r;

        /* nexthops */
        r = route_nexthops_set_netlink_message(link, route, m);
        if (r < 0)
                return r;

        /* metrics */
        r = route_metric_set_netlink_message(&route->metric, m);
        if (r < 0)
                return r;

        return 0;
}

static int route_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);

        /* link may be NULL. */

        if (link && IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -ESRCH)
                log_link_message_warning_errno(link, m, r, "Could not drop route, ignoring");

        return 1;
}

int route_remove(Route *route) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        unsigned char type;
        Manager *manager;
        Link *link;
        int r;

        assert(route);
        assert(route->manager || (route->link && route->link->manager));
        assert(IN_SET(route->family, AF_INET, AF_INET6));

        link = route->link;
        manager = route->manager ?: link->manager;

        log_route_debug(route, "Removing", link, manager);

        r = sd_rtnl_message_new_route(manager->rtnl, &m, RTM_DELROUTE, route->family, route->protocol);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not create netlink message: %m");

        r = route_set_netlink_message(route, m, link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not fill netlink message: %m");

        if (route->family == AF_INET && route->nexthop_id > 0 && route->type == RTN_BLACKHOLE)
                /* When IPv4 route has nexthop id and the nexthop type is blackhole, even though kernel
                 * sends RTM_NEWROUTE netlink message with blackhole type, kernel's internal route type
                 * fib_rt_info::type may not be blackhole. Thus, we cannot know the internal value.
                 * Moreover, on route removal, the matching is done with the hidden value if we set
                 * non-zero type in RTM_DELROUTE message. Note, sd_rtnl_message_new_route() sets
                 * RTN_UNICAST by default. So, we need to clear the type here. */
                type = RTN_UNSPEC;
        else
                type = route->type;

        r = sd_rtnl_message_route_set_type(m, type);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set route type: %m");

        r = netlink_call_async(manager->rtnl, NULL, m, route_remove_handler,
                               link ? link_netlink_destroy_callback : NULL, link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not send netlink message: %m");

        link_ref(link);

        route_enter_removing(route);
        return 0;
}

int route_remove_and_drop(Route *route) {
        if (!route)
                return 0;

        route_cancel_request(route, NULL);

        if (route_exists(route))
                return route_remove(route);

        if (route->state == 0)
                route_free(route);

        return 0;
}

static void manager_mark_routes(Manager *manager, bool foreign, const Link *except) {
        Route *route;
        Link *link;
        int r;

        assert(manager);

        /* First, mark all routes. */
        SET_FOREACH(route, manager->routes) {
                /* Do not touch routes managed by the kernel. */
                if (route->protocol == RTPROT_KERNEL)
                        continue;

                /* When 'foreign' is true, mark only foreign routes, and vice versa. */
                if (foreign != (route->source == NETWORK_CONFIG_SOURCE_FOREIGN))
                        continue;

                /* Do not touch dynamic routes. They will removed by dhcp_pd_prefix_lost() */
                if (IN_SET(route->source, NETWORK_CONFIG_SOURCE_DHCP4, NETWORK_CONFIG_SOURCE_DHCP6))
                        continue;

                /* Ignore routes not assigned yet or already removed. */
                if (!route_exists(route))
                        continue;

                route_mark(route);
        }

        /* Then, unmark all routes requested by active links. */
        HASHMAP_FOREACH(link, manager->links_by_index) {
                if (link == except)
                        continue;

                if (!link->network)
                        continue;

                if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                        continue;

                HASHMAP_FOREACH(route, link->network->routes_by_section) {
                        _cleanup_(converted_routes_freep) ConvertedRoutes *converted = NULL;
                        Route *existing;

                        r = route_convert(manager, link, route, &converted);
                        if (r < 0)
                                continue;
                        if (r == 0) {
                                if (route_get(manager, NULL, route, &existing) >= 0)
                                        route_unmark(existing);
                                continue;
                        }

                        for (size_t i = 0; i < converted->n; i++)
                                if (route_get(manager, NULL, converted->routes[i], &existing) >= 0)
                                        route_unmark(existing);
                }
        }
}

static int manager_drop_marked_routes(Manager *manager) {
        Route *route;
        int r = 0;

        assert(manager);

        SET_FOREACH(route, manager->routes) {
                if (!route_is_marked(route))
                        continue;

                RET_GATHER(r, route_remove(route));
        }

        return r;
}

static bool route_by_kernel(const Route *route) {
        assert(route);

        if (route->protocol == RTPROT_KERNEL)
                return true;

        /* The kernels older than a826b04303a40d52439aa141035fca5654ccaccd (v5.11) create the IPv6
         * multicast with RTPROT_BOOT. Do not touch it. */
        if (route->protocol == RTPROT_BOOT &&
            route->family == AF_INET6 &&
            route->dst_prefixlen == 8 &&
            in6_addr_equal(&route->dst.in6, & (struct in6_addr) {{{ 0xff,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 }}}))
                return true;

        return false;
}

static void link_unmark_wireguard_routes(Link *link) {
        assert(link);

        if (!link->netdev || link->netdev->kind != NETDEV_KIND_WIREGUARD)
                return;

        Route *route, *existing;
        Wireguard *w = WIREGUARD(link->netdev);

        SET_FOREACH(route, w->routes)
                if (route_get(NULL, link, route, &existing) >= 0)
                        route_unmark(existing);
}

int link_drop_foreign_routes(Link *link) {
        Route *route;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->network);

        SET_FOREACH(route, link->routes) {
                /* do not touch routes managed by the kernel */
                if (route_by_kernel(route))
                        continue;

                /* Do not remove routes we configured. */
                if (route->source != NETWORK_CONFIG_SOURCE_FOREIGN)
                        continue;

                /* Ignore routes not assigned yet or already removed. */
                if (!route_exists(route))
                        continue;

                if (route->protocol == RTPROT_STATIC &&
                    FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_STATIC))
                        continue;

                if (route->protocol == RTPROT_DHCP &&
                    FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP))
                        continue;

                route_mark(route);
        }

        HASHMAP_FOREACH(route, link->network->routes_by_section) {
                _cleanup_(converted_routes_freep) ConvertedRoutes *converted = NULL;
                Route *existing;

                r = route_convert(link->manager, link, route, &converted);
                if (r < 0)
                        continue;
                if (r == 0) {
                        if (route_get(NULL, link, route, &existing) >= 0)
                                route_unmark(existing);
                        continue;
                }

                for (size_t i = 0; i < converted->n; i++)
                        if (route_get(NULL, link, converted->routes[i], &existing) >= 0)
                                route_unmark(existing);
        }

        link_unmark_wireguard_routes(link);

        r = 0;
        SET_FOREACH(route, link->routes) {
                if (!route_is_marked(route))
                        continue;

                RET_GATHER(r, route_remove(route));
        }

        manager_mark_routes(link->manager, /* foreign = */ true, NULL);

        return RET_GATHER(r, manager_drop_marked_routes(link->manager));
}

int link_drop_managed_routes(Link *link) {
        Route *route;
        int r = 0;

        assert(link);

        SET_FOREACH(route, link->routes) {
                /* do not touch routes managed by the kernel */
                if (route_by_kernel(route))
                        continue;

                /* Do not touch routes managed by kernel or other tools. */
                if (route->source == NETWORK_CONFIG_SOURCE_FOREIGN)
                        continue;

                if (!route_exists(route))
                        continue;

                RET_GATHER(r, route_remove(route));
        }

        manager_mark_routes(link->manager, /* foreign = */ false, link);

        return RET_GATHER(r, manager_drop_marked_routes(link->manager));
}

void link_foreignize_routes(Link *link) {
        Route *route;

        assert(link);

        SET_FOREACH(route, link->routes)
                route->source = NETWORK_CONFIG_SOURCE_FOREIGN;

        manager_mark_routes(link->manager, /* foreign = */ false, link);

        SET_FOREACH(route, link->manager->routes) {
                if (!route_is_marked(route))
                        continue;

                route->source = NETWORK_CONFIG_SOURCE_FOREIGN;
        }
}

static int route_expire_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        Route *route = ASSERT_PTR(userdata);
        Link *link;
        int r;

        assert(route->manager || (route->link && route->link->manager));

        link = route->link; /* This may be NULL. */

        r = route_remove(route);
        if (r < 0) {
                log_link_warning_errno(link, r, "Could not remove route: %m");
                if (link)
                        link_enter_failed(link);
        }

        return 1;
}

static int route_setup_timer(Route *route, const struct rta_cacheinfo *cacheinfo) {
        int r;

        assert(route);

        if (cacheinfo && cacheinfo->rta_expires != 0)
                route->expiration_managed_by_kernel = true;

        if (route->lifetime_usec == USEC_INFINITY || /* We do not request expiration for the route. */
            route->expiration_managed_by_kernel) {   /* We have received nonzero expiration previously. The expiration is managed by the kernel. */
                route->expire = sd_event_source_disable_unref(route->expire);
                return 0;
        }

        Manager *manager = ASSERT_PTR(route->manager ?: ASSERT_PTR(route->link)->manager);
        r = event_reset_time(manager->event, &route->expire, CLOCK_BOOTTIME,
                             route->lifetime_usec, 0, route_expire_handler, route, 0, "route-expiration", true);
        if (r < 0)
                return log_link_warning_errno(route->link, r, "Failed to configure expiration timer for route, ignoring: %m");

        log_route_debug(route, "Configured expiration timer for", route->link, manager);
        return 1;
}

int route_configure_handler_internal(sd_netlink *rtnl, sd_netlink_message *m, Link *link, Route *route, const char *error_msg) {
        int r;

        assert(m);
        assert(link);
        assert(link->manager);
        assert(route);
        assert(error_msg);

        r = sd_netlink_message_get_errno(m);
        if (r == -EEXIST) {
                Route *existing;

                if (route_get(link->manager, link, route, &existing) >= 0) {
                        /* When re-configuring an existing route, kernel does not send RTM_NEWROUTE
                         * notification, so we need to update the timer here. */
                        existing->lifetime_usec = route->lifetime_usec;
                        (void) route_setup_timer(existing, NULL);
                }

        } else if (r < 0) {
                log_link_message_warning_errno(link, m, r, error_msg);
                link_enter_failed(link);
                return 0;
        }

        return 1;
}

static int route_configure(const Route *route, uint32_t lifetime_sec, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(route);
        assert(IN_SET(route->family, AF_INET, AF_INET6));
        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(req);

        log_route_debug(route, "Configuring", link, link->manager);

        r = sd_rtnl_message_new_route(link->manager->rtnl, &m, RTM_NEWROUTE, route->family, route->protocol);
        if (r < 0)
                return r;

        r = route_set_netlink_message(route, m, link);
        if (r < 0)
                return r;

        if (lifetime_sec != UINT32_MAX) {
                r = sd_netlink_message_append_u32(m, RTA_EXPIRES, lifetime_sec);
                if (r < 0)
                        return r;
        }

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static int route_is_ready_to_configure(const Route *route, Link *link) {
        int r;

        assert(route);
        assert(link);

        if (!link_is_ready_to_configure(link, /* allow_unmanaged = */ false))
                return false;

        if (set_size(link->routes) >= routes_max())
                return false;

        if (in_addr_is_set(route->family, &route->prefsrc) > 0) {
                r = manager_has_address(link->manager, route->family, &route->prefsrc);
                if (r <= 0)
                        return r;
        }

        return route_nexthops_is_ready_to_configure(route, link);
}

static int route_process_request(Request *req, Link *link, Route *route) {
        _cleanup_(converted_routes_freep) ConvertedRoutes *converted = NULL;
        int r;

        assert(req);
        assert(link);
        assert(link->manager);
        assert(route);

        r = route_is_ready_to_configure(route, link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to check if route is ready to configure: %m");
        if (r == 0)
                return 0;

        if (route_needs_convert(route)) {
                r = route_convert(link->manager, link, route, &converted);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to convert route: %m");

                assert(r > 0);
                assert(converted);

                for (size_t i = 0; i < converted->n; i++) {
                        Route *existing;

                        if (route_get(link->manager, converted->links[i] ?: link, converted->routes[i], &existing) < 0) {
                                _cleanup_(route_freep) Route *tmp = NULL;

                                r = route_dup(converted->routes[i], &tmp);
                                if (r < 0)
                                        return log_oom();

                                r = route_add(link->manager, converted->links[i] ?: link, tmp);
                                if (r < 0)
                                        return log_link_warning_errno(link, r, "Failed to add route: %m");

                                TAKE_PTR(tmp);
                        } else {
                                existing->source = converted->routes[i]->source;
                                existing->provider = converted->routes[i]->provider;
                        }
                }
        }

        usec_t now_usec;
        assert_se(sd_event_now(link->manager->event, CLOCK_BOOTTIME, &now_usec) >= 0);
        uint32_t sec = usec_to_sec(route->lifetime_usec, now_usec);
        if (sec == 0) {
                log_link_debug(link, "Refuse to configure %s route with zero lifetime.",
                               network_config_source_to_string(route->source));

                if (converted)
                        for (size_t i = 0; i < converted->n; i++) {
                                Route *existing;

                                assert_se(route_get(link->manager, converted->links[i] ?: link, converted->routes[i], &existing) >= 0);
                                route_cancel_requesting(existing);
                        }
                else
                        route_cancel_requesting(route);

                return 1;
        }

        r = route_configure(route, sec, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure route: %m");

        if (converted)
                for (size_t i = 0; i < converted->n; i++) {
                        Route *existing;

                        assert_se(route_get(link->manager, converted->links[i] ?: link, converted->routes[i], &existing) >= 0);
                        route_enter_configuring(existing);
                }
        else
                route_enter_configuring(route);

        return 1;
}

int link_request_route(
                Link *link,
                Route *route,
                bool consume_object,
                unsigned *message_counter,
                route_netlink_handler_t netlink_handler,
                Request **ret) {

        Route *existing = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(route);
        assert(route->source != NETWORK_CONFIG_SOURCE_FOREIGN);
        assert(!route_needs_convert(route));

        (void) route_get(link->manager, link, route, &existing);

        if (route->lifetime_usec == 0) {
                if (consume_object)
                        route_free(route);

                /* The requested route is outdated. Let's remove it. */
                return route_remove_and_drop(existing);
        }

        if (!existing) {
                _cleanup_(route_freep) Route *tmp = NULL;

                if (consume_object)
                        tmp = route;
                else {
                        r = route_dup(route, &tmp);
                        if (r < 0)
                                return r;
                }

                r = route_add(link->manager, link, tmp);
                if (r < 0)
                        return r;

                existing = TAKE_PTR(tmp);
        } else {
                existing->source = route->source;
                existing->provider = route->provider;
                existing->lifetime_usec = route->lifetime_usec;
                if (consume_object)
                        route_free(route);
        }

        log_route_debug(existing, "Requesting", link, link->manager);
        r = link_queue_request_safe(link, REQUEST_TYPE_ROUTE,
                                    existing, NULL,
                                    route_hash_func,
                                    route_compare_func,
                                    route_process_request,
                                    message_counter, netlink_handler, ret);
        if (r <= 0)
                return r;

        route_enter_requesting(existing);
        return 1;
}

static int static_route_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, Route *route) {
        int r;

        assert(link);

        r = route_configure_handler_internal(rtnl, m, link, route, "Could not set route");
        if (r <= 0)
                return r;

        if (link->static_route_messages == 0) {
                log_link_debug(link, "Routes set");
                link->static_routes_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int link_request_static_route(Link *link, Route *route) {
        assert(link);
        assert(link->manager);
        assert(route);

        if (!route_needs_convert(route))
                return link_request_route(link, route, false, &link->static_route_messages,
                                          static_route_handler, NULL);

        log_route_debug(route, "Requesting", link, link->manager);
        return link_queue_request_safe(link, REQUEST_TYPE_ROUTE,
                                       route, NULL, route_hash_func, route_compare_func,
                                       route_process_request,
                                       &link->static_route_messages, static_route_handler, NULL);
}

static int link_request_wireguard_routes(Link *link, bool only_ipv4) {
        NetDev *netdev;
        Route *route;
        int r;

        assert(link);

        if (!streq_ptr(link->kind, "wireguard"))
                return 0;

        if (netdev_get(link->manager, link->ifname, &netdev) < 0)
                return 0;

        Wireguard *w = WIREGUARD(netdev);

        SET_FOREACH(route, w->routes) {
                if (only_ipv4 && route->family != AF_INET)
                        continue;

                r = link_request_static_route(link, route);
                if (r < 0)
                        return r;
        }

        return 0;
}

int link_request_static_routes(Link *link, bool only_ipv4) {
        Route *route;
        int r;

        assert(link);
        assert(link->network);

        link->static_routes_configured = false;

        HASHMAP_FOREACH(route, link->network->routes_by_section) {
                if (route->gateway_from_dhcp_or_ra)
                        continue;

                if (only_ipv4 && route->family != AF_INET)
                        continue;

                r = link_request_static_route(link, route);
                if (r < 0)
                        return r;
        }

        r = link_request_wireguard_routes(link, only_ipv4);
        if (r < 0)
                return r;

        if (link->static_route_messages == 0) {
                link->static_routes_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Requesting routes");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

void route_cancel_request(Route *route, Link *link) {
        Request req;

        assert(route);

        link = route->link ?: link;

        assert(link);

        if (!route_is_requesting(route))
                return;

        req = (Request) {
                .link = link,
                .type = REQUEST_TYPE_ROUTE,
                .userdata = route,
                .hash_func = (hash_func_t) route_hash_func,
                .compare_func = (compare_func_t) route_compare_func,
        };

        request_detach(link->manager, &req);
        route_cancel_requesting(route);
}

static int process_route_one(
                Manager *manager,
                Link *link,
                uint16_t type,
                Route *in,
                const struct rta_cacheinfo *cacheinfo) {

        _cleanup_(route_freep) Route *tmp = in;
        Route *route = NULL;
        bool is_new = false, update_dhcp4;
        int r;

        assert(manager);
        assert(tmp);
        assert(IN_SET(type, RTM_NEWROUTE, RTM_DELROUTE));

        /* link may be NULL. This consumes 'in'. */

        update_dhcp4 = link && tmp->family == AF_INET6 && tmp->dst_prefixlen == 0;

        (void) route_get(manager, link, tmp, &route);

        switch (type) {
        case RTM_NEWROUTE:
                if (!route) {
                        if (!manager->manage_foreign_routes) {
                                route_enter_configured(tmp);
                                log_route_debug(tmp, "Ignoring received", link, manager);
                                return 0;
                        }

                        /* If we do not know the route, then save it. */
                        r = route_add(manager, link, tmp);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Failed to remember foreign route, ignoring: %m");
                                return 0;
                        }

                        route = TAKE_PTR(tmp);
                        is_new = true;

                } else
                        /* Update remembered route with the received notification. */
                        route->flags = tmp->flags;

                route_enter_configured(route);
                log_route_debug(route, is_new ? "Received new" : "Received remembered", link, manager);

                (void) route_setup_timer(route, cacheinfo);

                break;

        case RTM_DELROUTE:
                if (route) {
                        route_enter_removed(route);
                        if (route->state == 0) {
                                log_route_debug(route, "Forgetting", link, manager);
                                route_free(route);
                        } else
                                log_route_debug(route, "Removed", link, manager);
                } else
                        log_route_debug(tmp,
                                        manager->manage_foreign_routes ? "Kernel removed unknown" : "Ignoring received",
                                        link, manager);

                break;

        default:
                assert_not_reached();
        }

        if (update_dhcp4) {
                r = dhcp4_update_ipv6_connectivity(link);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Failed to notify IPv6 connectivity to DHCPv4 client: %m");
                        link_enter_failed(link);
                }
        }

        return 1;
}

int manager_rtnl_process_route(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        _cleanup_(route_freep) Route *tmp = NULL;
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

        uint16_t type;
        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWROUTE, RTM_DELROUTE)) {
                log_warning("rtnl: received unexpected message type %u when processing route, ignoring.", type);
                return 0;
        }

        r = route_new(&tmp);
        if (r < 0)
                return log_oom();

        /* rtmsg header */
        r = sd_rtnl_message_route_get_family(message, &tmp->family);
        if (r < 0) {
                log_warning_errno(r, "rtnl: received route message without family, ignoring: %m");
                return 0;
        } else if (!IN_SET(tmp->family, AF_INET, AF_INET6)) {
                log_debug("rtnl: received route message with invalid family '%i', ignoring.", tmp->family);
                return 0;
        }

        r = sd_rtnl_message_route_get_dst_prefixlen(message, &tmp->dst_prefixlen);
        if (r < 0) {
                log_warning_errno(r, "rtnl: received route message with invalid destination prefixlen, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_src_prefixlen(message, &tmp->src_prefixlen);
        if (r < 0) {
                log_warning_errno(r, "rtnl: received route message with invalid source prefixlen, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_tos(message, &tmp->tos);
        if (r < 0) {
                log_warning_errno(r, "rtnl: received route message with invalid tos, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_protocol(message, &tmp->protocol);
        if (r < 0) {
                log_warning_errno(r, "rtnl: received route message without route protocol, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_scope(message, &tmp->scope);
        if (r < 0) {
                log_warning_errno(r, "rtnl: received route message with invalid scope, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_type(message, &tmp->type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: received route message with invalid type, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_flags(message, &tmp->flags);
        if (r < 0) {
                log_warning_errno(r, "rtnl: received route message without route flags, ignoring: %m");
                return 0;
        }

        /* attributes */
        r = netlink_message_read_in_addr_union(message, RTA_DST, tmp->family, &tmp->dst);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: received route message without valid destination, ignoring: %m");
                return 0;
        }

        r = netlink_message_read_in_addr_union(message, RTA_SRC, tmp->family, &tmp->src);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: received route message without valid source, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_u32(message, RTA_PRIORITY, &tmp->priority);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: received route message with invalid priority, ignoring: %m");
                return 0;
        }

        r = netlink_message_read_in_addr_union(message, RTA_PREFSRC, tmp->family, &tmp->prefsrc);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: received route message without valid preferred source, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_u32(message, RTA_TABLE, &tmp->table);
        if (r == -ENODATA) {
                unsigned char table;

                r = sd_rtnl_message_route_get_table(message, &table);
                if (r >= 0)
                        tmp->table = table;
        }
        if (r < 0) {
                log_warning_errno(r, "rtnl: received route message with invalid table, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_u8(message, RTA_PREF, &tmp->pref);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: received route message with invalid preference, ignoring: %m");
                return 0;
        }

        /* nexthops */
        if (route_nexthops_read_netlink_message(tmp, message) < 0)
                return 0;

        /* metrics */
        if (route_metric_read_netlink_message(&tmp->metric, message) < 0)
                return 0;

        bool has_cacheinfo;
        struct rta_cacheinfo cacheinfo;
        r = sd_netlink_message_read(message, RTA_CACHEINFO, sizeof(cacheinfo), &cacheinfo);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: failed to read RTA_CACHEINFO attribute, ignoring: %m");
                return 0;
        }
        has_cacheinfo = r >= 0;

        Link *link = NULL;
        if (tmp->nexthop.ifindex > 0) {
                r = link_get_by_index(m, tmp->nexthop.ifindex, &link);
                if (r < 0) {
                        /* when enumerating we might be out of sync, but we will
                         * get the route again, so just ignore it */
                        if (!m->enumerating)
                                log_warning("rtnl: received route message for link (%i) we do not know about, ignoring", tmp->nexthop.ifindex);
                        return 0;
                }
        }

        if (!route_needs_convert(tmp))
                return process_route_one(m, link, type, TAKE_PTR(tmp), has_cacheinfo ? &cacheinfo : NULL);

        _cleanup_(converted_routes_freep) ConvertedRoutes *converted = NULL;
        r = route_convert(m, link, tmp, &converted);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: failed to convert received route, ignoring: %m");
                return 0;
        }

        assert(r > 0);
        assert(converted);

        for (size_t i = 0; i < converted->n; i++)
                (void) process_route_one(m,
                                         converted->links[i] ?: link,
                                         type,
                                         TAKE_PTR(converted->routes[i]),
                                         has_cacheinfo ? &cacheinfo : NULL);

        return 1;
}

int network_add_ipv4ll_route(Network *network) {
        _cleanup_(route_free_or_set_invalidp) Route *route = NULL;
        unsigned section_line;
        int r;

        assert(network);

        if (!network->ipv4ll_route)
                return 0;

        r = hashmap_by_section_find_unused_line(network->routes_by_section, network->filename, &section_line);
        if (r < 0)
                return r;

        /* IPv4LLRoute= is in [Network] section. */
        r = route_new_static(network, network->filename, section_line, &route);
        if (r < 0)
                return r;

        r = in_addr_from_string(AF_INET, "169.254.0.0", &route->dst);
        if (r < 0)
                return r;

        route->family = AF_INET;
        route->dst_prefixlen = 16;
        route->scope = RT_SCOPE_LINK;
        route->scope_set = true;
        route->table_set = true;
        route->priority = IPV4LL_ROUTE_METRIC;
        route->protocol = RTPROT_STATIC;

        TAKE_PTR(route);
        return 0;
}

int network_add_default_route_on_device(Network *network) {
        _cleanup_(route_free_or_set_invalidp) Route *route = NULL;
        unsigned section_line;
        int r;

        assert(network);

        if (!network->default_route_on_device)
                return 0;

        r = hashmap_by_section_find_unused_line(network->routes_by_section, network->filename, &section_line);
        if (r < 0)
                return r;

        /* DefaultRouteOnDevice= is in [Network] section. */
        r = route_new_static(network, network->filename, section_line, &route);
        if (r < 0)
                return r;

        route->family = AF_INET;
        route->scope = RT_SCOPE_LINK;
        route->scope_set = true;
        route->protocol = RTPROT_STATIC;

        TAKE_PTR(route);
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
        _cleanup_(route_free_or_set_invalidp) Route *route = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &route);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        if (route->family == AF_UNSPEC)
                r = in_addr_from_string_auto(rvalue, &route->family, &route->prefsrc);
        else
                r = in_addr_from_string(route->family, rvalue, &route->prefsrc);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, EINVAL,
                           "Invalid %s='%s', ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(route);
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
        _cleanup_(route_free_or_set_invalidp) Route *route = NULL;
        union in_addr_union *buffer;
        unsigned char *prefixlen;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &route);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        if (streq(lvalue, "Destination")) {
                buffer = &route->dst;
                prefixlen = &route->dst_prefixlen;
        } else if (streq(lvalue, "Source")) {
                buffer = &route->src;
                prefixlen = &route->src_prefixlen;
        } else
                assert_not_reached();

        if (route->family == AF_UNSPEC)
                r = in_addr_prefix_from_string_auto(rvalue, &route->family, buffer, prefixlen);
        else
                r = in_addr_prefix_from_string(rvalue, route->family, buffer, prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, EINVAL,
                           "Invalid %s='%s', ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        (void) in_addr_mask(route->family, buffer, *prefixlen);

        TAKE_PTR(route);
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
        _cleanup_(route_free_or_set_invalidp) Route *route = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &route);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        r = safe_atou32(rvalue, &route->priority);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse route priority \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        route->priority_set = true;
        TAKE_PTR(route);
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
        _cleanup_(route_free_or_set_invalidp) Route *route = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &route);
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

        route->scope = r;
        route->scope_set = true;
        TAKE_PTR(route);
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

        _cleanup_(route_free_or_set_invalidp) Route *route = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &route);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        r = manager_get_route_table_from_string(network->manager, rvalue, &route->table);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse route table \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        route->table_set = true;
        TAKE_PTR(route);
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
        _cleanup_(route_free_or_set_invalidp) Route *route = NULL;
        int r;

        r = route_new_static(network, filename, section_line, &route);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        if (streq(rvalue, "low"))
                route->pref = ICMPV6_ROUTER_PREF_LOW;
        else if (streq(rvalue, "medium"))
                route->pref = ICMPV6_ROUTER_PREF_MEDIUM;
        else if (streq(rvalue, "high"))
                route->pref = ICMPV6_ROUTER_PREF_HIGH;
        else {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Unknown route preference: %s", rvalue);
                return 0;
        }

        route->pref_set = true;
        TAKE_PTR(route);
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
        _cleanup_(route_free_or_set_invalidp) Route *route = NULL;
        int r;

        r = route_new_static(network, filename, section_line, &route);
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

        route->protocol = r;

        TAKE_PTR(route);
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
        _cleanup_(route_free_or_set_invalidp) Route *route = NULL;
        int t, r;

        r = route_new_static(network, filename, section_line, &route);
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

        route->type = (unsigned char) t;

        TAKE_PTR(route);
        return 0;
}

int route_section_verify(Route *route) {
        int r;

        assert(route);
        assert(route->section);

        if (section_is_invalid(route->section))
                return -EINVAL;

        /* Currently, we do not support static route with finite lifetime. */
        assert(route->lifetime_usec == USEC_INFINITY);

        r = route_section_verify_nexthops(route);
        if (r < 0)
                return r;

        /* table */
        if (!route->table_set && route->network && route->network->vrf) {
                route->table = VRF(route->network->vrf)->table;
                route->table_set = true;
        }

        if (!route->table_set && IN_SET(route->type, RTN_LOCAL, RTN_BROADCAST, RTN_ANYCAST, RTN_NAT))
                route->table = RT_TABLE_LOCAL;

        /* scope */
        if (!route->scope_set && route->family == AF_INET) {
                if (IN_SET(route->type, RTN_LOCAL, RTN_NAT))
                        route->scope = RT_SCOPE_HOST;
                else if (IN_SET(route->type, RTN_BROADCAST, RTN_ANYCAST, RTN_MULTICAST))
                        route->scope = RT_SCOPE_LINK;
                else if (IN_SET(route->type, RTN_UNICAST, RTN_UNSPEC) &&
                         !route->gateway_from_dhcp_or_ra &&
                         !in_addr_is_set(route->nexthop.family, &route->nexthop.gw) &&
                         ordered_set_isempty(route->nexthops) &&
                         route->nexthop_id == 0)
                        route->scope = RT_SCOPE_LINK;
        }

        /* IPv6 route */
        if (route->family == AF_INET6) {
                if (route->scope != RT_SCOPE_UNIVERSE) {
                        log_warning("%s: Scope= is specified for IPv6 route. It will be ignored.", route->section->filename);
                        route->scope = RT_SCOPE_UNIVERSE;
                }

                if (route->priority == 0)
                        route->priority = IP6_RT_PRIO_USER;
        }

        return 0;
}

void network_drop_invalid_routes(Network *network) {
        Route *route;

        assert(network);

        HASHMAP_FOREACH(route, network->routes_by_section)
                if (route_section_verify(route) < 0)
                        route_free(route);
}
