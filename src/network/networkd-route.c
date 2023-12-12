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
                .quickack = -1,
                .fast_open_no_cookie = -1,
                .gateway_onlink = -1,
                .ttl_propagate = -1,
        };

        *ret = TAKE_PTR(route);

        return 0;
}

static int route_new_static(Network *network, const char *filename, unsigned section_line, Route **ret) {
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

Route *route_free(Route *route) {
        if (!route)
                return NULL;

        if (route->network) {
                assert(route->section);
                hashmap_remove(route->network->routes_by_section, route->section);
        }

        config_section_free(route->section);

        if (route->link)
                set_remove(route->link->routes, route);

        if (route->manager)
                set_remove(route->manager->routes, route);

        ordered_set_free_with_destructor(route->multipath_routes, multipath_route_free);

        sd_event_source_disable_unref(route->expire);

        free(route->tcp_congestion_control_algo);

        return mfree(route);
}

static void route_hash_func(const Route *route, struct siphash *state) {
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

static bool route_type_is_reject(const Route *route) {
        assert(route);

        return IN_SET(route->type, RTN_UNREACHABLE, RTN_PROHIBIT, RTN_BLACKHOLE, RTN_THROW);
}

static bool route_needs_convert(const Route *route) {
        assert(route);

        return route->nexthop_id > 0 || !ordered_set_isempty(route->multipath_routes);
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
        dest->network = NULL;
        dest->section = NULL;
        dest->link = NULL;
        dest->manager = NULL;
        dest->multipath_routes = NULL;
        dest->expire = NULL;
        dest->tcp_congestion_control_algo = NULL;

        r = free_and_strdup(&dest->tcp_congestion_control_algo, src->tcp_congestion_control_algo);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(dest);
        return 0;
}

static void route_apply_nexthop(Route *route, const NextHop *nh, uint8_t nh_weight) {
        assert(route);
        assert(nh);
        assert(hashmap_isempty(nh->group));

        route->gw_family = nh->family;
        route->gw = nh->gw;

        if (nh_weight != UINT8_MAX)
                route->gw_weight = nh_weight;

        if (nh->blackhole)
                route->type = RTN_BLACKHOLE;
}

static void route_apply_multipath_route(Route *route, const MultipathRoute *m) {
        assert(route);
        assert(m);

        route->gw_family = m->gateway.family;
        route->gw = m->gateway.address;
        route->gw_weight = m->weight;
}

static int multipath_route_get_link(Manager *manager, const MultipathRoute *m, Link **ret) {
        int r;

        assert(manager);
        assert(m);

        if (m->ifname) {
                r = link_get_by_name(manager, m->ifname, ret);
                return r < 0 ? r : 1;

        } else if (m->ifindex > 0) { /* Always ignore ifindex if ifname is set. */
                r = link_get_by_index(manager, m->ifindex, ret);
                return r < 0 ? r : 1;
        }

        if (ret)
                *ret = NULL;
        return 0;
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

static int route_convert(Manager *manager, const Route *route, ConvertedRoutes **ret) {
        _cleanup_(converted_routes_freep) ConvertedRoutes *c = NULL;
        int r;

        assert(manager);
        assert(route);
        assert(ret);

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

        assert(!ordered_set_isempty(route->multipath_routes));

        r = converted_routes_new(ordered_set_size(route->multipath_routes), &c);
        if (r < 0)
                return r;

        size_t i = 0;
        MultipathRoute *m;
        ORDERED_SET_FOREACH(m, route->multipath_routes) {
                r = route_dup(route, &c->routes[i]);
                if (r < 0)
                        return r;

                route_apply_multipath_route(c->routes[i], m);

                r = multipath_route_get_link(manager, m, &c->links[i]);
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
        _cleanup_free_ char *state = NULL, *gw_alloc = NULL, *prefsrc = NULL,
                *table = NULL, *scope = NULL, *proto = NULL, *flags = NULL;
        const char *gw = NULL, *dst, *src;

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

        if (in_addr_is_set(route->gw_family, &route->gw)) {
                (void) in_addr_to_string(route->gw_family, &route->gw, &gw_alloc);
                gw = gw_alloc;
        } else if (route->gateway_from_dhcp_or_ra) {
                if (route->gw_family == AF_INET)
                        gw = "_dhcp4";
                else if (route->gw_family == AF_INET6)
                        gw = "_ipv6ra";
        } else {
                MultipathRoute *m;

                ORDERED_SET_FOREACH(m, route->multipath_routes) {
                        _cleanup_free_ char *buf = NULL;
                        union in_addr_union a = m->gateway.address;

                        (void) in_addr_to_string(m->gateway.family, &a, &buf);
                        (void) strextend_with_separator(&gw_alloc, ",", strna(buf));
                        if (m->ifname)
                                (void) strextend(&gw_alloc, "@", m->ifname);
                        else if (m->ifindex > 0)
                                (void) strextendf(&gw_alloc, "@%i", m->ifindex);
                        /* See comments in config_parse_multipath_route(). */
                        (void) strextendf(&gw_alloc, ":%"PRIu32, m->weight + 1);
                }
                gw = gw_alloc;
        }
        if (in_addr_is_set(route->family, &route->prefsrc))
                (void) in_addr_to_string(route->family, &route->prefsrc, &prefsrc);
        (void) route_scope_to_string_alloc(route->scope, &scope);
        (void) manager_get_route_table_to_string(manager, route->table, /* append_num = */ true, &table);
        (void) route_protocol_full_to_string_alloc(route->protocol, &proto);
        (void) route_flags_to_string_alloc(route->flags, &flags);

        log_link_debug(link,
                       "%s %s route (%s): dst: %s, src: %s, gw: %s, prefsrc: %s, scope: %s, table: %s, "
                       "proto: %s, type: %s, nexthop: %"PRIu32", priority: %"PRIu32", flags: %s",
                       str, strna(network_config_source_to_string(route->source)), strna(state),
                       strna(dst), strna(src), strna(gw), strna(prefsrc),
                       strna(scope), strna(table), strna(proto),
                       strna(route_type_to_string(route->type)),
                       route->nexthop_id, route->priority, strna(flags));
}

static int route_set_netlink_message(const Route *route, sd_netlink_message *req, Link *link) {
        int r;

        assert(route);
        assert(req);

        /* link may be NULL */

        if (in_addr_is_set(route->gw_family, &route->gw) && route->nexthop_id == 0) {
                if (route->gw_family == route->family) {
                        r = netlink_message_append_in_addr_union(req, RTA_GATEWAY, route->gw_family, &route->gw);
                        if (r < 0)
                                return r;
                } else {
                        RouteVia rtvia = {
                                .family = route->gw_family,
                                .address = route->gw,
                        };

                        r = sd_netlink_message_append_data(req, RTA_VIA, &rtvia, sizeof(rtvia));
                        if (r < 0)
                                return r;
                }
        }

        if (route->dst_prefixlen > 0) {
                r = netlink_message_append_in_addr_union(req, RTA_DST, route->family, &route->dst);
                if (r < 0)
                        return r;

                r = sd_rtnl_message_route_set_dst_prefixlen(req, route->dst_prefixlen);
                if (r < 0)
                        return r;
        }

        if (route->src_prefixlen > 0) {
                r = netlink_message_append_in_addr_union(req, RTA_SRC, route->family, &route->src);
                if (r < 0)
                        return r;

                r = sd_rtnl_message_route_set_src_prefixlen(req, route->src_prefixlen);
                if (r < 0)
                        return r;
        }

        if (in_addr_is_set(route->family, &route->prefsrc)) {
                r = netlink_message_append_in_addr_union(req, RTA_PREFSRC, route->family, &route->prefsrc);
                if (r < 0)
                        return r;
        }

        r = sd_rtnl_message_route_set_scope(req, route->scope);
        if (r < 0)
                return r;

        r = sd_rtnl_message_route_set_flags(req, route->flags & RTNH_F_ONLINK);
        if (r < 0)
                return r;

        if (route->table < 256) {
                r = sd_rtnl_message_route_set_table(req, route->table);
                if (r < 0)
                        return r;
        } else {
                r = sd_rtnl_message_route_set_table(req, RT_TABLE_UNSPEC);
                if (r < 0)
                        return r;

                /* Table attribute to allow more than 256. */
                r = sd_netlink_message_append_u32(req, RTA_TABLE, route->table);
                if (r < 0)
                        return r;
        }

        if (!route_type_is_reject(route) &&
            route->nexthop_id == 0 &&
            ordered_set_isempty(route->multipath_routes)) {
                assert(link); /* Those routes must be attached to a specific link */

                r = sd_netlink_message_append_u32(req, RTA_OIF, link->ifindex);
                if (r < 0)
                        return r;
        }

        if (route->nexthop_id > 0) {
                r = sd_netlink_message_append_u32(req, RTA_NH_ID, route->nexthop_id);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_append_u8(req, RTA_PREF, route->pref);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(req, RTA_PRIORITY, route->priority);
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
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
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

        r = sd_rtnl_message_new_route(manager->rtnl, &req,
                                      RTM_DELROUTE, route->family,
                                      route->protocol);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create netlink message: %m");

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

        r = sd_rtnl_message_route_set_type(req, type);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set route type: %m");

        r = route_set_netlink_message(route, req, link);
        if (r < 0)
                return log_error_errno(r, "Could not fill netlink message: %m");

        r = netlink_call_async(manager->rtnl, NULL, req, route_remove_handler,
                               link ? link_netlink_destroy_callback : NULL, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send netlink message: %m");

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

                        r = route_convert(manager, route, &converted);
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

                r = route_convert(link->manager, route, &converted);
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
        Manager *manager;
        int r;

        assert(route);
        assert(route->manager || (route->link && route->link->manager));

        manager = route->manager ?: route->link->manager;

        if (route->lifetime_usec == USEC_INFINITY)
                return 0;

        if (cacheinfo && cacheinfo->rta_expires != 0)
                /* Assume that non-zero rta_expires means kernel will handle the route expiration. */
                return 0;

        r = event_reset_time(manager->event, &route->expire, CLOCK_BOOTTIME,
                             route->lifetime_usec, 0, route_expire_handler, route, 0, "route-expiration", true);
        if (r < 0)
                return r;

        return 1;
}

static int append_nexthop_one(const Link *link, const Route *route, const MultipathRoute *m, struct rtattr **rta, size_t offset) {
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
                .rtnh_ifindex = m->ifindex > 0 ? m->ifindex : link->ifindex,
                .rtnh_hops = m->weight,
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

static int append_nexthops(const Link *link, const Route *route, sd_netlink_message *req) {
        _cleanup_free_ struct rtattr *rta = NULL;
        struct rtnexthop *rtnh;
        MultipathRoute *m;
        size_t offset;
        int r;

        assert(link);
        assert(route);
        assert(req);

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
                r = append_nexthop_one(link, route, m, &rta, offset);
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

int route_configure_handler_internal(sd_netlink *rtnl, sd_netlink_message *m, Link *link, const char *error_msg) {
        int r;

        assert(m);
        assert(link);
        assert(error_msg);

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not set route");
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

        r = sd_rtnl_message_route_set_type(m, route->type);
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

        if (route->ttl_propagate >= 0) {
                r = sd_netlink_message_append_u8(m, RTA_TTL_PROPAGATE, route->ttl_propagate);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_open_container(m, RTA_METRICS);
        if (r < 0)
                return r;

        if (route->mtu > 0) {
                r = sd_netlink_message_append_u32(m, RTAX_MTU, route->mtu);
                if (r < 0)
                        return r;
        }

        if (route->initcwnd > 0) {
                r = sd_netlink_message_append_u32(m, RTAX_INITCWND, route->initcwnd);
                if (r < 0)
                        return r;
        }

        if (route->initrwnd > 0) {
                r = sd_netlink_message_append_u32(m, RTAX_INITRWND, route->initrwnd);
                if (r < 0)
                        return r;
        }

        if (route->quickack >= 0) {
                r = sd_netlink_message_append_u32(m, RTAX_QUICKACK, route->quickack);
                if (r < 0)
                        return r;
        }

        if (route->fast_open_no_cookie >= 0) {
                r = sd_netlink_message_append_u32(m, RTAX_FASTOPEN_NO_COOKIE, route->fast_open_no_cookie);
                if (r < 0)
                        return r;
        }

        if (route->advmss > 0) {
                r = sd_netlink_message_append_u32(m, RTAX_ADVMSS, route->advmss);
                if (r < 0)
                        return r;
        }

        if (!isempty(route->tcp_congestion_control_algo)) {
                r = sd_netlink_message_append_string(m, RTAX_CC_ALGO, route->tcp_congestion_control_algo);
                if (r < 0)
                        return r;
        }

        if (route->hop_limit > 0) {
                r = sd_netlink_message_append_u32(m, RTAX_HOPLIMIT, route->hop_limit);
                if (r < 0)
                        return r;
        }

        if (route->tcp_rto_usec > 0) {
                r = sd_netlink_message_append_u32(m, RTAX_RTO_MIN, DIV_ROUND_UP(route->tcp_rto_usec, USEC_PER_MSEC));
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        if (!ordered_set_isempty(route->multipath_routes)) {
                assert(route->nexthop_id == 0);
                assert(!in_addr_is_set(route->gw_family, &route->gw));

                r = append_nexthops(link, route, m);
                if (r < 0)
                        return r;
        }

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static int route_is_ready_to_configure(const Route *route, Link *link) {
        int r;

        assert(route);
        assert(link);

        if (!link_is_ready_to_configure(link, false))
                return false;

        if (set_size(link->routes) >= routes_max())
                return false;

        if (route->nexthop_id > 0) {
                struct nexthop_grp *nhg;
                NextHop *nh;

                if (nexthop_get_by_id(link->manager, route->nexthop_id, &nh) < 0)
                        return false;

                if (!nexthop_exists(nh))
                        return false;

                HASHMAP_FOREACH(nhg, nh->group) {
                        NextHop *g;

                        if (nexthop_get_by_id(link->manager, nhg->id, &g) < 0)
                                return false;

                        if (!nexthop_exists(g))
                                return false;
                }
        }

        if (in_addr_is_set(route->family, &route->prefsrc) > 0) {
                r = manager_has_address(link->manager, route->family, &route->prefsrc, route->family == AF_INET6);
                if (r <= 0)
                        return r;
        }

        if (!gateway_is_ready(link, FLAGS_SET(route->flags, RTNH_F_ONLINK), route->gw_family, &route->gw))
                return false;

        MultipathRoute *m;
        ORDERED_SET_FOREACH(m, route->multipath_routes) {
                union in_addr_union a = m->gateway.address;
                Link *l = NULL;

                r = multipath_route_get_link(link->manager, m, &l);
                if (r < 0)
                        return false;
                if (r > 0) {
                        if (!link_is_ready_to_configure(l, /* allow_unmanaged = */ true) ||
                            !link_has_carrier(l))
                                return false;

                        m->ifindex = l->ifindex;
                }

                if (!gateway_is_ready(l ?: link, FLAGS_SET(route->flags, RTNH_F_ONLINK), m->gateway.family, &a))
                        return false;
        }

        return true;
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
                r = route_convert(link->manager, route, &converted);
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

                if (existing->expire) {
                        /* When re-configuring an existing route, kernel does not send RTM_NEWROUTE
                         * message, so we need to update the timer here. */
                        r = route_setup_timer(existing, NULL);
                        if (r < 0)
                                log_link_warning_errno(link, r, "Failed to update expiration timer for route, ignoring: %m");
                        if (r > 0)
                                log_route_debug(existing, "Updated expiration timer for", link, link->manager);
                }
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

        r = route_configure_handler_internal(rtnl, m, link, "Could not set route");
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
        bool update_dhcp4;
        int r;

        assert(manager);
        assert(tmp);
        assert(IN_SET(type, RTM_NEWROUTE, RTM_DELROUTE));

        /* link may be NULL. This consumes 'in'. */

        update_dhcp4 = link && tmp->family == AF_INET6 && tmp->dst_prefixlen == 0;

        (void) route_get(manager, link, tmp, &route);

        switch (type) {
        case RTM_NEWROUTE:
                if (route) {
                        route->flags = tmp->flags;
                        route_enter_configured(route);
                        log_route_debug(route, "Received remembered", link, manager);

                        r = route_setup_timer(route, cacheinfo);
                        if (r < 0)
                                log_link_warning_errno(link, r, "Failed to configure expiration timer for route, ignoring: %m");
                        if (r > 0)
                                log_route_debug(route, "Configured expiration timer for", link, manager);

                } else if (!manager->manage_foreign_routes) {
                        route_enter_configured(tmp);
                        log_route_debug(tmp, "Ignoring received", link, manager);

                } else {
                        /* A route appeared that we did not request */
                        route_enter_configured(tmp);
                        log_route_debug(tmp, "Received new", link, manager);
                        r = route_add(manager, link, tmp);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Failed to remember foreign route, ignoring: %m");
                                return 0;
                        }
                        TAKE_PTR(tmp);
                }

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
        _cleanup_(converted_routes_freep) ConvertedRoutes *converted = NULL;
        _cleanup_(route_freep) Route *tmp = NULL;
        _cleanup_free_ void *rta_multipath = NULL;
        struct rta_cacheinfo cacheinfo;
        bool has_cacheinfo;
        Link *link = NULL;
        uint32_t ifindex;
        uint16_t type;
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
                        log_warning("rtnl: received route message with invalid ifindex %u, ignoring.", ifindex);
                        return 0;
                }

                r = link_get_by_index(m, ifindex, &link);
                if (r < 0) {
                        /* when enumerating we might be out of sync, but we will
                         * get the route again, so just ignore it */
                        if (!m->enumerating)
                                log_warning("rtnl: received route message for link (%u) we do not know about, ignoring", ifindex);
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
                log_warning_errno(r, "rtnl: received route message without route protocol, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_route_get_flags(message, &tmp->flags);
        if (r < 0) {
                log_warning_errno(r, "rtnl: received route message without route flags, ignoring: %m");
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

        r = sd_netlink_message_read_u32(message, RTA_TABLE, &tmp->table);
        if (r == -ENODATA) {
                unsigned char table;

                r = sd_rtnl_message_route_get_table(message, &table);
                if (r >= 0)
                        tmp->table = table;
        }
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received route message with invalid table, ignoring: %m");
                return 0;
        }

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
                log_link_error_errno(link, r, "rtnl: Could not enter RTA_METRICS container, ignoring: %m");
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
                        log_link_error_errno(link, r, "rtnl: Could not exit from RTA_METRICS container, ignoring: %m");
                        return 0;
                }
        }

        r = sd_netlink_message_read_data(message, RTA_MULTIPATH, &rta_len, &rta_multipath);
        if (r < 0 && r != -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: failed to read RTA_MULTIPATH attribute, ignoring: %m");
                return 0;
        } else if (r >= 0) {
                r = rtattr_read_nexthop(rta_multipath, rta_len, tmp->family, &tmp->multipath_routes);
                if (r < 0) {
                        log_link_warning_errno(link, r, "rtnl: failed to parse RTA_MULTIPATH attribute, ignoring: %m");
                        return 0;
                }
        }

        r = sd_netlink_message_read(message, RTA_CACHEINFO, sizeof(cacheinfo), &cacheinfo);
        if (r < 0 && r != -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: failed to read RTA_CACHEINFO attribute, ignoring: %m");
                return 0;
        }
        has_cacheinfo = r >= 0;

        /* IPv6 routes with reject type are always assigned to the loopback interface. See kernel's
         * fib6_nh_init() in net/ipv6/route.c. However, we'd like to manage them by Manager. Hence, set
         * link to NULL here. */
        if (route_type_is_reject(tmp))
                link = NULL;

        if (!route_needs_convert(tmp))
                return process_route_one(m, link, type, TAKE_PTR(tmp), has_cacheinfo ? &cacheinfo : NULL);

        r = route_convert(m, tmp, &converted);
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
        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        unsigned section_line;
        int r;

        assert(network);

        if (!network->ipv4ll_route)
                return 0;

        r = hashmap_by_section_find_unused_line(network->routes_by_section, network->filename, &section_line);
        if (r < 0)
                return r;

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

        r = hashmap_by_section_find_unused_line(network->routes_by_section, network->filename, &section_line);
        if (r < 0)
                return r;

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
                assert_not_reached();

        if (n->family == AF_UNSPEC)
                r = in_addr_prefix_from_string_auto(rvalue, &n->family, buffer, prefixlen);
        else
                r = in_addr_prefix_from_string(rvalue, n->family, buffer, prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, EINVAL,
                           "Invalid %s='%s', ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        (void) in_addr_mask(n->family, buffer, *prefixlen);

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
                           "Could not parse route table \"%s\", ignoring assignment: %m", rvalue);
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
                assert_not_reached();

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

int config_parse_route_hop_limit(
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

        if (isempty(rvalue)) {
                n->hop_limit = 0;
                TAKE_PTR(n);
                return 0;
        }

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse per route hop limit, ignoring assignment: %s", rvalue);
                return 0;
        }
        if (k > 255) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified per route hop limit \"%s\" is too large, ignoring assignment: %m", rvalue);
                return 0;
        }
        if (k == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid per route hop limit \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        n->hop_limit = k;

        TAKE_PTR(n);
        return 0;
}

int config_parse_tcp_congestion(
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

        r = config_parse_string(unit, filename, line, section, section_line, lvalue, ltype,
                                rvalue, &n->tcp_congestion_control_algo, userdata);
        if (r < 0)
                return r;

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

        uint32_t *window = ASSERT_PTR(data);
        uint32_t k;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

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

        *window = k;
        return 0;
}

int config_parse_route_tcp_window(
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
        uint32_t *d;
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

        if (streq(lvalue, "InitialCongestionWindow"))
                d = &n->initcwnd;
        else if (streq(lvalue, "InitialAdvertisedReceiveWindow"))
                d = &n->initrwnd;
        else
                assert_not_reached();

        r = config_parse_tcp_window(unit, filename, line, section, section_line, lvalue, ltype, rvalue, d, userdata);
        if (r < 0)
                return r;

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

int config_parse_route_tcp_rto(
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
        usec_t usec;
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

        r = parse_sec(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse route TCP retransmission timeout (RTO), ignoring assignment: %s", rvalue);
                return 0;
        }

        if (IN_SET(usec, 0, USEC_INFINITY) ||
            DIV_ROUND_UP(usec, USEC_PER_MSEC) > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Route TCP retransmission timeout (RTO) must be in the range 0…%"PRIu32"ms, ignoring assignment: %s", UINT32_MAX, rvalue);
                return 0;
        }

        n->tcp_rto_usec = usec;

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

        _cleanup_(multipath_route_freep) MultipathRoute *m = NULL;
        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        _cleanup_free_ char *word = NULL;
        Network *network = userdata;
        union in_addr_union a;
        int family, r;
        const char *p;
        char *dev;

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
                n->multipath_routes = ordered_set_free_with_destructor(n->multipath_routes, multipath_route_free);
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
                *dev++ = '\0';

                r = parse_ifindex(dev);
                if (r > 0)
                        m->ifindex = r;
                else {
                        if (!ifname_valid_full(dev, IFNAME_VALID_ALTERNATIVE)) {
                                log_syntax(unit, LOG_WARNING, filename, line, 0,
                                           "Invalid interface name '%s' in %s=, ignoring: %s", dev, lvalue, rvalue);
                                return 0;
                        }

                        m->ifname = strdup(dev);
                        if (!m->ifname)
                                return log_oom();
                }
        }

        r = in_addr_from_string_auto(word, &family, &a);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid multipath route gateway '%s', ignoring assignment: %m", rvalue);
                return 0;
        }
        m->gateway.address = a;
        m->gateway.family = family;

        if (!isempty(p)) {
                r = safe_atou32(p, &m->weight);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid multipath route weight, ignoring assignment: %s", p);
                        return 0;
                }
                /* ip command takes weight in the range 1…255, while kernel takes the value in the
                 * range 0…254. MultiPathRoute= setting also takes weight in the same range which ip
                 * command uses, then networkd decreases by one and stores it to match the range which
                 * kernel uses. */
                if (m->weight == 0 || m->weight > 256) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid multipath route weight, ignoring assignment: %s", p);
                        return 0;
                }
                m->weight--;
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

static int route_section_verify(Route *route, Network *network) {
        if (section_is_invalid(route->section))
                return -EINVAL;

        /* Currently, we do not support static route with finite lifetime. */
        assert(route->lifetime_usec == USEC_INFINITY);

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
                else if (IN_SET(route->type, RTN_UNICAST, RTN_UNSPEC) &&
                         !route->gateway_from_dhcp_or_ra &&
                         !in_addr_is_set(route->gw_family, &route->gw) &&
                         ordered_set_isempty(route->multipath_routes) &&
                         route->nexthop_id == 0)
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

        if (route->gateway_onlink >= 0)
                SET_FLAG(route->flags, RTNH_F_ONLINK, route->gateway_onlink);

        if (route->family == AF_INET6) {
                MultipathRoute *m;

                ORDERED_SET_FOREACH(m, route->multipath_routes)
                        if (m->gateway.family == AF_INET)
                                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                         "%s: IPv4 multipath route is specified for IPv6 route. "
                                                         "Ignoring [Route] section from line %u.",
                                                         route->section->filename, route->section->line);
        }

        if ((route->gateway_from_dhcp_or_ra ||
             in_addr_is_set(route->gw_family, &route->gw)) &&
            !ordered_set_isempty(route->multipath_routes))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Gateway= cannot be specified with MultiPathRoute=. "
                                         "Ignoring [Route] section from line %u.",
                                         route->section->filename, route->section->line);

        if (route->nexthop_id > 0 &&
            (route->gateway_from_dhcp_or_ra ||
             in_addr_is_set(route->gw_family, &route->gw) ||
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
