/* SPDX-License-Identifier: LGPL-2.1+ */

#include <linux/icmpv6.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "in-addr-util.h"
#include "missing_network.h"
#include "netlink-util.h"
#include "networkd-ipv4ll.h"
#include "networkd-manager.h"
#include "networkd-route.h"
#include "parse-util.h"
#include "set.h"
#include "socket-netlink.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "strxcpyx.h"
#include "sysctl-util.h"
#include "vrf.h"

#define ROUTES_DEFAULT_MAX_PER_FAMILY 4096U

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
        assert(!!filename == (section_line > 0));

        if (filename) {
                r = network_config_section_new(filename, section_line, &n);
                if (r < 0)
                        return r;

                route = hashmap_get(network->routes_by_section, n);
                if (route) {
                        *ret = TAKE_PTR(route);

                        return 0;
                }
        }

        if (network->n_static_routes >= routes_max())
                return -E2BIG;

        r = route_new(&route);
        if (r < 0)
                return r;

        route->protocol = RTPROT_STATIC;
        route->network = network;
        LIST_PREPEND(routes, network->static_routes, route);
        network->n_static_routes++;

        if (filename) {
                route->section = TAKE_PTR(n);

                r = hashmap_ensure_allocated(&network->routes_by_section, &network_config_hash_ops);
                if (r < 0)
                        return r;

                r = hashmap_put(network->routes_by_section, route->section, route);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(route);

        return 0;
}

void route_free(Route *route) {
        if (!route)
                return;

        if (route->network) {
                LIST_REMOVE(routes, route->network->static_routes, route);

                assert(route->network->n_static_routes > 0);
                route->network->n_static_routes--;

                if (route->section)
                        hashmap_remove(route->network->routes_by_section, route->section);
        }

        network_config_section_free(route->section);

        if (route->link) {
                set_remove(route->link->routes, route);
                set_remove(route->link->routes_foreign, route);
        }

        ordered_set_free_free(route->multipath_routes);

        sd_event_source_unref(route->expire);

        free(route);
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

                siphash24_compress(&route->gw, FAMILY_ADDRESS_SIZE(route->family), state);

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

                r = memcmp(&a->gw, &b->gw, FAMILY_ADDRESS_SIZE(a->family));
                if (r != 0)
                        return r;

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

bool route_equal(Route *r1, Route *r2) {
        if (r1 == r2)
                return true;

        if (!r1 || !r2)
                return false;

        return route_compare_func(r1, r2) == 0;
}

int route_get(Link *link, Route *in, Route **ret) {

        Route *existing;

        assert(link);
        assert(in);

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

        return -ENOENT;
}

static int route_add_internal(Link *link, Set **routes, Route *in, Route **ret) {

        _cleanup_(route_freep) Route *route = NULL;
        int r;

        assert(link);
        assert(routes);
        assert(in);

        r = route_new(&route);
        if (r < 0)
                return r;

        route->family = in->family;
        route->src = in->src;
        route->src_prefixlen = in->src_prefixlen;
        route->dst = in->dst;
        route->dst_prefixlen = in->dst_prefixlen;
        route->gw = in->gw;
        route->prefsrc = in->prefsrc;
        route->scope = in->scope;
        route->protocol = in->protocol;
        route->type = in->type;
        route->tos = in->tos;
        route->priority = in->priority;
        route->table = in->table;
        route->initcwnd = in->initcwnd;
        route->initrwnd = in->initrwnd;
        route->lifetime = in->lifetime;

        r = set_ensure_put(routes, &route_hash_ops, route);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        route->link = link;

        if (ret)
                *ret = route;

        route = NULL;

        return 0;
}

int route_add_foreign(Link *link, Route *in, Route **ret) {
        return route_add_internal(link, &link->routes_foreign, in, ret);
}

int route_add(Link *link, Route *in, Route **ret) {

        Route *route;
        int r;

        r = route_get(link, in, &route);
        if (r == -ENOENT) {
                /* Route does not exist, create a new one */
                r = route_add_internal(link, &link->routes, in, &route);
                if (r < 0)
                        return r;
        } else if (r == 0) {
                /* Take over a foreign route */
                r = set_ensure_put(&link->routes, &route_hash_ops, route);
                if (r < 0)
                        return r;

                set_remove(link->routes_foreign, route);
        } else if (r == 1) {
                /* Route exists, do nothing */
                ;
        } else
                return r;

        if (ret)
                *ret = route;

        return 0;
}

static int route_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -ESRCH)
                log_link_message_warning_errno(link, m, r, "Could not drop route, ignoring");

        return 1;
}

int route_remove(Route *route, Link *link,
                 link_netlink_message_handler_t callback) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(IN_SET(route->family, AF_INET, AF_INET6));

        r = sd_rtnl_message_new_route(link->manager->rtnl, &req,
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
                if (!in_addr_is_null(route->family, &route->gw))
                        (void) in_addr_to_string(route->family, &route->gw, &gw);
                if (!in_addr_is_null(route->family, &route->prefsrc))
                        (void) in_addr_to_string(route->family, &route->prefsrc, &prefsrc);

                log_link_debug(link, "Removing route: dst: %s%s, src: %s, gw: %s, prefsrc: %s, scope: %s, table: %s, proto: %s, type: %s",
                               strna(dst), strempty(dst_prefixlen), strna(src), strna(gw), strna(prefsrc),
                               format_route_scope(route->scope, scope, sizeof(scope)),
                               format_route_table(route->table, table, sizeof(table)),
                               format_route_protocol(route->protocol, protocol, sizeof(protocol)),
                               strna(route_type_to_string(route->type)));
        }

        if (in_addr_is_null(route->family, &route->gw) == 0) {
                r = netlink_message_append_in_addr_union(req, RTA_GATEWAY, route->family, &route->gw);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTA_GATEWAY attribute: %m");
        }

        if (route->dst_prefixlen) {
                r = netlink_message_append_in_addr_union(req, RTA_DST, route->family, &route->dst);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTA_DST attribute: %m");

                r = sd_rtnl_message_route_set_dst_prefixlen(req, route->dst_prefixlen);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set destination prefix length: %m");
        }

        if (route->src_prefixlen) {
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

        r = sd_netlink_message_append_u32(req, RTA_PRIORITY, route->priority);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append RTA_PRIORITY attribute: %m");

        if (!IN_SET(route->type, RTN_UNREACHABLE, RTN_PROHIBIT, RTN_BLACKHOLE, RTN_THROW)) {
                r = sd_netlink_message_append_u32(req, RTA_OIF, link->ifindex);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTA_OIF attribute: %m");
        }

        r = netlink_call_async(link->manager->rtnl, NULL, req,
                               callback ?: route_remove_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

int route_expire_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        Route *route = userdata;
        int r;

        assert(route);

        r = route_remove(route, route->link, NULL);
        if (r < 0)
                log_link_warning_errno(route->link, r, "Could not remove route: %m");
        else
                route_free(route);

        return 1;
}

static int append_nexthop_one(Route *route, MultipathRoute *m, struct rtattr **rta, size_t offset) {
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

static int append_nexthops(Route *route, sd_netlink_message *req) {
        _cleanup_free_ struct rtattr *rta = NULL;
        struct rtnexthop *rtnh;
        MultipathRoute *m;
        size_t offset;
        Iterator i;
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

        ORDERED_SET_FOREACH(m, route->multipath_routes, i) {
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
                Route *route,
                Link *link,
                link_netlink_message_handler_t callback) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *expire = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(IN_SET(route->family, AF_INET, AF_INET6));
        assert(callback);

        if (route_get(link, route, NULL) <= 0 &&
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
                if (!in_addr_is_null(route->family, &route->gw))
                        (void) in_addr_to_string(route->family, &route->gw, &gw);
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

        if (in_addr_is_null(route->family, &route->gw) == 0) {
                r = netlink_message_append_in_addr_union(req, RTA_GATEWAY, route->family, &route->gw);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTA_GATEWAY attribute: %m");

                r = sd_rtnl_message_route_set_family(req, route->family);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set route family: %m");
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

        if (route->gateway_onlink >= 0)
                SET_FLAG(route->flags, RTNH_F_ONLINK, route->gateway_onlink);

        r = sd_rtnl_message_route_set_flags(req, route->flags);
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

        r = sd_netlink_message_append_u32(req, RTA_PRIORITY, route->priority);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append RTA_PRIORITY attribute: %m");

        r = sd_netlink_message_append_u8(req, RTA_PREF, route->pref);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append RTA_PREF attribute: %m");

        if (route->lifetime != USEC_INFINITY && kernel_route_expiration_supported()) {
                r = sd_netlink_message_append_u32(req, RTA_EXPIRES,
                        DIV_ROUND_UP(usec_sub_unsigned(route->lifetime, now(clock_boottime_or_monotonic())), USEC_PER_SEC));
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTA_EXPIRES attribute: %m");
        }

        r = sd_rtnl_message_route_set_type(req, route->type);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set route type: %m");

        if (!IN_SET(route->type, RTN_UNREACHABLE, RTN_PROHIBIT, RTN_BLACKHOLE, RTN_THROW)) {
                r = sd_netlink_message_append_u32(req, RTA_OIF, link->ifindex);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append RTA_OIF attribute: %m");
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

        r = netlink_call_async(link->manager->rtnl, NULL, req, callback,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        r = route_add(link, route, &route);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not add route: %m");

        /* TODO: drop expiration handling once it can be pushed into the kernel */
        if (route->lifetime != USEC_INFINITY && !kernel_route_expiration_supported()) {
                r = sd_event_add_time(link->manager->event, &expire, clock_boottime_or_monotonic(),
                                      route->lifetime, 0, route_expire_handler, route);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not arm expiration timer: %m");
        }

        sd_event_source_unref(route->expire);
        route->expire = TAKE_PTR(expire);

        return 1;
}

int network_add_ipv4ll_route(Network *network) {
        _cleanup_(route_free_or_set_invalidp) Route *n = NULL;
        int r;

        assert(network);

        if (!network->ipv4ll_route)
                return 0;

        /* IPv4LLRoute= is in [Network] section. */
        r = route_new_static(network, NULL, 0, &n);
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
        int r;

        assert(network);

        if (!network->default_route_on_device)
                return 0;

        /* DefaultRouteOnDevice= is in [Network] section. */
        r = route_new_static(network, NULL, 0, &n);
        if (r < 0)
                return r;

        n->family = AF_INET;
        n->scope = RT_SCOPE_LINK;
        n->scope_set = true;
        n->protocol = RTPROT_STATIC;

        TAKE_PTR(n);
        return 0;
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
DEFINE_STRING_TABLE_LOOKUP(route_type, int);

static const char * const route_scope_table[] = {
        [RT_SCOPE_UNIVERSE] = "global",
        [RT_SCOPE_SITE]     = "site",
        [RT_SCOPE_LINK]     = "link",
        [RT_SCOPE_HOST]     = "host",
        [RT_SCOPE_NOWHERE]  = "nowhere",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(route_scope, int);

const char *format_route_scope(int scope, char *buf, size_t size) {
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

const char *format_route_table(int table, char *buf, size_t size) {
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

const char *format_route_protocol(int protocol, char *buf, size_t size) {
        const char *s;
        char *p = buf;

        s = route_protocol_full_to_string(protocol);
        if (s)
                strpcpy(&p, size, s);
        else
                strpcpyf(&p, size, "%d", protocol);

        return buf;
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
                /* we are not in an Route section, so treat
                 * this as the special '0' section */
                r = route_new_static(network, NULL, 0, &n);
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

                if (streq(rvalue, "_dhcp")) {
                        n->gateway_from_dhcp = true;
                        TAKE_PTR(n);
                        return 0;
                }
        }

        if (n->family == AF_UNSPEC)
                r = in_addr_from_string_auto(rvalue, &n->family, &n->gw);
        else
                r = in_addr_from_string(n->family, rvalue, &n->gw);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid %s='%s', ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

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
        uint64_t k;
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

        r = parse_size(rvalue, 1024, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse TCP %s \"%s\", ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }
        if (k > UINT32_MAX) {
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

int route_section_verify(Route *route, Network *network) {
        if (section_is_invalid(route->section))
                return -EINVAL;

        if (route->family == AF_UNSPEC) {
                assert(route->section);

                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Route section without Gateway=, Destination=, Source=, "
                                         "or PreferredSource= field configured. "
                                         "Ignoring [Route] section from line %u.",
                                         route->section->filename, route->section->line);
        }

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

        if (network->n_static_addresses == 0 &&
            in_addr_is_null(route->family, &route->gw) == 0 &&
            route->gateway_onlink < 0) {
                log_warning("%s: Gateway= without static address configured. "
                            "Enabling GatewayOnLink= option.",
                            network->filename);
                route->gateway_onlink = true;
        }

        return 0;
}
