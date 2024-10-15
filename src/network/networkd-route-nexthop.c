/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/nexthop.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-nexthop.h"
#include "networkd-route.h"
#include "networkd-route-nexthop.h"
#include "networkd-route-util.h"
#include "parse-util.h"
#include "string-util.h"

void route_detach_from_nexthop(Route *route) {
        NextHop *nh;

        assert(route);
        assert(route->manager);

        if (route->nexthop_id == 0)
                return;

        if (nexthop_get_by_id(route->manager, route->nexthop_id, &nh) < 0)
                return;

        route_unref(set_remove(nh->routes, route));
}

void route_attach_to_nexthop(Route *route) {
        NextHop *nh;
        int r;

        assert(route);
        assert(route->manager);

        if (route->nexthop_id == 0)
                return;

        r = nexthop_get_by_id(route->manager, route->nexthop_id, &nh);
        if (r < 0) {
                if (route->manager->manage_foreign_nexthops)
                        log_debug_errno(r, "Route has unknown nexthop ID (%"PRIu32"), ignoring.",
                                        route->nexthop_id);
                return;
        }

        r = set_ensure_put(&nh->routes, &route_hash_ops_unref, route);
        if (r < 0)
                return (void) log_debug_errno(r, "Failed to save route to nexthop, ignoring: %m");
        if (r == 0)
                return (void) log_debug("Duplicated route assigned to nexthop, ignoring.");

        route_ref(route);
}

static void route_nexthop_done(RouteNextHop *nh) {
        assert(nh);

        free(nh->ifname);
}

RouteNextHop* route_nexthop_free(RouteNextHop *nh) {
        if (!nh)
                return NULL;

        route_nexthop_done(nh);

        return mfree(nh);
}

void route_nexthops_done(Route *route) {
        assert(route);

        route_nexthop_done(&route->nexthop);
        ordered_set_free(route->nexthops);
}

static void route_nexthop_hash_func_full(const RouteNextHop *nh, struct siphash *state, bool with_weight) {
        assert(nh);
        assert(state);

        /* See nh_comp() in net/ipv4/fib_semantics.c of the kernel. */

        siphash24_compress_typesafe(nh->family, state);
        if (!IN_SET(nh->family, AF_INET, AF_INET6))
                return;

        in_addr_hash_func(&nh->gw, nh->family, state);
        if (with_weight)
                siphash24_compress_typesafe(nh->weight, state);
        siphash24_compress_typesafe(nh->ifindex, state);
        if (nh->ifindex == 0)
                siphash24_compress_string(nh->ifname, state); /* For Network or Request object. */
}

static int route_nexthop_compare_func_full(const RouteNextHop *a, const RouteNextHop *b, bool with_weight) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->family, b->family);
        if (r != 0)
                return r;

        if (!IN_SET(a->family, AF_INET, AF_INET6))
                return 0;

        r = memcmp(&a->gw, &b->gw, FAMILY_ADDRESS_SIZE(a->family));
        if (r != 0)
                return r;

        if (with_weight) {
                r = CMP(a->weight, b->weight);
                if (r != 0)
                        return r;
        }

        r = CMP(a->ifindex, b->ifindex);
        if (r != 0)
                return r;

        if (a->ifindex == 0) {
                r = strcmp_ptr(a->ifname, b->ifname);
                if (r != 0)
                        return r;
        }

        return 0;
}

static void route_nexthop_hash_func(const RouteNextHop *nh, struct siphash *state) {
        route_nexthop_hash_func_full(nh, state, /* with_weight = */ true);
}

static int route_nexthop_compare_func(const RouteNextHop *a, const RouteNextHop *b) {
        return route_nexthop_compare_func_full(a, b, /* with_weight = */ true);
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
        route_nexthop_hash_ops,
        RouteNextHop,
        route_nexthop_hash_func,
        route_nexthop_compare_func,
        route_nexthop_free);

static size_t route_n_nexthops(const Route *route) {
        if (route->nexthop_id != 0 || route_is_reject(route))
                return 0;

        if (ordered_set_isempty(route->nexthops))
                return 1;

        return ordered_set_size(route->nexthops);
}

void route_nexthops_hash_func(const Route *route, struct siphash *state) {
        assert(route);

        size_t nhs = route_n_nexthops(route);
        siphash24_compress_typesafe(nhs, state);

        switch (nhs) {
        case 0:
                siphash24_compress_typesafe(route->nexthop_id, state);
                return;

        case 1:
                route_nexthop_hash_func_full(&route->nexthop, state, /* with_weight = */ false);
                return;

        default: {
                RouteNextHop *nh;
                ORDERED_SET_FOREACH(nh, route->nexthops)
                        route_nexthop_hash_func(nh, state);
        }}
}

int route_nexthops_compare_func(const Route *a, const Route *b) {
        int r;

        assert(a);
        assert(b);

        size_t a_nhs = route_n_nexthops(a);
        size_t b_nhs = route_n_nexthops(b);
        r = CMP(a_nhs, b_nhs);
        if (r != 0)
                return r;

        switch (a_nhs) {
        case 0:
                return CMP(a->nexthop_id, b->nexthop_id);

        case 1:
                return route_nexthop_compare_func_full(&a->nexthop, &b->nexthop, /* with_weight = */ false);

        default: {
                RouteNextHop *nh;
                ORDERED_SET_FOREACH(nh, a->nexthops) {
                        r = CMP(nh, (RouteNextHop*) ordered_set_get(a->nexthops, nh));
                        if (r != 0)
                                return r;
                }
                return 0;
        }}
}

static int route_nexthop_copy(const RouteNextHop *src, RouteNextHop *dest) {
        assert(src);
        assert(dest);

        *dest = *src;

        /* unset pointer copied in the above. */
        dest->ifname = NULL;

        return strdup_to(&dest->ifname, src->ifindex > 0 ? NULL : src->ifname);
}

static int route_nexthop_dup(const RouteNextHop *src, RouteNextHop **ret) {
        _cleanup_(route_nexthop_freep) RouteNextHop *dest = NULL;
        int r;

        assert(src);
        assert(ret);

        dest = new(RouteNextHop, 1);
        if (!dest)
                return -ENOMEM;

        r = route_nexthop_copy(src, dest);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(dest);
        return 0;
}

int route_nexthops_copy(const Route *src, const RouteNextHop *nh, Route *dest) {
        int r;

        assert(src);
        assert(dest);

        if (src->nexthop_id != 0 || route_is_reject(src))
                return 0;

        if (nh)
                return route_nexthop_copy(nh, &dest->nexthop);

        if (ordered_set_isempty(src->nexthops))
                return route_nexthop_copy(&src->nexthop, &dest->nexthop);

        ORDERED_SET_FOREACH(nh, src->nexthops) {
                _cleanup_(route_nexthop_freep) RouteNextHop *nh_dup = NULL;

                r = route_nexthop_dup(nh, &nh_dup);
                if (r < 0)
                        return r;

                r = ordered_set_ensure_put(&dest->nexthops, &route_nexthop_hash_ops, nh_dup);
                if (r < 0)
                        return r;
                assert(r > 0);

                TAKE_PTR(nh_dup);
        }

        return 0;
}

static bool multipath_routes_needs_adjust(const Route *route) {
        assert(route);

        RouteNextHop *nh;
        ORDERED_SET_FOREACH(nh, route->nexthops)
                if (route->nexthop.ifindex == 0)
                        return true;

        return false;
}

bool route_nexthops_needs_adjust(const Route *route) {
        assert(route);

        if (route->nexthop_id != 0)
                /* At this stage, the nexthop may not be configured, or may be under reconfiguring.
                 * Hence, we cannot know if the nexthop is blackhole or not. */
                return route->type != RTN_BLACKHOLE;

        if (route_is_reject(route))
                return false;

        if (ordered_set_isempty(route->nexthops))
                return route->nexthop.ifindex == 0;

        return multipath_routes_needs_adjust(route);
}

static bool route_nexthop_set_ifindex(RouteNextHop *nh, Link *link) {
        assert(nh);
        assert(link);
        assert(link->manager);

        if (nh->ifindex > 0) {
                nh->ifname = mfree(nh->ifname);
                return false;
        }

        /* If an interface name is specified, use it. Otherwise, use the interface that requests this route. */
        if (nh->ifname && link_get_by_name(link->manager, nh->ifname, &link) < 0)
                return false;

        nh->ifindex = link->ifindex;
        nh->ifname = mfree(nh->ifname);
        return true; /* updated */
}

int route_adjust_nexthops(Route *route, Link *link) {
        int r;

        assert(route);
        assert(link);
        assert(link->manager);

        /* When an IPv4 route has nexthop id and the nexthop type is blackhole, even though kernel sends
         * RTM_NEWROUTE netlink message with blackhole type, kernel's internal route type fib_rt_info::type
         * may not be blackhole. Thus, we cannot know the internal value. Moreover, on route removal, the
         * matching is done with the hidden value if we set non-zero type in RTM_DELROUTE message. So,
         * here let's set route type to BLACKHOLE when the nexthop is blackhole. */
        if (route->nexthop_id != 0) {
                NextHop *nexthop;

                r = nexthop_is_ready(link->manager, route->nexthop_id, &nexthop);
                if (r <= 0)
                        return r; /* r == 0 means the nexthop is under (re-)configuring.
                                   * We cannot use the currently remembered information. */

                if (!nexthop->blackhole)
                        return false;

                if (route->type == RTN_BLACKHOLE)
                        return false;

                route->type = RTN_BLACKHOLE;
                return true; /* updated */
        }

        if (route_is_reject(route))
                return false;

        if (ordered_set_isempty(route->nexthops))
                return route_nexthop_set_ifindex(&route->nexthop, link);

        if (!multipath_routes_needs_adjust(route))
                return false;

        _cleanup_ordered_set_free_ OrderedSet *nexthops = NULL;
        for (;;) {
                _cleanup_(route_nexthop_freep) RouteNextHop *nh = NULL;

                nh = ordered_set_steal_first(route->nexthops);
                if (!nh)
                        break;

                (void) route_nexthop_set_ifindex(nh, link);

                r = ordered_set_ensure_put(&nexthops, &route_nexthop_hash_ops, nh);
                if (r == -EEXIST)
                        continue; /* Duplicated? Let's drop the nexthop. */
                if (r < 0)
                        return r;
                assert(r > 0);

                TAKE_PTR(nh);
        }

        ordered_set_free(route->nexthops);
        route->nexthops = TAKE_PTR(nexthops);
        return true; /* updated */
}

int route_nexthop_get_link(Manager *manager, const RouteNextHop *nh, Link **ret) {
        assert(manager);
        assert(nh);

        if (nh->ifindex > 0)
                return link_get_by_index(manager, nh->ifindex, ret);
        if (nh->ifname)
                return link_get_by_name(manager, nh->ifname, ret);

        return -ENOENT;
}

static bool route_nexthop_is_ready_to_configure(const RouteNextHop *nh, Manager *manager, bool onlink) {
        Link *link;

        assert(nh);
        assert(manager);

        if (route_nexthop_get_link(manager, nh, &link) < 0)
                return false;

        if (!link_is_ready_to_configure(link, /* allow_unmanaged = */ true))
                return false;

        /* If the interface is not managed by us, we request that the interface has carrier.
         * That is, ConfigureWithoutCarrier=no is the default even for unamanaged interfaces. */
        if (!link->network && !link_has_carrier(link))
                return false;

        return gateway_is_ready(link, onlink, nh->family, &nh->gw);
}

int route_nexthops_is_ready_to_configure(const Route *route, Manager *manager) {
        int r;

        assert(route);
        assert(manager);

        if (route->nexthop_id != 0) {
                struct nexthop_grp *nhg;
                NextHop *nh;

                r = nexthop_is_ready(manager, route->nexthop_id, &nh);
                if (r <= 0)
                        return r;

                HASHMAP_FOREACH(nhg, nh->group) {
                        r = nexthop_is_ready(manager, nhg->id, NULL);
                        if (r <= 0)
                                return r;
                }

                return true;
        }

        if (route_is_reject(route))
                return true;

        if (ordered_set_isempty(route->nexthops))
                return route_nexthop_is_ready_to_configure(&route->nexthop, manager, FLAGS_SET(route->flags, RTNH_F_ONLINK));

        RouteNextHop *nh;
        ORDERED_SET_FOREACH(nh, route->nexthops)
                if (!route_nexthop_is_ready_to_configure(nh, manager, FLAGS_SET(route->flags, RTNH_F_ONLINK)))
                        return false;

        return true;
}

int route_nexthops_to_string(const Route *route, char **ret) {
        _cleanup_free_ char *buf = NULL;
        int r;

        assert(route);
        assert(ret);

        if (route->nexthop_id != 0) {
                if (asprintf(&buf, "nexthop: %"PRIu32, route->nexthop_id) < 0)
                        return -ENOMEM;

                *ret = TAKE_PTR(buf);
                return 0;
        }

        if (route_is_reject(route)) {
                buf = strdup("gw: n/a");
                if (!buf)
                        return -ENOMEM;

                *ret = TAKE_PTR(buf);
                return 0;
        }

        if (ordered_set_isempty(route->nexthops)) {
                if (in_addr_is_set(route->nexthop.family, &route->nexthop.gw)) {
                        if (asprintf(&buf, "gw: %s:%"PRIu32, IN_ADDR_TO_STRING(route->nexthop.family, &route->nexthop.gw), route->nexthop.weight + 1) < 0)
                                return -ENOMEM;
                } else if (route->gateway_from_dhcp_or_ra) {
                        if (route->nexthop.family == AF_INET)
                                buf = strdup("gw: _dhcp4");
                        else if (route->nexthop.family == AF_INET6)
                                buf = strdup("gw: _ipv6ra");
                        else
                                buf = strdup("gw: _dhcp");
                } else
                        buf = strdup("gw: n/a");
                if (!buf)
                        return -ENOMEM;

                *ret = TAKE_PTR(buf);
                return 0;
        }

        RouteNextHop *nh;
        ORDERED_SET_FOREACH(nh, route->nexthops) {
                const char *s = in_addr_is_set(nh->family, &nh->gw) ? IN_ADDR_TO_STRING(nh->family, &nh->gw) : NULL;

                if (nh->ifindex > 0)
                        r = strextendf_with_separator(&buf, ",", "%s@%i:%"PRIu32, strempty(s), nh->ifindex, nh->weight + 1);
                else if (nh->ifname)
                        r = strextendf_with_separator(&buf, ",", "%s@%s:%"PRIu32, strempty(s), nh->ifname, nh->weight + 1);
                else
                        r = strextendf_with_separator(&buf, ",", "%s:%"PRIu32, strempty(s), nh->weight + 1);
                if (r < 0)
                        return r;
        }

        char *p = strjoin("gw: ", strna(buf));
        if (!p)
                return -ENOMEM;

        *ret = p;
        return 0;
}

static int append_nexthop_one(const Route *route, const RouteNextHop *nh, struct rtattr **rta, size_t offset) {
        struct rtnexthop *rtnh;
        struct rtattr *new_rta;
        int r;

        assert(route);
        assert(IN_SET(route->family, AF_INET, AF_INET6));
        assert(nh);
        assert(rta);
        assert(*rta);

        new_rta = realloc(*rta, RTA_ALIGN((*rta)->rta_len) + RTA_SPACE(sizeof(struct rtnexthop)));
        if (!new_rta)
                return -ENOMEM;
        *rta = new_rta;

        rtnh = (struct rtnexthop *)((uint8_t *) *rta + offset);
        *rtnh = (struct rtnexthop) {
                .rtnh_len = sizeof(*rtnh),
                .rtnh_ifindex = nh->ifindex,
                .rtnh_hops = nh->weight,
        };

        (*rta)->rta_len += sizeof(struct rtnexthop);

        if (nh->family == route->family) {
                r = rtattr_append_attribute(rta, RTA_GATEWAY, &nh->gw, FAMILY_ADDRESS_SIZE(nh->family));
                if (r < 0)
                        goto clear;

                rtnh = (struct rtnexthop *)((uint8_t *) *rta + offset);
                rtnh->rtnh_len += RTA_SPACE(FAMILY_ADDRESS_SIZE(nh->family));

        } else if (nh->family == AF_INET6) {
                assert(route->family == AF_INET);

                r = rtattr_append_attribute(rta, RTA_VIA,
                                            &(RouteVia) {
                                                    .family = nh->family,
                                                    .address = nh->gw,
                                            }, sizeof(RouteVia));
                if (r < 0)
                        goto clear;

                rtnh = (struct rtnexthop *)((uint8_t *) *rta + offset);
                rtnh->rtnh_len += RTA_SPACE(sizeof(RouteVia));

        } else if (nh->family == AF_INET)
                assert_not_reached();

        return 0;

clear:
        (*rta)->rta_len -= sizeof(struct rtnexthop);
        return r;
}

static int netlink_message_append_multipath_route(const Route *route, sd_netlink_message *message) {
        _cleanup_free_ struct rtattr *rta = NULL;
        size_t offset;
        int r;

        assert(route);
        assert(message);

        rta = new(struct rtattr, 1);
        if (!rta)
                return -ENOMEM;

        *rta = (struct rtattr) {
                .rta_type = RTA_MULTIPATH,
                .rta_len = RTA_LENGTH(0),
        };
        offset = (uint8_t *) RTA_DATA(rta) - (uint8_t *) rta;

        if (ordered_set_isempty(route->nexthops)) {
                r = append_nexthop_one(route, &route->nexthop, &rta, offset);
                if (r < 0)
                        return r;

        } else {
                RouteNextHop *nh;
                ORDERED_SET_FOREACH(nh, route->nexthops) {
                        struct rtnexthop *rtnh;

                        r = append_nexthop_one(route, nh, &rta, offset);
                        if (r < 0)
                                return r;

                        rtnh = (struct rtnexthop *)((uint8_t *) rta + offset);
                        offset = (uint8_t *) RTNH_NEXT(rtnh) - (uint8_t *) rta;
                }
        }

        return sd_netlink_message_append_data(message, RTA_MULTIPATH, RTA_DATA(rta), RTA_PAYLOAD(rta));
}

int route_nexthops_set_netlink_message(const Route *route, sd_netlink_message *message) {
        int r;

        assert(route);
        assert(IN_SET(route->family, AF_INET, AF_INET6));
        assert(message);

        if (route->nexthop_id != 0)
                return sd_netlink_message_append_u32(message, RTA_NH_ID, route->nexthop_id);

        if (route_is_reject(route))
                return 0;

        /* We request IPv6 multipath routes separately. Even though, if weight is non-zero, we need to use
         * RTA_MULTIPATH, as we have no way to specify the weight of the nexthop. */
        if (ordered_set_isempty(route->nexthops) && route->nexthop.weight == 0) {

                if (in_addr_is_set(route->nexthop.family, &route->nexthop.gw)) {
                        if (route->nexthop.family == route->family)
                                r = netlink_message_append_in_addr_union(message, RTA_GATEWAY, route->nexthop.family, &route->nexthop.gw);
                        else {
                                assert(route->family == AF_INET);
                                r = sd_netlink_message_append_data(message, RTA_VIA,
                                                                   &(const RouteVia) {
                                                                           .family = route->nexthop.family,
                                                                           .address = route->nexthop.gw,
                                                                   }, sizeof(RouteVia));
                        }
                        if (r < 0)
                                return r;
                }

                assert(route->nexthop.ifindex > 0);
                return sd_netlink_message_append_u32(message, RTA_OIF, route->nexthop.ifindex);
        }

        return netlink_message_append_multipath_route(route, message);
}

static int route_parse_nexthops(Route *route, const struct rtnexthop *rtnh, size_t size) {
        _cleanup_ordered_set_free_ OrderedSet *nexthops = NULL;
        int r;

        assert(route);
        assert(IN_SET(route->family, AF_INET, AF_INET6));
        assert(rtnh);

        if (size < sizeof(struct rtnexthop))
                return -EBADMSG;

        for (; size >= sizeof(struct rtnexthop); ) {
                _cleanup_(route_nexthop_freep) RouteNextHop *nh = NULL;

                if (NLMSG_ALIGN(rtnh->rtnh_len) > size)
                        return -EBADMSG;

                if (rtnh->rtnh_len < sizeof(struct rtnexthop))
                        return -EBADMSG;

                nh = new(RouteNextHop, 1);
                if (!nh)
                        return -ENOMEM;

                *nh = (RouteNextHop) {
                        .ifindex = rtnh->rtnh_ifindex,
                        .weight = rtnh->rtnh_hops,
                };

                if (rtnh->rtnh_len > sizeof(struct rtnexthop)) {
                        size_t len = rtnh->rtnh_len - sizeof(struct rtnexthop);
                        bool have_gw = false;

                        for (struct rtattr *attr = RTNH_DATA(rtnh); RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {

                                switch (attr->rta_type) {
                                case RTA_GATEWAY:
                                        if (have_gw)
                                                return -EBADMSG;

                                        if (attr->rta_len != RTA_LENGTH(FAMILY_ADDRESS_SIZE(route->family)))
                                                return -EBADMSG;

                                        nh->family = route->family;
                                        memcpy(&nh->gw, RTA_DATA(attr), FAMILY_ADDRESS_SIZE(nh->family));
                                        have_gw = true;
                                        break;

                                case RTA_VIA:
                                        if (have_gw)
                                                return -EBADMSG;

                                        if (route->family != AF_INET)
                                                return -EBADMSG;

                                        if (attr->rta_len != RTA_LENGTH(sizeof(RouteVia)))
                                                return -EBADMSG;

                                        RouteVia *via = RTA_DATA(attr);
                                        if (via->family != AF_INET6)
                                                return -EBADMSG;

                                        nh->family = via->family;
                                        nh->gw = via->address;
                                        have_gw = true;
                                        break;
                                }
                        }
                }

                r = ordered_set_ensure_put(&nexthops, &route_nexthop_hash_ops, nh);
                assert(r != 0);
                if (r > 0)
                        TAKE_PTR(nh);
                else if (r != -EEXIST)
                        return r;

                size -= NLMSG_ALIGN(rtnh->rtnh_len);
                rtnh = RTNH_NEXT(rtnh);
        }

        ordered_set_free(route->nexthops);
        route->nexthops = TAKE_PTR(nexthops);
        return 0;
}

int route_nexthops_read_netlink_message(Route *route, sd_netlink_message *message) {
        int r;

        assert(route);
        assert(message);

        r = sd_netlink_message_read_u32(message, RTA_NH_ID, &route->nexthop_id);
        if (r < 0 && r != -ENODATA)
                return log_warning_errno(r, "rtnl: received route message with invalid nexthop id, ignoring: %m");

        if (route->nexthop_id != 0 || route_is_reject(route))
                /* IPv6 routes with reject type are always assigned to the loopback interface. See kernel's
                 * fib6_nh_init() in net/ipv6/route.c. However, we'd like to make it consistent with IPv4
                 * routes. Hence, skip reading of RTA_OIF. */
                return 0;

        uint32_t ifindex;
        r = sd_netlink_message_read_u32(message, RTA_OIF, &ifindex);
        if (r >= 0)
                route->nexthop.ifindex = (int) ifindex;
        else if (r != -ENODATA)
                return log_warning_errno(r, "rtnl: could not get ifindex from route message, ignoring: %m");

        if (route->nexthop.ifindex > 0) {
                r = netlink_message_read_in_addr_union(message, RTA_GATEWAY, route->family, &route->nexthop.gw);
                if (r >= 0) {
                        route->nexthop.family = route->family;
                        return 0;
                }
                if (r != -ENODATA)
                        return log_warning_errno(r, "rtnl: received route message without valid gateway, ignoring: %m");

                if (route->family != AF_INET)
                        return 0;

                RouteVia via;
                r = sd_netlink_message_read(message, RTA_VIA, sizeof(via), &via);
                if (r >= 0) {
                        route->nexthop.family = via.family;
                        route->nexthop.gw = via.address;
                        return 0;
                }
                if (r != -ENODATA)
                        return log_warning_errno(r, "rtnl: received route message without valid gateway, ignoring: %m");

                return 0;
        }

        size_t rta_len;
        _cleanup_free_ void *rta = NULL;
        r = sd_netlink_message_read_data(message, RTA_MULTIPATH, &rta_len, &rta);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return log_warning_errno(r, "rtnl: failed to read RTA_MULTIPATH attribute, ignoring: %m");

        r = route_parse_nexthops(route, rta, rta_len);
        if (r < 0)
                return log_warning_errno(r, "rtnl: failed to parse RTA_MULTIPATH attribute, ignoring: %m");

        return 0;
}

#define log_route_section(route, fmt, ...)                              \
        ({                                                              \
                const Route *_route = (route);                          \
                log_section_warning_errno(                              \
                                _route ? _route->section : NULL,        \
                                SYNTHETIC_ERRNO(EINVAL),                \
                                fmt " Ignoring [Route] section.",       \
                                ##__VA_ARGS__);                         \
        })

int route_section_verify_nexthops(Route *route) {
        assert(route);
        assert(route->section);

        if (route->gateway_from_dhcp_or_ra) {
                assert(route->network);

                if (route->nexthop.family == AF_UNSPEC)
                        /* When deprecated Gateway=_dhcp is set, then assume gateway family based on other settings. */
                        switch (route->family) {
                        case AF_UNSPEC:
                                log_section_warning(route->section,
                                                    "Deprecated value \"_dhcp\" is specified for Gateway=. "
                                                    "Please use \"_dhcp4\" or \"_ipv6ra\" instead. Assuming \"_dhcp4\".");

                                route->nexthop.family = route->family = AF_INET;
                                break;
                        case AF_INET:
                        case AF_INET6:
                                log_section_warning(route->section,
                                                    "Deprecated value \"_dhcp\" is specified for Gateway=. "
                                                    "Assuming \"%s\" based on Destination=, Source=, or PreferredSource= setting.",
                                                    route->family == AF_INET ? "_dhcp4" : "_ipv6ra");

                                route->nexthop.family = route->family;
                                break;
                        default:
                                return log_route_section(route, "Invalid route family.");
                        }

                if (route->nexthop.family == AF_INET && !FLAGS_SET(route->network->dhcp, ADDRESS_FAMILY_IPV4))
                        return log_route_section(route, "Gateway=\"_dhcp4\" is specified but DHCPv4 client is disabled.");

                if (route->nexthop.family == AF_INET6 && route->network->ndisc == 0)
                        return log_route_section(route, "Gateway=\"_ipv6ra\" is specified but IPv6AcceptRA= is disabled.");
        }

        /* When only Gateway= is specified, assume the route family based on the Gateway address. */
        if (route->family == AF_UNSPEC)
                route->family = route->nexthop.family;

        if (route->family == AF_UNSPEC) {
                assert(route->section);

                return log_route_section(route, "Route section without Gateway=, Destination=, Source=, or PreferredSource= field configured.");
        }

        if (route->gateway_onlink < 0 && in_addr_is_set(route->nexthop.family, &route->nexthop.gw) &&
            route->network && ordered_hashmap_isempty(route->network->addresses_by_section)) {
                /* If no address is configured, in most cases the gateway cannot be reachable.
                 * TODO: we may need to improve the condition above. */
                log_section_warning(route->section, "Gateway= without static address configured. Enabling GatewayOnLink= option.");
                route->gateway_onlink = true;
        }

        if (route->gateway_onlink >= 0)
                SET_FLAG(route->flags, RTNH_F_ONLINK, route->gateway_onlink);

        if (route->family == AF_INET6) {
                if (route->nexthop.family == AF_INET)
                        return log_route_section(route, "IPv4 gateway is configured for IPv6 route.");

                RouteNextHop *nh;
                ORDERED_SET_FOREACH(nh, route->nexthops)
                        if (nh->family == AF_INET)
                                return log_route_section(route, "IPv4 multipath route is specified for IPv6 route.");
        }

        if (route->nexthop_id != 0 &&
            (route->gateway_from_dhcp_or_ra ||
             in_addr_is_set(route->nexthop.family, &route->nexthop.gw) ||
             !ordered_set_isempty(route->nexthops)))
                return log_route_section(route, "NextHopId= cannot be specified with Gateway= or MultiPathRoute=.");

        if (route_is_reject(route) &&
            (route->gateway_from_dhcp_or_ra ||
             in_addr_is_set(route->nexthop.family, &route->nexthop.gw) ||
             !ordered_set_isempty(route->nexthops)))
                return log_route_section(route, "Reject type route cannot be specified with Gateway= or MultiPathRoute=.");

        if ((route->gateway_from_dhcp_or_ra ||
             in_addr_is_set(route->nexthop.family, &route->nexthop.gw)) &&
            !ordered_set_isempty(route->nexthops))
                return log_route_section(route, "Gateway= cannot be specified with MultiPathRoute=.");

        if (ordered_set_size(route->nexthops) == 1) {
                _cleanup_(route_nexthop_freep) RouteNextHop *nh = ordered_set_steal_first(route->nexthops);

                route_nexthop_done(&route->nexthop);
                route->nexthop = TAKE_STRUCT(*nh);

                assert(ordered_set_isempty(route->nexthops));
                route->nexthops = ordered_set_free(route->nexthops);
        }

        return 0;
}

int config_parse_gateway(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype, /* 0 : only address is accepted, 1 : also supports an empty string, _dhcp, and friends. */
                const char *rvalue,
                void *data,
                void *userdata) {

        Route *route = ASSERT_PTR(userdata);
        int r;

        if (ltype) {
                if (isempty(rvalue)) {
                        route->gateway_from_dhcp_or_ra = false;
                        route->nexthop.family = AF_UNSPEC;
                        route->nexthop.gw = IN_ADDR_NULL;
                        return 1;
                }

                if (streq(rvalue, "_dhcp")) {
                        route->gateway_from_dhcp_or_ra = true;
                        route->nexthop.family = AF_UNSPEC;
                        route->nexthop.gw = IN_ADDR_NULL;
                        return 1;
                }

                if (streq(rvalue, "_dhcp4")) {
                        route->gateway_from_dhcp_or_ra = true;
                        route->nexthop.family = AF_INET;
                        route->nexthop.gw = IN_ADDR_NULL;
                        return 1;
                }

                if (streq(rvalue, "_ipv6ra")) {
                        route->gateway_from_dhcp_or_ra = true;
                        route->nexthop.family = AF_INET6;
                        route->nexthop.gw = IN_ADDR_NULL;
                        return 1;
                }
        }

        assert(rvalue);

        r = in_addr_from_string_auto(rvalue, &route->nexthop.family, &route->nexthop.gw);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        route->gateway_from_dhcp_or_ra = false;
        return 1;
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

        uint32_t id, *p = ASSERT_PTR(data);
        int r;

        if (isempty(rvalue)) {
                *p = 0;
                return 1;
        }

        r = safe_atou32(rvalue, &id);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);
        if (id == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid nexthop ID, ignoring assignment: %s", rvalue);
                return 0;
        }

        *p = id;
        return 1;
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

        _cleanup_(route_nexthop_freep) RouteNextHop *nh = NULL;
        _cleanup_free_ char *word = NULL;
        OrderedSet **nexthops = ASSERT_PTR(data);
        const char *p;
        char *dev;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *nexthops = ordered_set_free(*nexthops);
                return 1;
        }

        nh = new0(RouteNextHop, 1);
        if (!nh)
                return log_oom();

        p = rvalue;
        r = extract_first_word(&p, &word, NULL, 0);
        if (r <= 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        dev = strchr(word, '@');
        if (dev) {
                *dev++ = '\0';

                r = parse_ifindex(dev);
                if (r > 0)
                        nh->ifindex = r;
                else {
                        if (!ifname_valid_full(dev, IFNAME_VALID_ALTERNATIVE)) {
                                log_syntax(unit, LOG_WARNING, filename, line, 0,
                                           "Invalid interface name '%s' in %s=, ignoring: %s", dev, lvalue, rvalue);
                                return 0;
                        }

                        nh->ifname = strdup(dev);
                        if (!nh->ifname)
                                return log_oom();
                }
        }

        r = in_addr_from_string_auto(word, &nh->family, &nh->gw);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid multipath route gateway '%s', ignoring assignment: %m", rvalue);
                return 0;
        }

        if (!isempty(p)) {
                r = safe_atou32(p, &nh->weight);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid multipath route weight, ignoring assignment: %s", p);
                        return 0;
                }
                /* ip command takes weight in the range 1…255, while kernel takes the value in the
                 * range 0…254. MultiPathRoute= setting also takes weight in the same range which ip
                 * command uses, then networkd decreases by one and stores it to match the range which
                 * kernel uses. */
                if (nh->weight == 0 || nh->weight > 256) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid multipath route weight, ignoring assignment: %s", p);
                        return 0;
                }
                nh->weight--;
        }

        r = ordered_set_ensure_put(nexthops, &route_nexthop_hash_ops, nh);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to store multipath route, ignoring assignment: %m");
                return 0;
        }

        TAKE_PTR(nh);
        return 1;
}
