/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/nexthop.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-nexthop.h"
#include "networkd-route.h"
#include "networkd-route-nexthop.h"
#include "parse-util.h"
#include "string-util.h"

static void route_nexthop_done(RouteNextHop *nh) {
        assert(nh);

        nh->ifname = mfree(nh->ifname);
}

void route_nexthops_done(Route *route) {
        assert(route);

        route_nexthop_done(&route->nexthop);
        route->nexthops = ordered_set_free(route->nexthops);
}

RouteNextHop* route_nexthop_free(RouteNextHop *nh) {
        if (!nh)
                return NULL;

        route_nexthop_done(nh);

        return mfree(nh);
}

static int route_nexthop_copy(const RouteNextHop *src, RouteNextHop *dest) {
        assert(src);
        assert(dest);

        *dest = *src;

        dest->ifname = NULL;

        if (src->ifindex == 0)
                return free_and_strdup(&dest->ifname, src->ifname);

        return 0;
}

static int route_nexthop_dup(const RouteNextHop *src, RouteNextHop **ret) {
        _cleanup_(route_nexthop_freep) RouteNextHop *dest = NULL;
        int r;

        assert(src);
        assert(ret);

        dest = newdup(RouteNextHop, src, 1);
        if (!dest)
                return -ENOMEM;

        dest->ifname = NULL;

        if (src->ifindex == 0) {
                r = free_and_strdup(&dest->ifname, src->ifname);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(dest);
        return 0;
}

int route_nexthops_copy(const Route *src, const RouteNextHop *nh, Route *dest) {
        int r;

        assert(src);
        assert(dest);

        if (src->nexthop_id != 0 || route_type_is_reject(src))
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

DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(
        route_nexthop_hash_ops,
        RouteNextHop,
        route_nexthop_hash_func,
        route_nexthop_compare_func,
        route_nexthop_free);

void route_nexthops_hash_func(const Route *route, struct siphash *state) {
        assert(route);

        /* nexthops (id, number of nexthops, nexthop) */
        if (route->nexthop_id != 0 || route_type_is_reject(route)) {
                size_t nhs = 0;
                siphash24_compress_typesafe(nhs, state);
                siphash24_compress_typesafe(route->nexthop_id, state);

        } else if (ordered_set_isempty(route->nexthops)) {
                size_t nhs = 1;
                siphash24_compress_typesafe(nhs, state);
                route_nexthop_hash_func_full(&route->nexthop, state, /* with_weight = */ false);

        } else {
                size_t nhs = ordered_set_size(route->nexthops);
                siphash24_compress_typesafe(nhs, state);

                RouteNextHop *nh;
                ORDERED_SET_FOREACH(nh, route->nexthops)
                        route_nexthop_hash_func(nh, state);
        }
}

int route_nexthops_compare_func(const Route *a, const Route *b) {
        int r;

        assert(a);
        assert(b);

        size_t a_nhs = (a->nexthop_id != 0 || route_type_is_reject(a)) ? 0 : ordered_set_isempty(a->nexthops) ? 1 : ordered_set_size(a->nexthops);
        size_t b_nhs = (b->nexthop_id != 0 || route_type_is_reject(b)) ? 0 : ordered_set_isempty(b->nexthops) ? 1 : ordered_set_size(b->nexthops);
        r = CMP(a_nhs, b_nhs);
        if (r != 0)
                return r;

        if (a_nhs == 0) {
                r = CMP(a->nexthop_id, b->nexthop_id);
                if (r != 0)
                        return r;

        } else if (a_nhs == 1) {
                r = route_nexthop_compare_func_full(&a->nexthop, &b->nexthop, /* with_weight = */ false);
                if (r != 0)
                        return r;

        } else {
                RouteNextHop *nh;
                ORDERED_SET_FOREACH(nh, a->nexthops) {
                        r = CMP(nh, (RouteNextHop*) ordered_set_get(a->nexthops, nh));
                        if (r != 0)
                                return r;
                }
        }

        return 0;
}

int route_nexthops_to_string(const Route *route, char **ret) {
        _cleanup_free_ char *buf = NULL;
        int r;

        assert(route);
        assert(ret);

        if (route->nexthop_id != 0) {
                if (asprintf(&buf, "nexthop: %"PRIu32, route->nexthop_id) < 0)
                        buf = NULL;

        } else if (route_type_is_reject(route))
                buf = strdup("gw: n/a");

        else if (ordered_set_isempty(route->nexthops)) {
                if (in_addr_is_set(route->nexthop.family, &route->nexthop.gw))
                        buf = strjoin("gw: ", IN_ADDR_TO_STRING(route->nexthop.family, &route->nexthop.gw));
                else if (route->gateway_from_dhcp_or_ra) {
                        if (route->nexthop.family == AF_INET)
                                buf = strdup("gw: _dhcp4");
                        else if (route->nexthop.family == AF_INET6)
                                buf = strdup("gw: _ipv6ra");
                        else
                                buf = strdup("gw: _dhcp");

                } else
                        buf = strdup("gw: n/a");
        } else {
                RouteNextHop *nh;

                ORDERED_SET_FOREACH(nh, route->nexthops) {
                        if (nh->ifindex > 0)
                                r = strextendf_with_separator(&buf, ",", "%s@%i:%"PRIu32, IN_ADDR_TO_STRING(nh->family, &nh->gw), nh->ifindex, nh->weight + 1);
                        else if (nh->ifname)
                                r = strextendf_with_separator(&buf, ",", "%s@%s:%"PRIu32, IN_ADDR_TO_STRING(nh->family, &nh->gw), nh->ifname, nh->weight + 1);
                        else
                                r = strextendf_with_separator(&buf, ",", "%s:%"PRIu32, IN_ADDR_TO_STRING(nh->family, &nh->gw), nh->weight + 1);
                        if (r < 0)
                                return r;
                }

                char *p = strjoin("gw: ", buf);
                if (!p)
                        return -ENOMEM;

                free_and_replace(buf, p);
        }
        if (!buf)
                return -ENOMEM;

        *ret = TAKE_PTR(buf);
        return 0;
}

static int route_nexthop_set_ifindex(RouteNextHop *nh, Link *link) {
        assert(nh);
        assert(link);
        assert(link->manager);

        if (nh->ifindex > 0) {
                nh->ifname = mfree(nh->ifname);
                return 0;
        }

        if (nh->ifname && link_get_by_name(link->manager, nh->ifname, &link) < 0)
                return 0;

        nh->ifindex = link->ifindex;
        nh->ifname = mfree(nh->ifname);
        return 1;
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

                if (nexthop_get_by_id(link->manager, route->nexthop_id, &nexthop) < 0)
                        return 0;

                if (!nexthop->blackhole)
                        return 0;

                if (route->type == RTN_BLACKHOLE)
                        return 0;

                route->type = RTN_BLACKHOLE;
                return 1;
        }

        if (route_type_is_reject(route))
                return 0;

        if (ordered_set_isempty(route->nexthops))
                return route_nexthop_set_ifindex(&route->nexthop, link);

        _cleanup_ordered_set_free_ OrderedSet *nexthops = NULL;
        for (;;) {
                _cleanup_(route_nexthop_freep) RouteNextHop *nh = NULL;

                nh = ordered_set_steal_first(route->nexthops);
                if (!nh)
                        break;

                (void) route_nexthop_set_ifindex(nh, link);

                r = ordered_set_ensure_put(&nexthops, &route_nexthop_hash_ops, nh);
                if (r < 0)
                        return r;
                assert(r > 0);

                TAKE_PTR(nh);
        }

        ordered_set_free(route->nexthops);
        route->nexthops = TAKE_PTR(nexthops);

        return 1;
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

        if (!gateway_is_ready(link, onlink, nh->family, &nh->gw))
                return false;

        return true;
}

bool route_nexthops_is_ready_to_configure(const Route *route, Manager *manager) {
        assert(route);
        assert(manager);

        if (route->nexthop_id != 0) {
                struct nexthop_grp *nhg;
                NextHop *nh;

                if (nexthop_get_by_id(manager, route->nexthop_id, &nh) < 0)
                        return false;

                if (!nexthop_exists(nh))
                        return false;

                HASHMAP_FOREACH(nhg, nh->group) {
                        NextHop *g;

                        if (nexthop_get_by_id(manager, nhg->id, &g) < 0)
                                return false;

                        if (!nexthop_exists(g))
                                return false;
                }

                return true;
        }

        if (route_type_is_reject(route))
                return true;

        if (ordered_set_isempty(route->nexthops))
                return route_nexthop_is_ready_to_configure(&route->nexthop, manager, FLAGS_SET(route->flags, RTNH_F_ONLINK));

        RouteNextHop *nh;
        ORDERED_SET_FOREACH(nh, route->nexthops)
                if (!route_nexthop_is_ready_to_configure(nh, manager, FLAGS_SET(route->flags, RTNH_F_ONLINK)))
                        return false;

        return true;
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

        /* We request IPv6 multipath routes separatedly. Even though, if weight is non-zero, we need to use
         * RTA_MULTIPATH, as we have no way to specify the weight of the nexthop. */
        if (ordered_set_isempty(route->nexthops) && route->nexthop.weight == 0) {

                /* Note that unreachable routes do not have RTA_OIF. */
                if (route->nexthop.ifindex == 0)
                        return 0;

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

        if (route->nexthop_id != 0 || route_type_is_reject(route)) {
                /* IPv6 routes with reject type are always assigned to the loopback interface. See kernel's
                 * fib6_nh_init() in net/ipv6/route.c. However, we'd like to manage them by Manager. Hence, set
                 * link to NULL here. */
                route->nexthop.ifindex = 0;
                return 0;
        }

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
        _cleanup_(route_unref_or_set_invalidp) Route *n = NULL;
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
        _cleanup_(route_unref_or_set_invalidp) Route *n = NULL;
        _cleanup_free_ char *word = NULL;
        Network *network = userdata;
        const char *p;
        char *dev;
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
                n->nexthops = ordered_set_free(n->nexthops);
                return 0;
        }

        nh = new0(RouteNextHop, 1);
        if (!nh)
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

        r = ordered_set_ensure_put(&n->nexthops, &route_nexthop_hash_ops, nh);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to store multipath route, ignoring assignment: %m");
                return 0;
        }

        TAKE_PTR(nh);
        TAKE_PTR(n);
        return 0;
}
