/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/nexthop.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "netlink-util.h"
#include "networkd-network.h"
#include "networkd-nexthop.h"
#include "networkd-route.h"
#include "networkd-route-nexthop.h"
#include "networkd-route-util.h"
#include "parse-util.h"
#include "string-util.h"

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

        ordered_set_free(route->nexthops);
}

static void route_nexthop_hash_func(const RouteNextHop *nh, struct siphash *state) {
        assert(nh);
        assert(state);

        /* See nh_comp() in net/ipv4/fib_semantics.c of the kernel. */

        siphash24_compress_typesafe(nh->family, state);
        if (!IN_SET(nh->family, AF_INET, AF_INET6))
                return;

        in_addr_hash_func(&nh->gw, nh->family, state);
        siphash24_compress_typesafe(nh->weight, state);
        siphash24_compress_typesafe(nh->ifindex, state);
        if (nh->ifindex == 0)
                siphash24_compress_string(nh->ifname, state); /* For Network or Request object. */
}

static int route_nexthop_compare_func(const RouteNextHop *a, const RouteNextHop *b) {
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

        r = CMP(a->weight, b->weight);
        if (r != 0)
                return r;

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

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
        route_nexthop_hash_ops,
        RouteNextHop,
        route_nexthop_hash_func,
        route_nexthop_compare_func,
        route_nexthop_free);

int route_nexthop_get_link(Manager *manager, const RouteNextHop *nh, Link **ret) {
        int r;

        assert(manager);
        assert(nh);

        if (nh->ifindex > 0) {
                r = link_get_by_index(manager, nh->ifindex, ret);
                return r < 0 ? r : 1;
        }
        if (nh->ifname) {
                r = link_get_by_name(manager, nh->ifname, ret);
                return r < 0 ? r : 1;
        }

        if (ret)
                *ret = NULL;
        return 0;
}

static bool route_nexthop_is_ready_to_configure(const RouteNextHop *nh, Link *link, bool onlink) {
        Link *l = NULL;
        int r;

        assert(nh);
        assert(link);

        r = route_nexthop_get_link(link->manager, nh, &l);
        if (r < 0)
                return false;
        if (r > 0)
                link = l;

        if (!link_is_ready_to_configure(link, /* allow_unmanaged = */ true))
                return false;

        /* If the interface is not managed by us, we request that the interface has carrier.
         * That is, ConfigureWithoutCarrier=no is the default even for unamanaged interfaces. */
        if (!link->network && !link_has_carrier(link))
                return false;

        return gateway_is_ready(link, onlink, nh->family, &nh->gw);
}

int route_nexthops_is_ready_to_configure(const Route *route, Link *link) {
        int r;

        assert(route);
        assert(link);

        Manager *manager = ASSERT_PTR(link->manager);

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

        if (route_type_is_reject(route))
                return true;

        if (ordered_set_isempty(route->nexthops))
                return gateway_is_ready(link, FLAGS_SET(route->flags, RTNH_F_ONLINK), route->gw_family, &route->gw);

        RouteNextHop *nh;
        ORDERED_SET_FOREACH(nh, route->nexthops)
                if (!route_nexthop_is_ready_to_configure(nh, link, FLAGS_SET(route->flags, RTNH_F_ONLINK)))
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

        if (route_type_is_reject(route)) {
                buf = strdup("gw: n/a");
                if (!buf)
                        return -ENOMEM;

                *ret = TAKE_PTR(buf);
                return 0;
        }

        if (ordered_set_isempty(route->nexthops)) {
                if (in_addr_is_set(route->gw_family, &route->gw))
                        buf = strjoin("gw: ", IN_ADDR_TO_STRING(route->gw_family, &route->gw));
                else if (route->gateway_from_dhcp_or_ra) {
                        if (route->gw_family == AF_INET)
                                buf = strdup("gw: _dhcp4");
                        else if (route->gw_family == AF_INET6)
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

static int append_nexthop_one(Link *link, const Route *route, const RouteNextHop *nh, struct rtattr **rta, size_t offset) {
        struct rtnexthop *rtnh;
        struct rtattr *new_rta;
        int r;

        assert(route);
        assert(IN_SET(route->family, AF_INET, AF_INET6));
        assert(nh);
        assert(rta);
        assert(*rta);

        if (nh->ifindex <= 0) {
                assert(link);
                assert(link->manager);

                Link *l;
                r = route_nexthop_get_link(link->manager, nh, &l);
                if (r < 0)
                        return r;
                if (r > 0)
                        link = l;
        }

        new_rta = realloc(*rta, RTA_ALIGN((*rta)->rta_len) + RTA_SPACE(sizeof(struct rtnexthop)));
        if (!new_rta)
                return -ENOMEM;
        *rta = new_rta;

        rtnh = (struct rtnexthop *)((uint8_t *) *rta + offset);
        *rtnh = (struct rtnexthop) {
                .rtnh_len = sizeof(*rtnh),
                .rtnh_ifindex = nh->ifindex > 0 ? nh->ifindex : link->ifindex,
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

static int netlink_message_append_multipath_route(Link *link, const Route *route, sd_netlink_message *message) {
        _cleanup_free_ struct rtattr *rta = NULL;
        size_t offset;
        int r;

        assert(route);
        assert(message);

        if (ordered_set_isempty(route->nexthops))
                return 0;

        rta = new(struct rtattr, 1);
        if (!rta)
                return -ENOMEM;

        *rta = (struct rtattr) {
                .rta_type = RTA_MULTIPATH,
                .rta_len = RTA_LENGTH(0),
        };
        offset = (uint8_t *) RTA_DATA(rta) - (uint8_t *) rta;

        RouteNextHop *nh;
        ORDERED_SET_FOREACH(nh, route->nexthops) {
                struct rtnexthop *rtnh;

                r = append_nexthop_one(link, route, nh, &rta, offset);
                if (r < 0)
                        return r;

                rtnh = (struct rtnexthop *)((uint8_t *) rta + offset);
                offset = (uint8_t *) RTNH_NEXT(rtnh) - (uint8_t *) rta;
        }

        return sd_netlink_message_append_data(message, RTA_MULTIPATH, RTA_DATA(rta), RTA_PAYLOAD(rta));
}

int route_nexthops_set_netlink_message(Link *link, const Route *route, sd_netlink_message *message) {
        int r;

        assert(route);
        assert(IN_SET(route->family, AF_INET, AF_INET6));
        assert(message);

        if (route->nexthop_id != 0)
                return sd_netlink_message_append_u32(message, RTA_NH_ID, route->nexthop_id);

        if (route_type_is_reject(route))
                return 0;

        if (ordered_set_isempty(route->nexthops)) {

                if (in_addr_is_set(route->gw_family, &route->gw)) {
                        if (route->gw_family == route->family)
                                r = netlink_message_append_in_addr_union(message, RTA_GATEWAY, route->gw_family, &route->gw);
                        else {
                                assert(route->family == AF_INET);
                                r = sd_netlink_message_append_data(message, RTA_VIA,
                                                                   &(const RouteVia) {
                                                                           .family = route->gw_family,
                                                                           .address = route->gw,
                                                                   }, sizeof(RouteVia));
                        }
                        if (r < 0)
                                return r;
                }

                assert(link);
                return sd_netlink_message_append_u32(message, RTA_OIF, link->ifindex);
        }

        return netlink_message_append_multipath_route(link, route, message);
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

        if (route->nexthop_id != 0 || route_type_is_reject(route))
                /* IPv6 routes with reject type are always assigned to the loopback interface. See kernel's
                 * fib6_nh_init() in net/ipv6/route.c. However, we'd like to make it consistent with IPv4
                 * routes. Hence, skip reading of RTA_OIF. */
                return 0;

        uint32_t ifindex = 0;
        r = sd_netlink_message_read_u32(message, RTA_OIF, &ifindex);
        if (r < 0 && r != -ENODATA)
                return log_warning_errno(r, "rtnl: could not get ifindex from route message, ignoring: %m");

        if (ifindex > 0) {
                r = netlink_message_read_in_addr_union(message, RTA_GATEWAY, route->family, &route->gw);
                if (r >= 0) {
                        route->gw_family = route->family;
                        return 0;
                }
                if (r != -ENODATA)
                        return log_warning_errno(r, "rtnl: received route message without valid gateway, ignoring: %m");

                if (route->family != AF_INET)
                        return 0;

                RouteVia via;
                r = sd_netlink_message_read(message, RTA_VIA, sizeof(via), &via);
                if (r >= 0) {
                        route->gw_family = via.family;
                        route->gw = via.address;
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

int route_section_verify_nexthops(Route *route) {
        assert(route);
        assert(route->section);

        if (route->gateway_from_dhcp_or_ra) {
                assert(route->network);

                if (route->gw_family == AF_UNSPEC)
                        /* When deprecated Gateway=_dhcp is set, then assume gateway family based on other settings. */
                        switch (route->family) {
                        case AF_UNSPEC:
                                log_warning("%s: Deprecated value \"_dhcp\" is specified for Gateway= in [Route] section from line %u. "
                                            "Please use \"_dhcp4\" or \"_ipv6ra\" instead. Assuming \"_dhcp4\".",
                                            route->section->filename, route->section->line);

                                route->gw_family = route->family = AF_INET;
                                break;
                        case AF_INET:
                        case AF_INET6:
                                log_warning("%s: Deprecated value \"_dhcp\" is specified for Gateway= in [Route] section from line %u. "
                                            "Assuming \"%s\" based on Destination=, Source=, or PreferredSource= setting.",
                                            route->section->filename, route->section->line, route->family == AF_INET ? "_dhcp4" : "_ipv6ra");

                                route->gw_family = route->family;
                                break;
                        default:
                                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                         "%s: Invalid route family. Ignoring [Route] section from line %u.",
                                                         route->section->filename, route->section->line);
                        }

                if (route->gw_family == AF_INET && !FLAGS_SET(route->network->dhcp, ADDRESS_FAMILY_IPV4))
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: Gateway=\"_dhcp4\" is specified but DHCPv4 client is disabled. "
                                                 "Ignoring [Route] section from line %u.",
                                                 route->section->filename, route->section->line);

                if (route->gw_family == AF_INET6 && !route->network->ipv6_accept_ra)
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

        if (route->gateway_onlink < 0 && in_addr_is_set(route->gw_family, &route->gw) &&
            route->network && ordered_hashmap_isempty(route->network->addresses_by_section)) {
                /* If no address is configured, in most cases the gateway cannot be reachable.
                 * TODO: we may need to improve the condition above. */
                log_warning("%s: Gateway= without static address configured. "
                            "Enabling GatewayOnLink= option.",
                            route->section->filename);
                route->gateway_onlink = true;
        }

        if (route->gateway_onlink >= 0)
                SET_FLAG(route->flags, RTNH_F_ONLINK, route->gateway_onlink);

        if (route->family == AF_INET6) {
                if (route->gw_family == AF_INET)
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: IPv4 gateway is configured for IPv6 route. "
                                                 "Ignoring [Route] section from line %u.",
                                                 route->section->filename, route->section->line);

                RouteNextHop *nh;
                ORDERED_SET_FOREACH(nh, route->nexthops)
                        if (nh->family == AF_INET)
                                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                         "%s: IPv4 multipath route is specified for IPv6 route. "
                                                         "Ignoring [Route] section from line %u.",
                                                         route->section->filename, route->section->line);
        }

        if (route->nexthop_id != 0 &&
            (route->gateway_from_dhcp_or_ra ||
             in_addr_is_set(route->gw_family, &route->gw) ||
             !ordered_set_isempty(route->nexthops)))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: NextHopId= cannot be specified with Gateway= or MultiPathRoute=. "
                                         "Ignoring [Route] section from line %u.",
                                         route->section->filename, route->section->line);

        if (route_type_is_reject(route) &&
            (route->gateway_from_dhcp_or_ra ||
             in_addr_is_set(route->gw_family, &route->gw) ||
             !ordered_set_isempty(route->nexthops)))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: reject type route cannot be specified with Gateway= or MultiPathRoute=. "
                                         "Ignoring [Route] section from line %u.",
                                         route->section->filename, route->section->line);

        if ((route->gateway_from_dhcp_or_ra ||
             in_addr_is_set(route->gw_family, &route->gw)) &&
            !ordered_set_isempty(route->nexthops))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Gateway= cannot be specified with MultiPathRoute=. "
                                         "Ignoring [Route] section from line %u.",
                                         route->section->filename, route->section->line);

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
        _cleanup_(route_free_or_set_invalidp) Route *route = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(section, "Network")) {
                /* we are not in an Route section, so use line number instead */
                r = route_new_static(network, filename, line, &route);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to allocate route, ignoring assignment: %m");
                        return 0;
                }
        } else {
                r = route_new_static(network, filename, section_line, &route);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to allocate route, ignoring assignment: %m");
                        return 0;
                }

                if (isempty(rvalue)) {
                        route->gateway_from_dhcp_or_ra = false;
                        route->gw_family = AF_UNSPEC;
                        route->gw = IN_ADDR_NULL;
                        TAKE_PTR(route);
                        return 0;
                }

                if (streq(rvalue, "_dhcp")) {
                        route->gateway_from_dhcp_or_ra = true;
                        route->gw_family = AF_UNSPEC;
                        route->gw = IN_ADDR_NULL;
                        TAKE_PTR(route);
                        return 0;
                }

                if (streq(rvalue, "_dhcp4")) {
                        route->gateway_from_dhcp_or_ra = true;
                        route->gw_family = AF_INET;
                        route->gw = IN_ADDR_NULL;
                        TAKE_PTR(route);
                        return 0;
                }

                if (streq(rvalue, "_ipv6ra")) {
                        route->gateway_from_dhcp_or_ra = true;
                        route->gw_family = AF_INET6;
                        route->gw = IN_ADDR_NULL;
                        TAKE_PTR(route);
                        return 0;
                }
        }

        r = in_addr_from_string_auto(rvalue, &route->gw_family, &route->gw);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid %s='%s', ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        route->gateway_from_dhcp_or_ra = false;
        TAKE_PTR(route);
        return 0;
}

int config_parse_route_gateway_onlink(
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

        r = config_parse_tristate(unit, filename, line, section, section_line, lvalue, ltype, rvalue,
                                  &route->gateway_onlink, network);
        if (r <= 0)
                return r;

        TAKE_PTR(route);
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
        _cleanup_(route_free_or_set_invalidp) Route *route = NULL;
        uint32_t id;
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

        if (isempty(rvalue)) {
                route->nexthop_id = 0;
                TAKE_PTR(route);
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

        route->nexthop_id = id;
        TAKE_PTR(route);
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
        _cleanup_(route_free_or_set_invalidp) Route *route = NULL;
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

        r = route_new_static(network, filename, section_line, &route);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                route->nexthops = ordered_set_free(route->nexthops);
                TAKE_PTR(route);
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

        r = ordered_set_ensure_put(&route->nexthops, &route_nexthop_hash_ops, nh);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to store multipath route, ignoring assignment: %m");
                return 0;
        }

        TAKE_PTR(nh);
        TAKE_PTR(route);
        return 0;
}
