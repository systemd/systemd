/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/nexthop.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "netlink-util.h"
#include "networkd-network.h"
#include "networkd-route.h"
#include "networkd-route-nexthop.h"
#include "networkd-route-util.h"
#include "parse-util.h"
#include "string-util.h"

static int append_nexthop_one(Link *link, const Route *route, const MultipathRoute *m, struct rtattr **rta, size_t offset) {
        struct rtnexthop *rtnh;
        struct rtattr *new_rta;
        int r;

        assert(route);
        assert(IN_SET(route->family, AF_INET, AF_INET6));
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

        if (m->gateway.family == route->family) {
                r = rtattr_append_attribute(rta, RTA_GATEWAY, &m->gateway.address, FAMILY_ADDRESS_SIZE(m->gateway.family));
                if (r < 0)
                        goto clear;

                rtnh = (struct rtnexthop *)((uint8_t *) *rta + offset);
                rtnh->rtnh_len += RTA_SPACE(FAMILY_ADDRESS_SIZE(m->gateway.family));

        } else if (m->gateway.family == AF_INET6) {
                assert(route->family == AF_INET);

                r = rtattr_append_attribute(rta, RTA_VIA, &m->gateway, sizeof(RouteVia));
                if (r < 0)
                        goto clear;

                rtnh = (struct rtnexthop *)((uint8_t *) *rta + offset);
                rtnh->rtnh_len += RTA_SPACE(sizeof(RouteVia));

        } else if (m->gateway.family == AF_INET)
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

        MultipathRoute *m;
        ORDERED_SET_FOREACH(m, route->multipath_routes) {
                struct rtnexthop *rtnh;

                r = append_nexthop_one(link, route, m, &rta, offset);
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

        if (ordered_set_isempty(route->multipath_routes)) {

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

        r = rtattr_read_nexthop(rta, rta_len, route->family, &route->multipath_routes);
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

                MultipathRoute *m;
                ORDERED_SET_FOREACH(m, route->multipath_routes)
                        if (m->gateway.family == AF_INET)
                                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                         "%s: IPv4 multipath route is specified for IPv6 route. "
                                                         "Ignoring [Route] section from line %u.",
                                                         route->section->filename, route->section->line);
        }

        if (route->nexthop_id != 0 &&
            (route->gateway_from_dhcp_or_ra ||
             in_addr_is_set(route->gw_family, &route->gw) ||
             !ordered_set_isempty(route->multipath_routes)))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: NextHopId= cannot be specified with Gateway= or MultiPathRoute=. "
                                         "Ignoring [Route] section from line %u.",
                                         route->section->filename, route->section->line);

        if (route_type_is_reject(route) &&
            (route->gateway_from_dhcp_or_ra ||
             in_addr_is_set(route->gw_family, &route->gw) ||
             !ordered_set_isempty(route->multipath_routes)))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: reject type route cannot be specified with Gateway= or MultiPathRoute=. "
                                         "Ignoring [Route] section from line %u.",
                                         route->section->filename, route->section->line);

        if ((route->gateway_from_dhcp_or_ra ||
             in_addr_is_set(route->gw_family, &route->gw)) &&
            !ordered_set_isempty(route->multipath_routes))
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
                        TAKE_PTR(route);
                        return 0;
                }

                if (streq(rvalue, "_dhcp4")) {
                        route->gw_family = AF_INET;
                        route->gateway_from_dhcp_or_ra = true;
                        TAKE_PTR(route);
                        return 0;
                }

                if (streq(rvalue, "_ipv6ra")) {
                        route->gw_family = AF_INET6;
                        route->gateway_from_dhcp_or_ra = true;
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

        _cleanup_(multipath_route_freep) MultipathRoute *m = NULL;
        _cleanup_(route_free_or_set_invalidp) Route *route = NULL;
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

        r = route_new_static(network, filename, section_line, &route);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                route->multipath_routes = ordered_set_free_with_destructor(route->multipath_routes, multipath_route_free);
                TAKE_PTR(route);
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

        r = ordered_set_ensure_put(&route->multipath_routes, NULL, m);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to store multipath route, ignoring assignment: %m");
                return 0;
        }

        TAKE_PTR(m);
        TAKE_PTR(route);
        return 0;
}
