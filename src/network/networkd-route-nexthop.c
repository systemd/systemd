/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/nexthop.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "netlink-util.h"
#include "networkd-network.h"
#include "networkd-route.h"
#include "networkd-route-nexthop.h"
#include "parse-util.h"
#include "string-util.h"

int route_section_verify_nexthops(Route *route) {
        assert(route);
        assert(route->section);
        assert(route->network);

        if (route->gateway_from_dhcp_or_ra) {
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
            ordered_hashmap_isempty(route->network->addresses_by_section)) {
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
