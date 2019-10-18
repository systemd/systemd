/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */

#include "alloc-util.h"
#include "conf-parser.h"
#include "in-addr-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-route.h"
#include "networkd-multipath-route.h"
#include "networkd-route.h"
#include "netlink-util.h"
#include "ordered-set.h"
#include "parse-util.h"
#include "set.h"
#include "string-table.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "sysctl-util.h"
#include "util.h"

void multipath_route_free(MultiPathRoute *route) {
        if (!route)
                return;

        if (route->network)
                if (route->section)
                        ordered_hashmap_remove(route->network->multipath_routes_by_section, route->section);

        network_config_section_free(route->section);
        free(route);
}

int multipath_route_new(MultiPathRoute **ret) {
        MultiPathRoute *route;

        route = new0(MultiPathRoute, 1);
        if (!route)
                return -ENOMEM;

        *ret = TAKE_PTR(route);

        return 0;
}

static int multipath_route_new_static(Network *network, const char *filename,
                                      unsigned section_line, MultiPathRoute **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(multipath_route_freep) MultiPathRoute *route = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(!!filename == (section_line > 0));

        if (filename) {
                r = network_config_section_new(filename, section_line, &n);
                if (r < 0)
                        return r;

                if (section_line) {
                        route = ordered_hashmap_get(network->multipath_routes_by_section, n);
                        if(route) {
                                *ret = TAKE_PTR(route);

                                return 0;
                        }
                }
        }

        r = multipath_route_new(&route);
        if (r < 0)
                return r;

        route->network = network;

       if (filename) {
                route->section = TAKE_PTR(n);

                r = ordered_hashmap_ensure_allocated(&network->multipath_routes_by_section, &network_config_hash_ops);
                if (r < 0)
                        return r;

                r = ordered_hashmap_put(network->multipath_routes_by_section, route->section, route);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(route);

        return 0;
}

static int multipath_route_add_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -ESRCH)
                log_link_warning_errno(link, r, "Could not add multipath route: %m");

        return 1;
}

int multipath_route_configure(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        _cleanup_free_ struct rtattr *rta;
        struct rtnexthop *rtnh;
        MultiPathRoute *route;
        Iterator i;
        int r;

        r = sd_rtnl_message_new_route(link->manager->rtnl, &req, RTM_NEWROUTE, AF_INET, 0);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create RTM_NEWROUTE message: %m");

        rta = malloc0(8192UL);
        if (!rta)
                return log_oom();

        rta->rta_type = RTA_MULTIPATH;
        rta->rta_len = RTA_LENGTH(0);
        rtnh = RTA_DATA(rta);

        ORDERED_HASHMAP_FOREACH(route, link->network->multipath_routes_by_section, i) {
                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *gw = NULL;

                        if (!in_addr_is_null(route->family, &route->gw))
                                (void) in_addr_to_string(route->family, &route->gw, &gw);

                        log_link_debug(link, "Configuring route: gw: %s, ifindex:%d, Weight=%d",
                                       strna(gw), route->ifindex, route->weight);
                }

                rtnh->rtnh_len = sizeof(struct rtnexthop);
                rta->rta_len += rtnh->rtnh_len;

                rtnh->rtnh_ifindex = route->ifindex;
                rtnh->rtnh_hops = route->weight;

                if (in_addr_is_null(route->family, &route->gw) == 0) {
                        if (route->family == AF_INET)
                                r = sd_netlink_message_append_attribute(rta, RTA_GATEWAY, &route->gw.in, FAMILY_ADDRESS_SIZE(route->family));
                        else if (route->family == AF_INET6)
                                r = sd_netlink_message_append_attribute(rta, RTA_GATEWAY, &route->gw.in6, FAMILY_ADDRESS_SIZE(route->family));

                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not append RTA_GATEWAY attribute: %m");

                        rtnh->rtnh_len += sizeof(struct rtattr) + FAMILY_ADDRESS_SIZE(route->family);

                        r = sd_rtnl_message_route_set_family(req, route->family);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not set route family: %m");
                }

                rtnh = RTNH_NEXT(rtnh);
        }

        r = sd_netlink_message_append_data(req, RTA_MULTIPATH, RTA_DATA(rta), rta->rta_len);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append RTA_MULTIPATH attribute: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, multipath_route_add_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 1;
}

int config_parse_multipath_gateway(
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
        _cleanup_(multipath_route_freep) MultiPathRoute *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = multipath_route_new_static(network, filename, section_line, &n);
        if (r < 0)
                return r;

        r = in_addr_from_string_auto(rvalue, &n->family, &n->gw);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Invalid %s='%s', ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(n);
        return 0;
}

int config_parse_multipath_weight(
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
        _cleanup_(multipath_route_freep) MultiPathRoute *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = multipath_route_new_static(network, filename, section_line, &n);
        if (r < 0)
                return r;

        r = safe_atou32(rvalue, &n->weight);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Could not parse multipath route weight \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        TAKE_PTR(n);
        return 0;
}

int config_parse_multipath_link(
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
        _cleanup_(multipath_route_freep) MultiPathRoute *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = multipath_route_new_static(network, filename, section_line, &n);
        if (r < 0)
                return r;

        r = parse_ifindex_or_ifname(rvalue, &n->ifindex);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse '%s' interface name, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        n = NULL;

        TAKE_PTR(n);
        return 0;
}
