/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/


#include "networkd.h"
#include "networkd-link.h"

#include "util.h"
#include "conf-parser.h"

int route_new_static(Network *network, unsigned section, Route **ret) {
        _cleanup_route_free_ Route *route = NULL;

        if (section) {
                route = hashmap_get(network->routes_by_section,
                                    UINT_TO_PTR(section));
                if (route) {
                        *ret = route;
                        route = NULL;

                        return 0;
                }
        }

        route = new0(Route, 1);
        if (!route)
                return -ENOMEM;

        route->family = AF_UNSPEC;
        route->scope = RT_SCOPE_UNIVERSE;
        route->protocol = RTPROT_STATIC;

        route->network = network;

        LIST_PREPEND(routes, network->static_routes, route);

        if (section) {
                route->section = section;
                hashmap_put(network->routes_by_section,
                            UINT_TO_PTR(route->section), route);
        }

        *ret = route;
        route = NULL;

        return 0;
}

int route_new_dynamic(Route **ret, unsigned char rtm_protocol) {
        _cleanup_route_free_ Route *route = NULL;

        route = new0(Route, 1);
        if (!route)
                return -ENOMEM;

        route->family = AF_UNSPEC;
        route->scope = RT_SCOPE_UNIVERSE;
        route->protocol = rtm_protocol;

        *ret = route;
        route = NULL;

        return 0;
}

void route_free(Route *route) {
        if (!route)
                return;

        if (route->network) {
                LIST_REMOVE(routes, route->network->static_routes, route);

                if (route->section)
                        hashmap_remove(route->network->routes_by_section,
                                       UINT_TO_PTR(route->section));
        }

        free(route);
}

int route_drop(Route *route, Link *link,
               sd_rtnl_message_handler_t callback) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(route->family == AF_INET || route->family == AF_INET6);

        r = sd_rtnl_message_new_route(link->manager->rtnl, &req,
                                      RTM_DELROUTE, route->family,
                                      route->protocol);
        if (r < 0)
                return log_error_errno(r, "Could not create RTM_DELROUTE message: %m");

        if (!in_addr_is_null(route->family, &route->in_addr)) {
                if (route->family == AF_INET)
                        r = sd_rtnl_message_append_in_addr(req, RTA_GATEWAY, &route->in_addr.in);
                else if (route->family == AF_INET6)
                        r = sd_rtnl_message_append_in6_addr(req, RTA_GATEWAY, &route->in_addr.in6);
                if (r < 0)
                        return log_error_errno(r, "Could not append RTA_GATEWAY attribute: %m");
        }

        if (route->dst_prefixlen) {
                if (route->family == AF_INET)
                        r = sd_rtnl_message_append_in_addr(req, RTA_DST, &route->dst_addr.in);
                else if (route->family == AF_INET6)
                        r = sd_rtnl_message_append_in6_addr(req, RTA_DST, &route->dst_addr.in6);
                if (r < 0)
                        return log_error_errno(r, "Could not append RTA_DST attribute: %m");

                r = sd_rtnl_message_route_set_dst_prefixlen(req, route->dst_prefixlen);
                if (r < 0)
                        return log_error_errno(r, "Could not set destination prefix length: %m");
        }

        if (route->src_prefixlen) {
                if (route->family == AF_INET)
                        r = sd_rtnl_message_append_in_addr(req, RTA_SRC, &route->src_addr.in);
                else if (route->family == AF_INET6)
                        r = sd_rtnl_message_append_in6_addr(req, RTA_SRC, &route->src_addr.in6);
                if (r < 0)
                        return log_error_errno(r, "Could not append RTA_DST attribute: %m");

                r = sd_rtnl_message_route_set_src_prefixlen(req, route->src_prefixlen);
                if (r < 0)
                        return log_error_errno(r, "Could not set source prefix length: %m");
        }

        if (!in_addr_is_null(route->family, &route->prefsrc_addr)) {
                if (route->family == AF_INET)
                        r = sd_rtnl_message_append_in_addr(req, RTA_PREFSRC, &route->prefsrc_addr.in);
                else if (route->family == AF_INET6)
                        r = sd_rtnl_message_append_in6_addr(req, RTA_PREFSRC, &route->prefsrc_addr.in6);
                if (r < 0)
                        return log_error_errno(r, "Could not append RTA_PREFSRC attribute: %m");
        }

        r = sd_rtnl_message_route_set_scope(req, route->scope);
        if (r < 0)
                return log_error_errno(r, "Could not set scope: %m");

        r = sd_rtnl_message_append_u32(req, RTA_PRIORITY, route->metrics);
        if (r < 0)
                return log_error_errno(r, "Could not append RTA_PRIORITY attribute: %m");

        r = sd_rtnl_message_append_u32(req, RTA_OIF, link->ifindex);
        if (r < 0)
                return log_error_errno(r, "Could not append RTA_OIF attribute: %m");

        r = sd_rtnl_call_async(link->manager->rtnl, req, callback, link, 0, NULL);
        if (r < 0)
                return log_error_errno(r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

int route_configure(Route *route, Link *link,
                    sd_rtnl_message_handler_t callback) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(route->family == AF_INET || route->family == AF_INET6);

        r = sd_rtnl_message_new_route(link->manager->rtnl, &req,
                                      RTM_NEWROUTE, route->family,
                                      route->protocol);
        if (r < 0)
                return log_error_errno(r, "Could not create RTM_NEWROUTE message: %m");

        if (!in_addr_is_null(route->family, &route->in_addr)) {
                if (route->family == AF_INET)
                        r = sd_rtnl_message_append_in_addr(req, RTA_GATEWAY, &route->in_addr.in);
                else if (route->family == AF_INET6)
                        r = sd_rtnl_message_append_in6_addr(req, RTA_GATEWAY, &route->in_addr.in6);
                if (r < 0)
                        return log_error_errno(r, "Could not append RTA_GATEWAY attribute: %m");
        }

        if (route->dst_prefixlen) {
                if (route->family == AF_INET)
                        r = sd_rtnl_message_append_in_addr(req, RTA_DST, &route->dst_addr.in);
                else if (route->family == AF_INET6)
                        r = sd_rtnl_message_append_in6_addr(req, RTA_DST, &route->dst_addr.in6);
                if (r < 0)
                        return log_error_errno(r, "Could not append RTA_DST attribute: %m");

                r = sd_rtnl_message_route_set_dst_prefixlen(req, route->dst_prefixlen);
                if (r < 0)
                        return log_error_errno(r, "Could not set destination prefix length: %m");
        }

        if (route->src_prefixlen) {
                if (route->family == AF_INET)
                        r = sd_rtnl_message_append_in_addr(req, RTA_SRC, &route->src_addr.in);
                else if (route->family == AF_INET6)
                        r = sd_rtnl_message_append_in6_addr(req, RTA_SRC, &route->src_addr.in6);
                if (r < 0)
                        return log_error_errno(r, "Could not append RTA_SRC attribute: %m");

                r = sd_rtnl_message_route_set_src_prefixlen(req, route->src_prefixlen);
                if (r < 0)
                        return log_error_errno(r, "Could not set source prefix length: %m");
        }

        if (!in_addr_is_null(route->family, &route->prefsrc_addr)) {
                if (route->family == AF_INET)
                        r = sd_rtnl_message_append_in_addr(req, RTA_PREFSRC, &route->prefsrc_addr.in);
                else if (route->family == AF_INET6)
                        r = sd_rtnl_message_append_in6_addr(req, RTA_PREFSRC, &route->prefsrc_addr.in6);
                if (r < 0)
                        return log_error_errno(r, "Could not append RTA_PREFSRC attribute: %m");
        }

        r = sd_rtnl_message_route_set_scope(req, route->scope);
        if (r < 0)
                return log_error_errno(r, "Could not set scope: %m");

        r = sd_rtnl_message_append_u32(req, RTA_PRIORITY, route->metrics);
        if (r < 0)
                return log_error_errno(r, "Could not append RTA_PRIORITY attribute: %m");

        r = sd_rtnl_message_append_u32(req, RTA_OIF, link->ifindex);
        if (r < 0)
                return log_error_errno(r, "Could not append RTA_OIF attribute: %m");

        r = sd_rtnl_call_async(link->manager->rtnl, req, callback, link, 0, NULL);
        if (r < 0)
                return log_error_errno(r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

int config_parse_gateway(const char *unit,
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
        _cleanup_route_free_ Route *n = NULL;
        union in_addr_union buffer;
        int r, f;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(section, "Network")) {
                /* we are not in an Route section, so treat
                 * this as the special '0' section */
                section_line = 0;
        }

        r = route_new_static(network, section_line, &n);
        if (r < 0)
                return r;

        r = in_addr_from_string_auto(rvalue, &f, &buffer);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Route is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        n->family = f;
        n->in_addr = buffer;
        n = NULL;

        return 0;
}

int config_parse_destination(const char *unit,
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
        _cleanup_route_free_ Route *n = NULL;
        const char *address, *e;
        union in_addr_union buffer;
        unsigned char prefixlen;
        int r, f;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, section_line, &n);
        if (r < 0)
                return r;

        /* Destination|Source=address/prefixlen */

        /* address */
        e = strchr(rvalue, '/');
        if (e)
                address = strndupa(rvalue, e - rvalue);
        else
                address = rvalue;

        r = in_addr_from_string_auto(address, &f, &buffer);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Destination is invalid, ignoring assignment: %s", address);
                return 0;
        }

        if (f != AF_INET && f != AF_INET6) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Unknown address family, ignoring assignment: %s", address);
                return 0;
        }

        /* prefixlen */
        if (e) {
                r = safe_atou8(e + 1, &prefixlen);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Route destination prefix length is invalid, ignoring assignment: %s", e + 1);
                        return 0;
                }
        } else {
                switch (f) {
                        case AF_INET:
                                prefixlen = 32;
                                break;
                        case AF_INET6:
                                prefixlen = 128;
                                break;
                }
        }

        n->family = f;
        if (streq(lvalue, "Destination")) {
                n->dst_addr = buffer;
                n->dst_prefixlen = prefixlen;
        } else if (streq(lvalue, "Source")) {
                n->src_addr = buffer;
                n->src_prefixlen = prefixlen;
        } else
                assert_not_reached(lvalue);

        n = NULL;

        return 0;
}

int config_parse_route_priority(const char *unit,
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
        _cleanup_route_free_ Route *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, section_line, &n);
        if (r < 0)
                return r;

        r = config_parse_unsigned(unit, filename, line, section,
                                  section_line, lvalue, ltype,
                                  rvalue, &n->metrics, userdata);
        if (r < 0)
                return r;

        n = NULL;

        return 0;
}

int config_parse_route_scope(const char *unit,
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
        _cleanup_route_free_ Route *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, section_line, &n);
        if (r < 0)
                return r;

        if (streq(rvalue, "host"))
                n->scope = RT_SCOPE_HOST;
        else if (streq(rvalue, "link"))
                n->scope = RT_SCOPE_LINK;
        else if (streq(rvalue, "global"))
                n->scope = RT_SCOPE_UNIVERSE;
        else {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Unknown route scope: %s", rvalue);
                return 0;
        }

        n = NULL;

        return 0;
}
