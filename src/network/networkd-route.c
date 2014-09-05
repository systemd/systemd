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

#include <net/if.h>

#include "networkd.h"
#include "networkd-link.h"

#include "utf8.h"
#include "util.h"
#include "conf-parser.h"
#include "network-internal.h"

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
        if (r < 0) {
                log_error("Could not create RTM_DELROUTE message: %s", strerror(-r));
                return r;
        }

        if (route->family == AF_INET)
                r = sd_rtnl_message_append_in_addr(req, RTA_GATEWAY, &route->in_addr.in);
        else if (route->family == AF_INET6)
                r = sd_rtnl_message_append_in6_addr(req, RTA_GATEWAY, &route->in_addr.in6);
        if (r < 0) {
                log_error("Could not append RTA_GATEWAY attribute: %s", strerror(-r));
                return r;
        }

        if (route->dst_prefixlen) {
                if (route->family == AF_INET)
                        r = sd_rtnl_message_append_in_addr(req, RTA_DST, &route->dst_addr.in);
                else if (route->family == AF_INET6)
                        r = sd_rtnl_message_append_in6_addr(req, RTA_DST, &route->dst_addr.in6);
                if (r < 0) {
                        log_error("Could not append RTA_DST attribute: %s", strerror(-r));
                        return r;
                }

                r = sd_rtnl_message_route_set_dst_prefixlen(req, route->dst_prefixlen);
                if (r < 0) {
                        log_error("Could not set destination prefix length: %s", strerror(-r));
                        return r;
                }
        }

        if (!in_addr_is_null(route->family, &route->prefsrc_addr)) {
                if (route->family == AF_INET)
                        r = sd_rtnl_message_append_in_addr(req, RTA_PREFSRC, &route->prefsrc_addr.in);
                else if (route->family == AF_INET6)
                        r = sd_rtnl_message_append_in6_addr(req, RTA_PREFSRC, &route->prefsrc_addr.in6);
                if (r < 0) {
                        log_error("Could not append RTA_PREFSRC attribute: %s", strerror(-r));
                        return r;
                }
        }

        r = sd_rtnl_message_route_set_scope(req, route->scope);
        if (r < 0) {
                log_error("Could not set scope: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u32(req, RTA_PRIORITY, route->metrics);
        if (r < 0) {
                log_error("Could not append RTA_PRIORITY attribute: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u32(req, RTA_OIF, link->ifindex);
        if (r < 0) {
                log_error("Could not append RTA_OIF attribute: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_call_async(link->manager->rtnl, req, callback, link, 0, NULL);
        if (r < 0) {
                log_error("Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

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
        if (r < 0) {
                log_error("Could not create RTM_NEWROUTE message: %s", strerror(-r));
                return r;
        }

        if (route->family == AF_INET)
                r = sd_rtnl_message_append_in_addr(req, RTA_GATEWAY, &route->in_addr.in);
        else if (route->family == AF_INET6)
                r = sd_rtnl_message_append_in6_addr(req, RTA_GATEWAY, &route->in_addr.in6);
        if (r < 0) {
                log_error("Could not append RTA_GATEWAY attribute: %s", strerror(-r));
                return r;
        }

        if (route->dst_prefixlen) {
                if (route->family == AF_INET)
                        r = sd_rtnl_message_append_in_addr(req, RTA_DST, &route->dst_addr.in);
                else if (route->family == AF_INET6)
                        r = sd_rtnl_message_append_in6_addr(req, RTA_DST, &route->dst_addr.in6);
                if (r < 0) {
                        log_error("Could not append RTA_DST attribute: %s", strerror(-r));
                        return r;
                }

                r = sd_rtnl_message_route_set_dst_prefixlen(req, route->dst_prefixlen);
                if (r < 0) {
                        log_error("Could not set destination prefix length: %s", strerror(-r));
                        return r;
                }
        }

        if (!in_addr_is_null(route->family, &route->prefsrc_addr)) {
                if (route->family == AF_INET)
                        r = sd_rtnl_message_append_in_addr(req, RTA_PREFSRC, &route->prefsrc_addr.in);
                else if (route->family == AF_INET6)
                        r = sd_rtnl_message_append_in6_addr(req, RTA_PREFSRC, &route->prefsrc_addr.in6);
                if (r < 0) {
                        log_error("Could not append RTA_PREFSRC attribute: %s", strerror(-r));
                        return r;
                }
        }

        r = sd_rtnl_message_route_set_scope(req, route->scope);
        if (r < 0) {
                log_error("Could not set scope: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u32(req, RTA_PRIORITY, route->metrics);
        if (r < 0) {
                log_error("Could not append RTA_PRIORITY attribute: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u32(req, RTA_OIF, link->ifindex);
        if (r < 0) {
                log_error("Could not append RTA_OIF attribute: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_call_async(link->manager->rtnl, req, callback, link, 0, NULL);
        if (r < 0) {
                log_error("Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

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
        int r, f;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, section_line, &n);
        if (r < 0)
                return r;

        /* Destination=address/prefixlen */

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

        /* prefixlen */
        if (e) {
                unsigned i;

                r = safe_atou(e + 1, &i);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Route destination prefix length is invalid, ignoring assignment: %s", e + 1);
                        return 0;
                }

                n->dst_prefixlen = (unsigned char) i;
        } else {
                switch (n->family) {
                        case AF_INET:
                                n->dst_prefixlen = 32;
                                break;
                        case AF_INET6:
                                n->dst_prefixlen = 128;
                                break;
                }
        }

        n->family = f;
        n->dst_addr = buffer;
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
