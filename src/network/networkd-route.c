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

#include "utf8.h"
#include "util.h"
#include "conf-parser.h"
#include "net-util.h"

int route_new(Network *network, unsigned section, Route **ret) {
        _cleanup_route_free_ Route *route = NULL;

        if (section) {
                uint64_t key = section;

                route = hashmap_get(network->routes_by_section, &key);
                if (route) {
                        *ret = route;
                        route = NULL;

                        return 0;
                }
        }

        route = new0(Route, 1);
        if (!route)
                return -ENOMEM;

        route->network = network;

        LIST_PREPEND(routes, network->routes, route);

        if (section) {
                route->section = section;
                hashmap_put(network->routes_by_section, &route->section, route);
        }

        *ret = route;
        route = NULL;

        return 0;
}

void route_free(Route *route) {
        if (!route)
                return;

        LIST_REMOVE(routes, route->network->routes, route);

        if (route->section)
                hashmap_remove(route->network->routes_by_section,
                               &route->section);

        free(route);
}

int route_configure(Route *route, Link *link,
                    sd_rtnl_message_handler_t callback) {
        _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(route->family == AF_INET || route->family == AF_INET6);

        r = sd_rtnl_message_route_new(RTM_NEWROUTE, route->family, route->dst_prefixlen,
                                      0, 0, RT_TABLE_MAIN, RT_SCOPE_UNIVERSE,
                                      RTPROT_BOOT, RTN_UNICAST, 0, &req);
        if (r < 0) {
                log_error("Could not create RTM_NEWROUTE message: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append(req, RTA_GATEWAY, &route->in_addr);
        if (r < 0) {
                log_error("Could not append RTA_GATEWAY attribute: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append(req, RTA_DST, &route->dst_addr);
        if (r < 0) {
                log_error("Could not append RTA_DST attribute: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append(req, RTA_OIF, &link->ifindex);
        if (r < 0) {
                log_error("Could not append RTA_OIF attribute: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_call_async(link->manager->rtnl, req, callback, link, 0, NULL);
        if (r < 0) {
                log_error("Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        link->rtnl_messages ++;

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
        _cleanup_free_ char *route = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new(network, section_line, &n);
        if (r < 0)
                return r;

        r = net_parse_inaddr(rvalue, &n->family, &n->in_addr);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Route is invalid, ignoring assignment: %s", route);
                return 0;
        }

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
        _cleanup_free_ char *address = NULL;
        const char *e;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new(network, section_line, &n);
        if (r < 0)
                return r;

        /* Destination=address/prefixlen */

        /* prefixlen */
        e = strchr(rvalue, '/');
        if (e) {
                unsigned i;
                r = safe_atou(e + 1, &i);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Route destination prefix length is invalid, "
                                   "ignoring assignment: %s", e + 1);
                        return 0;
                }

                n->dst_prefixlen = (unsigned char) i;

                address = strndup(rvalue, e - rvalue);
                if (!address)
                        return log_oom();
        } else {
                address = strdup(rvalue);
                if (!address)
                        return log_oom();
        }

        r = net_parse_inaddr(address, &n->family, &n->dst_addr);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Destination is invalid, ignoring assignment: %s", address);
                return 0;
        }

        n = NULL;

        return 0;
}
