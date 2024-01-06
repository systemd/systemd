/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "networkd-route.h"
#include "networkd-route-metric.h"
#include "parse-util.h"
#include "string-util.h"

int config_parse_route_metric_mtu(
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

        r = config_parse_mtu(unit, filename, line, section, section_line, lvalue, AF_UNSPEC, rvalue, &route->mtu, userdata);
        if (r <= 0)
                return r;

        TAKE_PTR(route);
        return 0;
}

int config_parse_route_metric_advmss(
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

        _cleanup_(route_free_or_set_invalidp) Route *route = NULL;
        Network *network = userdata;
        uint64_t u;
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
                route->advmss = 0;
                TAKE_PTR(route);
                return 0;
        }

        r = parse_size(rvalue, 1024, &u);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse TCPAdvertisedMaximumSegmentSize= \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        if (u == 0 || u > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid TCPAdvertisedMaximumSegmentSize= \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        route->advmss = u;

        TAKE_PTR(route);
        return 0;
}

int config_parse_route_metric_hop_limit(
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

        _cleanup_(route_free_or_set_invalidp) Route *route = NULL;
        Network *network = userdata;
        uint32_t k;
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
                route->hop_limit = 0;
                TAKE_PTR(route);
                return 0;
        }

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse per route hop limit, ignoring assignment: %s", rvalue);
                return 0;
        }
        if (k > 255) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified per route hop limit \"%s\" is too large, ignoring assignment: %m", rvalue);
                return 0;
        }
        if (k == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid per route hop limit \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        route->hop_limit = k;

        TAKE_PTR(route);
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

        uint32_t *window = ASSERT_PTR(data);
        uint32_t k;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse TCP %s \"%s\", ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }
        if (k >= 1024) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified TCP %s \"%s\" is too large, ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }
        if (k == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid TCP %s \"%s\", ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        *window = k;
        return 0;
}

int config_parse_route_metric_tcp_window(
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

        _cleanup_(route_free_or_set_invalidp) Route *route = NULL;
        Network *network = userdata;
        uint32_t *d;
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

        if (streq(lvalue, "InitialCongestionWindow"))
                d = &route->initcwnd;
        else if (streq(lvalue, "InitialAdvertisedReceiveWindow"))
                d = &route->initrwnd;
        else
                assert_not_reached();

        r = config_parse_tcp_window(unit, filename, line, section, section_line, lvalue, ltype, rvalue, d, userdata);
        if (r < 0)
                return r;

        TAKE_PTR(route);
        return 0;
}

int config_parse_route_metric_tcp_rto(
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
        usec_t usec;
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

        r = parse_sec(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse route TCP retransmission timeout (RTO), ignoring assignment: %s", rvalue);
                return 0;
        }

        if (!timestamp_is_set(usec) ||
            DIV_ROUND_UP(usec, USEC_PER_MSEC) > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Route TCP retransmission timeout (RTO) must be in the range 0…%"PRIu32"ms, ignoring assignment: %s", UINT32_MAX, rvalue);
                return 0;
        }

        route->tcp_rto_usec = usec;

        TAKE_PTR(route);
        return 0;
}

int config_parse_route_metric_boolean(
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

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse %s=\"%s\", ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        if (streq(lvalue, "QuickAck"))
                route->quickack = r;
        else if (streq(lvalue, "FastOpenNoCookie"))
                route->fast_open_no_cookie = r;
        else
                assert_not_reached();

        TAKE_PTR(route);
        return 0;
}

int config_parse_route_metric_tcp_congestion(
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

        r = config_parse_string(unit, filename, line, section, section_line, lvalue, 0,
                                rvalue, &route->tcp_congestion_control_algo, userdata);
        if (r < 0)
                return r;

        TAKE_PTR(route);
        return 0;
}
