/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "netlink-util.h"
#include "networkd-route.h"
#include "networkd-route-metric.h"
#include "parse-util.h"
#include "string-util.h"

void route_metric_done(RouteMetric *metric) {
        assert(metric);

        free(metric->tcp_congestion_control_algo);
}

int route_metric_copy(const RouteMetric *src, RouteMetric *dest) {
        assert(src);
        assert(dest);

        dest->quickack = src->quickack;
        dest->fast_open_no_cookie = src->fast_open_no_cookie;
        dest->mtu = src->mtu;
        dest->initcwnd = src->initcwnd;
        dest->initrwnd = src->initrwnd;
        dest->advmss = src->advmss;
        dest->hop_limit = src->hop_limit;
        dest->tcp_rto_usec = src->tcp_rto_usec;

        return free_and_strdup(&dest->tcp_congestion_control_algo, src->tcp_congestion_control_algo);
}

void route_metric_hash_func(const RouteMetric *metric, struct siphash *state) {
        assert(metric);

        siphash24_compress_typesafe(metric->initcwnd, state);
        siphash24_compress_typesafe(metric->initrwnd, state);
        siphash24_compress_typesafe(metric->advmss, state);
}

int route_metric_compare_func(const RouteMetric *a, const RouteMetric *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->initcwnd, b->initcwnd);
        if (r != 0)
                return r;

        r = CMP(a->initrwnd, b->initrwnd);
        if (r != 0)
                return r;

        return CMP(a->advmss, b->advmss);
}

int route_metric_set_netlink_message(const RouteMetric *metric, sd_netlink_message *m) {
        int r;

        assert(metric);
        assert(m);

        r = sd_netlink_message_open_container(m, RTA_METRICS);
        if (r < 0)
                return r;

        if (metric->mtu > 0) {
                r = sd_netlink_message_append_u32(m, RTAX_MTU, metric->mtu);
                if (r < 0)
                        return r;
        }

        if (metric->initcwnd > 0) {
                r = sd_netlink_message_append_u32(m, RTAX_INITCWND, metric->initcwnd);
                if (r < 0)
                        return r;
        }

        if (metric->initrwnd > 0) {
                r = sd_netlink_message_append_u32(m, RTAX_INITRWND, metric->initrwnd);
                if (r < 0)
                        return r;
        }

        if (metric->quickack >= 0) {
                r = sd_netlink_message_append_u32(m, RTAX_QUICKACK, metric->quickack);
                if (r < 0)
                        return r;
        }

        if (metric->fast_open_no_cookie >= 0) {
                r = sd_netlink_message_append_u32(m, RTAX_FASTOPEN_NO_COOKIE, metric->fast_open_no_cookie);
                if (r < 0)
                        return r;
        }

        if (metric->advmss > 0) {
                r = sd_netlink_message_append_u32(m, RTAX_ADVMSS, metric->advmss);
                if (r < 0)
                        return r;
        }

        if (!isempty(metric->tcp_congestion_control_algo)) {
                r = sd_netlink_message_append_string(m, RTAX_CC_ALGO, metric->tcp_congestion_control_algo);
                if (r < 0)
                        return r;
        }

        if (metric->hop_limit > 0) {
                r = sd_netlink_message_append_u32(m, RTAX_HOPLIMIT, metric->hop_limit);
                if (r < 0)
                        return r;
        }

        if (metric->tcp_rto_usec > 0) {
                r = sd_netlink_message_append_u32(m, RTAX_RTO_MIN, DIV_ROUND_UP(metric->tcp_rto_usec, USEC_PER_MSEC));
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        return 0;
}

int route_metric_read_netlink_message(RouteMetric *metric, sd_netlink_message *m) {
        int r;

        assert(metric);
        assert(m);

        r = sd_netlink_message_enter_container(m, RTA_METRICS);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return log_warning_errno(r, "rtnl: Could not enter RTA_METRICS container, ignoring: %m");

        r = sd_netlink_message_read_u32(m, RTAX_INITCWND, &metric->initcwnd);
        if (r < 0 && r != -ENODATA)
                return log_warning_errno(r, "rtnl: received route message with invalid initcwnd, ignoring: %m");

        r = sd_netlink_message_read_u32(m, RTAX_INITRWND, &metric->initrwnd);
        if (r < 0 && r != -ENODATA)
                return log_warning_errno(r, "rtnl: received route message with invalid initrwnd, ignoring: %m");

        r = sd_netlink_message_read_u32(m, RTAX_ADVMSS, &metric->advmss);
        if (r < 0 && r != -ENODATA)
                return log_warning_errno(r, "rtnl: received route message with invalid advmss, ignoring: %m");

        r = sd_netlink_message_exit_container(m);
        if (r < 0)
                return log_warning_errno(r, "rtnl: Could not exit from RTA_METRICS container, ignoring: %m");

        return 0;
}

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

        r = config_parse_mtu(unit, filename, line, section, section_line, lvalue, AF_UNSPEC, rvalue, &route->metric.mtu, userdata);
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
                route->metric.advmss = 0;
                TAKE_PTR(route);
                return 0;
        }

        r = parse_size(rvalue, 1024, &u);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        if (u == 0 || u > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        route->metric.advmss = u;

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
                route->metric.hop_limit = 0;
                TAKE_PTR(route);
                return 0;
        }

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }
        if (k == 0 || k > 255) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        route->metric.hop_limit = k;

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
                           "Could not parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }
        if (k == 0 || k >= 1024) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid %s=, ignoring assignment: %s", lvalue, rvalue);
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
                d = &route->metric.initcwnd;
        else if (streq(lvalue, "InitialAdvertisedReceiveWindow"))
                d = &route->metric.initrwnd;
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
                           "Failed to parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        if (!timestamp_is_set(usec) ||
            DIV_ROUND_UP(usec, USEC_PER_MSEC) > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        route->metric.tcp_rto_usec = usec;

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
                           "Could not parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        if (streq(lvalue, "QuickAck"))
                route->metric.quickack = r;
        else if (streq(lvalue, "FastOpenNoCookie"))
                route->metric.fast_open_no_cookie = r;
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
                                rvalue, &route->metric.tcp_congestion_control_algo, userdata);
        if (r < 0)
                return r;

        TAKE_PTR(route);
        return 0;
}
