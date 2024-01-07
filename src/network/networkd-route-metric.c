/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "netlink-util.h"
#include "networkd-route.h"
#include "networkd-route-metric.h"
#include "parse-util.h"
#include "string-util.h"

void route_metric_done(RouteMetric *metric) {
        assert(metric);

        free(metric->metrics);
        free(metric->metrics_set);
        free(metric->tcp_congestion_control_algo);
}

int route_metric_copy(const RouteMetric *src, RouteMetric *dest) {
        assert(src);
        assert(dest);

        dest->n_metrics = src->n_metrics;
        dest->metrics = newdup(uint32_t, src->metrics, src->n_metrics);
        if (!dest->metrics)
                return -ENOMEM;

        dest->n_metrics_set = src->n_metrics_set;
        dest->metrics_set = newdup(bool, src->metrics_set, src->n_metrics_set);
        if (!dest->metrics_set)
                return -ENOMEM;

        return free_and_strdup(&dest->tcp_congestion_control_algo, src->tcp_congestion_control_algo);
}

void route_metric_hash_func(const RouteMetric *metric, struct siphash *state) {
        assert(metric);

        siphash24_compress_typesafe(metric->n_metrics, state);
        siphash24_compress_safe(metric->metrics, sizeof(uint32_t) * metric->n_metrics, state);
        siphash24_compress_string(metric->tcp_congestion_control_algo, state);
}

int route_metric_compare_func(const RouteMetric *a, const RouteMetric *b) {
        int r;

        assert(a);
        assert(b);

        r = memcmp_nn(a->metrics, a->n_metrics * sizeof(uint32_t), b->metrics, b->n_metrics * sizeof(uint32_t));
        if (r != 0)
                return r;

        return strcmp_ptr(a->tcp_congestion_control_algo, b->tcp_congestion_control_algo);
}

int route_metric_set_full(RouteMetric *metric, uint16_t attr, uint32_t value, bool force) {
        assert(metric);

        if (force) {
                if (!GREEDY_REALLOC0(metric->metrics_set, attr + 1))
                        return -ENOMEM;

                metric->metrics_set[attr] = true;
                metric->n_metrics_set = MAX(metric->n_metrics_set, (size_t) (attr + 1));
        } else {
                /* Do not override the values specified in conf parsers. */
                if (metric->n_metrics_set > attr && metric->metrics_set[attr])
                        return 0;
        }

        if (value != 0) {
                if (!GREEDY_REALLOC0(metric->metrics, attr + 1))
                        return -ENOMEM;

                metric->metrics[attr] = value;
                metric->n_metrics = MAX(metric->n_metrics, (size_t) (attr + 1));
                return 0;
        }

        if (metric->n_metrics <= attr)
                return 0;

        metric->metrics[attr] = 0;

        for (size_t i = metric->n_metrics; i > 0; i--)
                if (metric->metrics[i-1] != 0) {
                        metric->n_metrics = i;
                        return 0;
                }

        metric->n_metrics = 0;
        return 0;
}

static void route_metric_unset(RouteMetric *metric, uint16_t attr) {
        assert(metric);

        if (metric->n_metrics_set > attr)
                metric->metrics_set[attr] = false;

        assert_se(route_metric_set_full(metric, attr, 0, /* force = */ false) >= 0);
}

uint32_t route_metric_get(const RouteMetric *metric, uint16_t attr) {
        assert(metric);

        if (metric->n_metrics <= attr)
                return 0;

        return metric->metrics[attr];
}

int route_metric_set_netlink_message(const RouteMetric *metric, sd_netlink_message *m) {
        int r;

        assert(metric);
        assert(m);

        if (metric->n_metrics <= 0 && isempty(metric->tcp_congestion_control_algo))
                return 0;

        r = sd_netlink_message_open_container(m, RTA_METRICS);
        if (r < 0)
                return r;

        for (size_t i = 0; i < metric->n_metrics; i++) {
                if (i == RTAX_CC_ALGO)
                        continue;

                if (metric->metrics[i] == 0)
                        continue;

                r = sd_netlink_message_append_u32(m, i, metric->metrics[i]);
                if (r < 0)
                        return r;
        }

        if (!isempty(metric->tcp_congestion_control_algo)) {
                r = sd_netlink_message_append_string(m, RTAX_CC_ALGO, metric->tcp_congestion_control_algo);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        return 0;
}

int route_metric_read_netlink_message(RouteMetric *metric, sd_netlink_message *m) {
        _cleanup_free_ void *data = NULL;
        size_t len;
        int r;

        assert(metric);
        assert(m);

        r = sd_netlink_message_read_data(m, RTA_METRICS, &len, &data);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return log_warning_errno(r, "rtnl: Could not read RTA_METRICS attribute, ignoring: %m");

        for (struct rtattr *rta = data; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
                size_t rta_type = RTA_TYPE(rta);

                if (rta_type == RTAX_CC_ALGO) {
                        char *p = memdup_suffix0(RTA_DATA(rta), RTA_PAYLOAD(rta));
                        if (!p)
                                return log_oom();

                        free_and_replace(metric->tcp_congestion_control_algo, p);

                } else {
                        if (RTA_PAYLOAD(rta) != sizeof(uint32_t))
                                continue;

                        r = route_metric_set(metric, rta_type, *(uint32_t*) RTA_DATA(rta));
                        if (r < 0)
                                return log_oom();
                }
        }

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

        uint32_t k;
        r = config_parse_mtu(unit, filename, line, section, section_line, lvalue, AF_UNSPEC, rvalue, &k, userdata);
        if (r <= 0)
                return r;

        if (route_metric_set_full(&route->metric, ltype, k, /* force = */ true) < 0)
                return log_oom();

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
                route_metric_unset(&route->metric, ltype);
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

        if (route_metric_set_full(&route->metric, ltype, u, /* force = */ true) < 0)
                return log_oom();

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
                route_metric_unset(&route->metric, ltype);
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

        if (route_metric_set_full(&route->metric, ltype, k, /* force = */ true) < 0)
                return log_oom();

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
        return 1;
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

        uint32_t k;
        r = config_parse_tcp_window(unit, filename, line, section, section_line, lvalue, ltype, rvalue, &k, userdata);
        if (r <= 0)
                return r;

        if (route_metric_set_full(&route->metric, ltype, k, /* force = */ true) < 0)
                return log_oom();

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

        if (route_metric_set_full(&route->metric, ltype, DIV_ROUND_UP(usec, USEC_PER_MSEC), /* force = */ true) < 0)
                return log_oom();

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

        if (route_metric_set_full(&route->metric, ltype, r, /* force = */ true) < 0)
                return log_oom();

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
