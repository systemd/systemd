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
        if (src->n_metrics > 0) {
                assert(src->n_metrics != 1);

                dest->metrics = newdup(uint32_t, src->metrics, src->n_metrics);
                if (!dest->metrics)
                        return -ENOMEM;
        } else
                dest->metrics = NULL;

        dest->n_metrics_set = src->n_metrics_set;
        if (src->n_metrics_set > 0) {
                assert(src->n_metrics_set != 1);

                dest->metrics_set = newdup(bool, src->metrics_set, src->n_metrics_set);
                if (!dest->metrics_set)
                        return -ENOMEM;

        } else
                dest->metrics_set = NULL;

        return free_and_strdup(&dest->tcp_congestion_control_algo, src->tcp_congestion_control_algo);
}

void route_metric_hash_func(const RouteMetric *metric, struct siphash *state) {
        assert(metric);

        siphash24_compress_typesafe(metric->n_metrics, state);
        for (size_t i = 1; i < metric->n_metrics; i++)
                siphash24_compress_typesafe(metric->metrics[i], state);
        siphash24_compress_string(metric->tcp_congestion_control_algo, state);
}

int route_metric_compare_func(const RouteMetric *a, const RouteMetric *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->n_metrics, b->n_metrics);
        if (r != 0)
                return r;

        for (size_t i = 1; i < a->n_metrics; i++) {
                r = CMP(a->metrics[i], b->metrics[i]);
                if (r != 0)
                        return r;
        }

        return strcmp_ptr(a->tcp_congestion_control_algo, b->tcp_congestion_control_algo);
}

int route_metric_set_full(RouteMetric *metric, uint16_t attr, uint32_t value, bool force) {
        assert(metric);
        assert(attr > 0);

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

        for (size_t i = metric->n_metrics - 1; i > 0; i--)
                if (metric->metrics[i] != 0) {
                        metric->n_metrics = i + 1;
                        return 0;
                }

        metric->metrics = mfree(metric->metrics);
        metric->n_metrics = 0;
        return 0;
}

static void route_metric_unset(RouteMetric *metric, uint16_t attr) {
        assert(metric);
        assert(attr > 0);

        if (metric->n_metrics_set > attr)
                metric->metrics_set[attr] = false;

        assert_se(route_metric_set_full(metric, attr, 0, /* force = */ false) >= 0);
}

uint32_t route_metric_get(const RouteMetric *metric, uint16_t attr) {
        assert(metric);
        assert(attr > 0);

        if (metric->n_metrics <= attr)
                return 0;

        return metric->metrics[attr];
}

int route_metric_set_netlink_message(const RouteMetric *metric, sd_netlink_message *m) {
        int r;

        assert(metric);
        assert(m);

        if (metric->n_metrics <= 1 && isempty(metric->tcp_congestion_control_algo))
                return 0;

        r = sd_netlink_message_open_container(m, RTA_METRICS);
        if (r < 0)
                return r;

        for (size_t i = 1; i < metric->n_metrics; i++) {
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

int route_metric_read_netlink_message(RouteMetric *metric, sd_netlink_message *message) {
        _cleanup_free_ void *data = NULL;
        size_t len;
        int r;

        assert(metric);
        assert(message);

        r = sd_netlink_message_read_data(message, RTA_METRICS, &len, &data);
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

static int parse_route_metric_mtu(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                const char *rvalue,
                uint32_t *ret) {

        uint32_t k = 0;
        int r;

        assert(rvalue);
        assert(ret);

        r = config_parse_mtu(unit, filename, line, section, section_line, lvalue, AF_UNSPEC, rvalue, &k, NULL);
        if (r < 0)
                return r;

        *ret = k;
        return r; /* config_parse_mtu() returns 1 on success. */
}

static int parse_route_metric_advmss(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                const char *rvalue,
                uint32_t *ret) {

        uint64_t u;
        int r;

        assert(rvalue);
        assert(ret);

        r = parse_size(rvalue, 1024, &u);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse %s=, ignoring assignment: %s", lvalue, rvalue);
                *ret = 0;
                return 0;
        }

        if (u == 0 || u > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid %s=, ignoring assignment: %s", lvalue, rvalue);
                *ret = 0;
                return 0;
        }

        *ret = (uint32_t) u;
        return 1;
}

static int parse_route_metric_hop_limit(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                const char *rvalue,
                uint32_t *ret) {

        uint32_t k;
        int r;

        assert(rvalue);
        assert(ret);

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse %s=, ignoring assignment: %s", lvalue, rvalue);
                *ret = 0;
                return 0;
        }
        if (k == 0 || k > 255) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid %s=, ignoring assignment: %s", lvalue, rvalue);
                *ret = 0;
                return 0;
        }

        *ret = k;
        return 1;
}

static int parse_route_metric_tcp_window(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                const char *rvalue,
                uint32_t *ret) {

        uint32_t k;
        int r;

        assert(rvalue);
        assert(ret);

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse %s=, ignoring assignment: %s", lvalue, rvalue);
                *ret = 0;
                return 0;
        }
        if (k == 0 || k >= 1024) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid %s=, ignoring assignment: %s", lvalue, rvalue);
                *ret = 0;
                return 0;
        }

        *ret = k;
        return 1;
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

        uint32_t k, *window = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(rvalue);

        r = parse_route_metric_tcp_window(unit, filename, line, section, section_line, lvalue, rvalue, &k);
        if (r <= 0)
                return r;

        *window = k;
        return 1;
}

static int parse_route_metric_tcp_rto(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                const char *rvalue,
                uint32_t *ret) {

        usec_t usec;
        int r;

        assert(rvalue);
        assert(ret);

        r = parse_sec(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s", lvalue, rvalue);
                *ret = 0;
                return 0;
        }

        if (!timestamp_is_set(usec) ||
            DIV_ROUND_UP(usec, USEC_PER_MSEC) > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalud %s=, ignoring assignment: %s", lvalue, rvalue);
                *ret = 0;
                return 0;
        }

        *ret = (uint32_t) DIV_ROUND_UP(usec, USEC_PER_MSEC);
        return 1;
}

static int parse_route_metric_boolean(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                const char *rvalue,
                uint32_t *ret) {

        int r;

        assert(rvalue);
        assert(ret);

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse %s=, ignoring assignment: %s", lvalue, rvalue);
                *ret = 0;
                return 0;
        }

        *ret = r;
        return 1;
}

#define DEFINE_CONFIG_PARSE_ROUTE_METRIC(name)                          \
        int config_parse_route_metric_##name(                           \
                        const char *unit,                               \
                        const char *filename,                           \
                        unsigned line,                                  \
                        const char *section,                            \
                        unsigned section_line,                          \
                        const char *lvalue,                             \
                        int ltype,                                      \
                        const char *rvalue,                             \
                        void *data,                                     \
                        void *userdata) {                               \
                                                                        \
                Network *network = userdata;                            \
                _cleanup_(route_unref_or_set_invalidp) Route *route = NULL; \
                uint16_t attr_type = ltype;                             \
                int r;                                                  \
                                                                        \
                assert(filename);                                       \
                assert(section);                                        \
                assert(lvalue);                                         \
                assert(rvalue);                                         \
                assert(data);                                           \
                assert(attr_type > 0);                                  \
                                                                        \
                r = route_new_static(network, filename, section_line, &route); \
                if (r == -ENOMEM)                                       \
                        return log_oom();                               \
                if (r < 0) {                                            \
                        log_syntax(unit, LOG_WARNING, filename, line, r, \
                                   "Failed to allocate route, ignoring assignment: %m"); \
                        return 0;                                       \
                }                                                       \
                                                                        \
                if (isempty(rvalue)) {                                  \
                        route_metric_unset(&route->metric, attr_type);  \
                        TAKE_PTR(route);                                \
                        return 0;                                       \
                }                                                       \
                                                                        \
                uint32_t k;                                             \
                r = parse_route_metric_##name(                          \
                                unit,                                   \
                                filename,                               \
                                line,                                   \
                                section,                                \
                                section_line,                           \
                                lvalue,                                 \
                                rvalue,                                 \
                                &k);                                    \
                if (r <= 0)                                             \
                        return r;                                       \
                                                                        \
                if (route_metric_set_full(                              \
                                &route->metric,                         \
                                attr_type,                              \
                                k,                                      \
                                /* force = */ true) < 0)                \
                        return log_oom();                               \
                                                                        \
                TAKE_PTR(route);                                        \
                return 0;                                               \
        }

DEFINE_CONFIG_PARSE_ROUTE_METRIC(mtu);
DEFINE_CONFIG_PARSE_ROUTE_METRIC(advmss);
DEFINE_CONFIG_PARSE_ROUTE_METRIC(hop_limit);
DEFINE_CONFIG_PARSE_ROUTE_METRIC(tcp_window);
DEFINE_CONFIG_PARSE_ROUTE_METRIC(tcp_rto);
DEFINE_CONFIG_PARSE_ROUTE_METRIC(boolean);

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
        _cleanup_(route_unref_or_set_invalidp) Route *route = NULL;
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
