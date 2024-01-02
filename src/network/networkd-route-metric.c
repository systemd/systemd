/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/icmpv6.h>
#include <linux/ipv6_route.h>
#include <linux/nexthop.h>

#include "alloc-util.h"
#include "event-util.h"
#include "netlink-util.h"
#include "networkd-address.h"
#include "networkd-ipv4ll.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-nexthop.h"
#include "networkd-queue.h"
#include "networkd-route-util.h"
#include "networkd-route.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "vrf.h"
#include "wireguard.h"

void route_metric_done(Route *route) {
        assert(route);

        route->n_metrics = 0;
        route->metrics = mfree(route->metrics);
        route->tcp_congestion_control_algo = mfree(route->tcp_congestion_control_algo);
}

int route_metric_copy(const Route *src, Route *dest) {
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

        return free_and_strdup(&dest->tcp_congestion_control_algo, src->tcp_congestion_control_algo);
}

void route_metric_hash_func(const Route *route, struct siphash *state) {
        assert(route);

        siphash24_compress_typesafe(route->n_metrics, state);
        for (size_t i = 1; i < route->n_metrics; i++)
                siphash24_compress_typesafe(route->metrics[i], state);
        siphash24_compress_string(route->tcp_congestion_control_algo, state);
}

int route_metric_compare_func(const Route *a, const Route *b) {
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

int route_set_metric(Route *route, uint16_t attr, uint32_t value) {
        assert(route);

        if (value != 0) {
                if (!GREEDY_REALLOC0(route->metrics, attr + 1))
                        return -ENOMEM;

                route->metrics[attr] = value;
                route->n_metrics = MAX(route->n_metrics, (size_t) (attr + 1));
                return 0;
        }

        if (route->n_metrics <= attr)
                return 0;

        route->metrics[attr] = 0;

        for (size_t i = route->n_metrics - 1; i > 0; i--)
                if (route->metrics[i] != 0) {
                        route->n_metrics = i + 1;
                        return 0;
                }

        route->metrics = mfree(route->metrics);
        route->n_metrics = 0;
        return 0;
}

int route_metric_set_netlink_message(const Route *route, sd_netlink_message *m) {
        int r;

        assert(route);
        assert(m);

        if (route->n_metrics <= 1 && isempty(route->tcp_congestion_control_algo))
                return 0;

        r = sd_netlink_message_open_container(m, RTA_METRICS);
        if (r < 0)
                return r;

        for (size_t i = 1; i < route->n_metrics; i++) {
                if (i == RTAX_CC_ALGO)
                        continue;

                if (route->metrics[i] == 0)
                        continue;

                r = sd_netlink_message_append_u32(m, i, route->metrics[i]);
                if (r < 0)
                        return r;
        }

        if (!isempty(route->tcp_congestion_control_algo)) {
                r = sd_netlink_message_append_string(m, RTAX_CC_ALGO, route->tcp_congestion_control_algo);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        return 0;
}

int route_metric_read_netlink_message(Route *route, sd_netlink_message *message) {
        _cleanup_free_ void *data = NULL;
        size_t len;
        int r;

        assert(route);
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

                        free_and_replace(route->tcp_congestion_control_algo, p);

                } else {
                        if (RTA_PAYLOAD(rta) != sizeof(uint32_t))
                                continue;

                        r = route_set_metric(route, rta_type, *(uint32_t*) RTA_DATA(rta));
                        if (r < 0)
                                return log_oom();
                }
        }

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
        _cleanup_(route_unref_or_set_invalidp) Route *n = NULL;
        uint16_t attr_type = ltype;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                (void) route_set_metric(n, attr_type, 0);
                TAKE_PTR(n);
                return 0;
        }

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse %s=\"%s\", ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        r = route_set_metric(n, attr_type, r);
        if (r < 0)
                return log_oom();

        TAKE_PTR(n);
        return 0;
}

int config_parse_route_hop_limit(
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

        _cleanup_(route_unref_or_set_invalidp) Route *n = NULL;
        Network *network = userdata;
        uint32_t k;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                (void) route_set_metric(n, RTAX_HOPLIMIT, 0);
                TAKE_PTR(n);
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

        r = route_set_metric(n, RTAX_HOPLIMIT, k);
        if (r < 0)
                return log_oom();

        TAKE_PTR(n);
        return 0;
}

int config_parse_tcp_congestion(
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
        _cleanup_(route_unref_or_set_invalidp) Route *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        r = config_parse_string(unit, filename, line, section, section_line, lvalue, ltype,
                                rvalue, &n->tcp_congestion_control_algo, userdata);
        if (r < 0)
                return r;

        TAKE_PTR(n);
        return 0;
}

int config_parse_tcp_advmss(
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

        _cleanup_(route_unref_or_set_invalidp) Route *n = NULL;
        Network *network = userdata;
        uint64_t u;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                (void) route_set_metric(n, RTAX_ADVMSS, 0);
                TAKE_PTR(n);
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

        r = route_set_metric(n, RTAX_ADVMSS, (uint32_t) u);
        if (r < 0)
                return log_oom();

        TAKE_PTR(n);
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

        uint32_t k, *window = ASSERT_PTR(data);
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
        return 1;
}

int config_parse_route_tcp_window(
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

        _cleanup_(route_unref_or_set_invalidp) Route *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        uint16_t attr_type;
        if (streq(lvalue, "InitialCongestionWindow"))
                attr_type = RTAX_INITCWND;
        else if (streq(lvalue, "InitialAdvertisedReceiveWindow"))
                attr_type = RTAX_INITRWND;
        else
                assert_not_reached();

        if (isempty(rvalue)) {
                (void) route_set_metric(n, attr_type, 0);
                TAKE_PTR(n);
                return 0;
        }

        uint32_t k;
        r = config_parse_tcp_window(unit, filename, line, section, section_line, lvalue, ltype, rvalue, &k, userdata);
        if (r <= 0)
                return r;

        r = route_set_metric(n, attr_type, k);
        if (r < 0)
                return log_oom();

        TAKE_PTR(n);
        return 0;
}

int config_parse_route_mtu(
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
        _cleanup_(route_unref_or_set_invalidp) Route *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                (void) route_set_metric(n, RTAX_MTU, 0);
                TAKE_PTR(n);
                return 0;
        }

        uint32_t k;
        r = config_parse_mtu(unit, filename, line, section, section_line, lvalue, ltype, rvalue, &k, userdata);
        if (r <= 0)
                return r;

        r = route_set_metric(n, RTAX_MTU, k);
        if (r < 0)
                return log_oom();

        TAKE_PTR(n);
        return 0;
}

int config_parse_route_tcp_rto(
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
        _cleanup_(route_unref_or_set_invalidp) Route *n = NULL;
        usec_t usec;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate route, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                (void) route_set_metric(n, RTAX_RTO_MIN, 0);
                TAKE_PTR(n);
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

        r = route_set_metric(n, RTAX_RTO_MIN, (uint32_t) DIV_ROUND_UP(usec, USEC_PER_MSEC));
        if (r < 0)
                return log_oom();

        TAKE_PTR(n);
        return 0;
}
