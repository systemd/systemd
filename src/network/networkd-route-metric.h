/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "sd-netlink.h"

#include "conf-parser.h"
#include "hash-funcs.h"

typedef struct RouteMetric {
        size_t n_metrics; /* maximum metric attr type with non-zero value */
        uint32_t *metrics; /* RTAX_*, except for RTAX_CC_ALGO */

        size_t n_metrics_set;
        bool *metrics_set; /* used by conf parsers */

        char *tcp_congestion_control_algo; /* RTAX_CC_ALGO */
} RouteMetric;

#define ROUTE_METRIC_NULL ((const RouteMetric) {})

void route_metric_done(RouteMetric *metric);
int route_metric_copy(const RouteMetric *src, RouteMetric *dest);

void route_metric_hash_func(const RouteMetric *metric, struct siphash *state);
int route_metric_compare_func(const RouteMetric *a, const RouteMetric *b);

int route_metric_set_full(RouteMetric *metric, uint16_t attr, uint32_t value, bool force);
static inline int route_metric_set(RouteMetric *metric, uint16_t attr, uint32_t value) {
        return route_metric_set_full(metric, attr, value, false);
}
uint32_t route_metric_get(const RouteMetric *metric, uint16_t attr);

int route_metric_set_netlink_message(const RouteMetric *metric, sd_netlink_message *m);
int route_metric_read_netlink_message(RouteMetric *metric, sd_netlink_message *message);

CONFIG_PARSER_PROTOTYPE(config_parse_route_metric_mtu);
CONFIG_PARSER_PROTOTYPE(config_parse_route_metric_advmss);
CONFIG_PARSER_PROTOTYPE(config_parse_route_metric_hop_limit);
CONFIG_PARSER_PROTOTYPE(config_parse_route_metric_tcp_window);
CONFIG_PARSER_PROTOTYPE(config_parse_route_metric_tcp_rto);
CONFIG_PARSER_PROTOTYPE(config_parse_route_metric_boolean);
CONFIG_PARSER_PROTOTYPE(config_parse_route_metric_tcp_congestion);
CONFIG_PARSER_PROTOTYPE(config_parse_tcp_window);
