/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "sd-netlink.h"

#include "conf-parser.h"
#include "hash-funcs.h"

typedef struct RouteMetric {
        int quickack;
        int fast_open_no_cookie;
        uint32_t mtu;
        uint32_t initcwnd;
        uint32_t initrwnd;
        uint32_t advmss;
        uint32_t hop_limit;
        char *tcp_congestion_control_algo;
        usec_t tcp_rto_usec;
} RouteMetric;

#define ROUTE_METRIC_NULL                       \
        ((const RouteMetric) {                  \
                .quickack = -1,                 \
                .fast_open_no_cookie = -1,      \
        })

void route_metric_done(RouteMetric *metric);
int route_metric_copy(const RouteMetric *src, RouteMetric *dest);

void route_metric_hash_func(const RouteMetric *metric, struct siphash *state);
int route_metric_compare_func(const RouteMetric *a, const RouteMetric *b);

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
