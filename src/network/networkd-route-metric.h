/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "conf-parser.h"
#include "macro.h"

typedef struct Link Link;
typedef struct Manager Manager;
typedef struct Route Route;

void route_metric_done(Route *route);
int route_metric_copy(const Route *src, Route *dest);

void route_metric_hash_func(const Route *route, struct siphash *state);
int route_metric_compare_func(const Route *a, const Route *b);

int route_set_metric(Route *route, uint16_t attr, uint32_t value);

int route_metric_set_netlink_message(const Route *route, sd_netlink_message *m);
int route_metric_read_netlink_message(Route *route, sd_netlink_message *message);

CONFIG_PARSER_PROTOTYPE(config_parse_route_metric_boolean);
CONFIG_PARSER_PROTOTYPE(config_parse_route_hop_limit);
CONFIG_PARSER_PROTOTYPE(config_parse_tcp_congestion);
CONFIG_PARSER_PROTOTYPE(config_parse_tcp_advmss);
CONFIG_PARSER_PROTOTYPE(config_parse_tcp_window);
CONFIG_PARSER_PROTOTYPE(config_parse_route_tcp_window);
CONFIG_PARSER_PROTOTYPE(config_parse_route_mtu);
CONFIG_PARSER_PROTOTYPE(config_parse_route_tcp_rto);
