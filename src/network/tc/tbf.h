/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"
#include "time-util.h"

typedef struct TokenBufferFilter {
        QDisc meta;

        uint64_t rate;
        uint64_t peak_rate;
        uint32_t burst;
        uint32_t mtu;
        usec_t latency;
        size_t limit;
        size_t mpu;
} TokenBufferFilter;

DEFINE_QDISC_CAST(TBF, TokenBufferFilter);
extern const QDiscVTable tbf_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_tc_token_buffer_filter_latency);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_token_buffer_filter_size);
