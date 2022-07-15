/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"
#include "time-util.h"

typedef struct TokenBucketFilter {
        QDisc meta;

        uint64_t rate;
        uint64_t peak_rate;
        uint32_t burst;
        uint32_t mtu;
        usec_t latency;
        size_t limit;
        size_t mpu;
} TokenBucketFilter;

DEFINE_QDISC_CAST(TBF, TokenBucketFilter);
extern const QDiscVTable tbf_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_token_bucket_filter_latency);
CONFIG_PARSER_PROTOTYPE(config_parse_token_bucket_filter_size);
CONFIG_PARSER_PROTOTYPE(config_parse_token_bucket_filter_rate);
