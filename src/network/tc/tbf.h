/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "sd-netlink.h"

#include "conf-parser.h"
#include "networkd-link.h"

typedef struct TokenBufferFilter {
        uint64_t rate;

        uint32_t burst;
        uint32_t latency;
} TokenBufferFilter;

int token_buffer_filter_new(TokenBufferFilter **ret);
int token_buffer_filter_fill_message(Link *link, const TokenBufferFilter *tbf, sd_netlink_message *req);

CONFIG_PARSER_PROTOTYPE(config_parse_tc_token_buffer_filter_latency);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_token_buffer_filter_size);
