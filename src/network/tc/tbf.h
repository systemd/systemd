/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "sd-netlink.h"

#include "conf-parser.h"
#include "networkd-link.h"
#include "networkd-util.h"
#include "tc-util.h"

typedef struct TokenBufferFilter {
        uint64_t rate;
        uint64_t peak_rate;
        uint32_t burst;
        uint32_t mtu;
        usec_t latency;
        size_t limit;
        size_t mpu;
} TokenBufferFilter;

int token_buffer_filter_new(TokenBufferFilter **ret);
int token_buffer_filter_fill_message(Link *link, const TokenBufferFilter *tbf, sd_netlink_message *req);
int token_buffer_filter_section_verify(const TokenBufferFilter *tbf, const NetworkConfigSection *section);

CONFIG_PARSER_PROTOTYPE(config_parse_tc_token_buffer_filter_latency);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_token_buffer_filter_size);
