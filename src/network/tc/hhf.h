/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"

typedef struct HeavyHitterFilter {
        QDisc meta;

        uint32_t packet_limit;
} HeavyHitterFilter;

DEFINE_QDISC_CAST(HHF, HeavyHitterFilter);
extern const QDiscVTable hhf_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_heavy_hitter_filter_packet_limit);
