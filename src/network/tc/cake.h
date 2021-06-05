/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"

typedef struct CommonApplicationsKeptEnhanced {
        QDisc meta;

        int overhead;
        uint64_t bandwidth;

} CommonApplicationsKeptEnhanced;

DEFINE_QDISC_CAST(CAKE, CommonApplicationsKeptEnhanced);
extern const QDiscVTable cake_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_cake_bandwidth);
CONFIG_PARSER_PROTOTYPE(config_parse_cake_overhead);
