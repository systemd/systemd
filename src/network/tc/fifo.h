/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"

typedef struct FirstInFirstOut {
        QDisc meta;

        uint32_t limit;
} FirstInFirstOut;

DEFINE_QDISC_CAST(PFIFO, FirstInFirstOut);
DEFINE_QDISC_CAST(BFIFO, FirstInFirstOut);

extern const QDiscVTable pfifo_vtable;
extern const QDiscVTable bfifo_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_pfifo_size);
CONFIG_PARSER_PROTOTYPE(config_parse_bfifo_size);
