/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"
#include "time-util.h"

typedef struct GenericRandomEarlyDrop {
        QDisc meta;

        uint32_t virtual_queues;
        uint32_t default_virtual_queue;
        int grio;
} GenericRandomEarlyDrop;

DEFINE_QDISC_CAST(GRED, GenericRandomEarlyDrop);
extern const QDiscVTable gred_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_generic_random_early_drop_u32);
CONFIG_PARSER_PROTOTYPE(config_parse_generic_random_early_drop_bool);
