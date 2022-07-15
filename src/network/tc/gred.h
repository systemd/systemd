/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"

typedef struct GenericRandomEarlyDetection {
        QDisc meta;

        uint32_t virtual_queues;
        uint32_t default_virtual_queue;
        int grio;
} GenericRandomEarlyDetection;

DEFINE_QDISC_CAST(GRED, GenericRandomEarlyDetection);
extern const QDiscVTable gred_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_generic_random_early_detection_u32);
CONFIG_PARSER_PROTOTYPE(config_parse_generic_random_early_detection_bool);
