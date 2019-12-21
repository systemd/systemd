/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"
#include "time-util.h"

typedef struct ControlledDelay {
        QDisc meta;

        uint32_t packet_limit;

} ControlledDelay;

DEFINE_QDISC_CAST(CODEL, ControlledDelay);
extern const QDiscVTable codel_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_tc_controlled_delay_u32);
