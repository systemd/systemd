/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2020 Intel Corporation */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"
#include "time-util.h"

#define CLOCKID_INVALID (-1)

static const struct static_clockid {
      const char *name;
      clockid_t clockid;
} clockids_sysv[] = {
      { "REALTIME", CLOCK_REALTIME },
      { "TAI", CLOCK_TAI },
      { "BOOTTIME", CLOCK_BOOTTIME },
      { "MONOTONIC", CLOCK_MONOTONIC },
      { NULL }
};

typedef struct EarliestTxTimeFirst {
        QDisc meta;

        __s32 clockid;
        __s32 delta;
        bool deadline;
        bool offload;
        bool skipsock;
} EarliestTxTimeFirst;

DEFINE_QDISC_CAST(ETF, EarliestTxTimeFirst);
extern const QDiscVTable etf_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_tc_etf_clockid);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_etf_delay_nsec);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_etf_bool);
