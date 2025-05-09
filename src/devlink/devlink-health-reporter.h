/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "devlink.h"
#include "devlink-util.h"

typedef struct DevlinkHealthReporter {
        Devlink meta;
        int grace_period_valid:1,
            auto_recover_valid:1,
            auto_dump_valid:1;
        uint64_t grace_period;
        bool auto_recover;
        bool auto_dump;
} DevlinkHealthReporter;

DEFINE_DEVLINK_CAST(HEALTH_REPORTER, DevlinkHealthReporter);

extern const DevlinkVTable devlink_health_reporter_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_devlink_health_reporter_grace_period);
CONFIG_PARSER_PROTOTYPE(config_parse_devlink_health_reporter_auto_recover);
CONFIG_PARSER_PROTOTYPE(config_parse_devlink_health_reporter_auto_dump);
