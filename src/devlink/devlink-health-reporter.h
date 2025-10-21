/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "devlink.h"

typedef struct DevlinkHealthReporter {
        Devlink meta;
        uint64_t grace_period;
        bool grace_period_valid;
        bool auto_recover;
        bool auto_recover_valid;
        bool auto_dump;
        bool auto_dump_valid;
} DevlinkHealthReporter;

DEFINE_DEVLINK_CAST(HEALTH_REPORTER, DevlinkHealthReporter);

extern const DevlinkVTable devlink_health_reporter_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_devlink_health_reporter_grace_period);
CONFIG_PARSER_PROTOTYPE(config_parse_devlink_health_reporter_auto_recover);
CONFIG_PARSER_PROTOTYPE(config_parse_devlink_health_reporter_auto_dump);
