/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "parse-util.h"
#include "string-table.h"      /* IWYU pragma: keep */

typedef struct Manager Manager;
typedef struct OomdRuleset OomdRuleset;
typedef enum OomdAction OomdAction;

typedef struct OomdConfig {
        int swap_used_limit_permyriad;
        loadavg_t default_mem_pressure_limit;
        usec_t default_mem_pressure_duration_usec;
        usec_t prekill_timeout;
} OomdConfig;

int oomd_config_parse(OomdConfig *config);

void oomd_ruleset_free(OomdRuleset *ruleset);
void manager_load_rulesets(Manager *m);
DECLARE_STRING_TABLE_LOOKUP(oomd_action, OomdAction);
