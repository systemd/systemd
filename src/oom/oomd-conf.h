/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "string-table-fundamental.h"

typedef struct Manager Manager;
typedef struct OomdRuleset OomdRuleset;
typedef enum OomdAction OomdAction;

void oomd_ruleset_free(OomdRuleset *ruleset);

void manager_set_defaults(Manager *m);

void manager_parse_config_file(Manager *m);

DECLARE_STRING_TABLE_LOOKUP(oomd_action, OomdAction);
