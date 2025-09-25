/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Manager Manager;
enum OomdAction;

struct oom_ruleset;

void oom_ruleset_free(struct oom_ruleset *ruleset);

void manager_set_defaults(Manager *m);

void manager_parse_config_file(Manager *m);

const char* actions_to_string(enum OomdAction i);
enum OomdAction actions_from_string(const char *s);
