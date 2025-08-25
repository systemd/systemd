/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro-fundamental.h"

typedef struct Manager Manager;

typedef enum EnablePrekillHook {
        ENABLE_PREKILL_HOOK_NO = 0,
        ENABLE_PREKILL_HOOK_YES = 1,

        _ENABLE_PREKILL_HOOK_MAX,
        _ENABLE_PREKILL_HOOK_INVALID = -1
} EnablePrekillHook;

void manager_set_defaults(Manager *m);

void manager_parse_config_file(Manager *m);

const char* prekill_enabled_to_string(EnablePrekillHook i) _const_;
EnablePrekillHook prekill_enabled_from_string(const char *s) _pure_;
