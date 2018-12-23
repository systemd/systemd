/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"

typedef enum HandleAction
{
        HANDLE_IGNORE,
        HANDLE_POWEROFF,
        HANDLE_REBOOT,
        HANDLE_HALT,
        HANDLE_KEXEC,
        HANDLE_SUSPEND,
        HANDLE_HIBERNATE,
        HANDLE_HYBRID_SLEEP,
        HANDLE_SUSPEND_THEN_HIBERNATE,
        HANDLE_LOCK,
        _HANDLE_ACTION_MAX,
        _HANDLE_ACTION_INVALID = -1
} HandleAction;

#include "logind-inhibit.h"
#include "logind.h"

int manager_handle_action(Manager *m, InhibitWhat inhibit_key, HandleAction handle, bool ignore_inhibited, bool is_edge);

const char *handle_action_to_string(HandleAction h) _const_;
HandleAction handle_action_from_string(const char *s) _pure_;

const char *manager_target_for_action(HandleAction handle);

CONFIG_PARSER_PROTOTYPE(config_parse_handle_action);
