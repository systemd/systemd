/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"

typedef enum HandleAction {
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
        HANDLE_FACTORY_RESET,
        _HANDLE_ACTION_MAX,
        _HANDLE_ACTION_INVALID = -EINVAL,
} HandleAction;

typedef struct HandleActionData HandleActionData;

#include "logind-inhibit.h"
#include "logind.h"
#include "sleep-config.h"

static inline bool handle_action_valid(HandleAction a) {
        return a >= 0 && a < _HANDLE_ACTION_MAX;
}

struct HandleActionData {
        HandleAction handle;
        const char *target;
        InhibitWhat inhibit_what;
        const char *polkit_action;
        const char *polkit_action_multiple_sessions;
        const char *polkit_action_ignore_inhibit;
        SleepOperation sleep_operation;
        const char* message_id;
        const char* message;
        const char* log_verb;
};

int manager_handle_action(
                Manager *m,
                InhibitWhat inhibit_key,
                HandleAction handle,
                bool ignore_inhibited,
                bool is_edge);

const char* handle_action_verb_to_string(HandleAction h) _const_;

const char* handle_action_to_string(HandleAction h) _const_;
HandleAction handle_action_from_string(const char *s) _pure_;

const HandleActionData* handle_action_lookup(HandleAction handle);

CONFIG_PARSER_PROTOTYPE(config_parse_handle_action);
