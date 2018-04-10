/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering
***/

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
        _HANDLE_ACTION_MAX,
        _HANDLE_ACTION_INVALID = -1
} HandleAction;

#include "logind-inhibit.h"
#include "logind.h"

int manager_handle_action(
                Manager *m,
                InhibitWhat inhibit_key,
                HandleAction handle,
                bool ignore_inhibited,
                bool is_edge);

const char* handle_action_to_string(HandleAction h) _const_;
HandleAction handle_action_from_string(const char *s) _pure_;

int config_parse_handle_action(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
