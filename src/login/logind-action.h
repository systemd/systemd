/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
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
        HANDLE_LOCK,
        _HANDLE_ACTION_MAX,
        _HANDLE_ACTION_INVALID = -1
} HandleAction;

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
