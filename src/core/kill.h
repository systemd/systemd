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

typedef struct KillContext KillContext;

#include <stdbool.h>
#include <stdio.h>

#include "macro.h"

typedef enum KillMode {
        /* The kill mode is a property of a unit. */
        KILL_CONTROL_GROUP = 0,
        KILL_PROCESS,
        KILL_MIXED,
        KILL_NONE,
        _KILL_MODE_MAX,
        _KILL_MODE_INVALID = -1
} KillMode;

struct KillContext {
        KillMode kill_mode;
        int kill_signal;
        bool send_sigkill;
        bool send_sighup;
};

typedef enum KillWho {
        /* Kill who is a property of an operation */
        KILL_MAIN,
        KILL_CONTROL,
        KILL_ALL,
        KILL_MAIN_FAIL,
        KILL_CONTROL_FAIL,
        KILL_ALL_FAIL,
        _KILL_WHO_MAX,
        _KILL_WHO_INVALID = -1
} KillWho;

void kill_context_init(KillContext *c);
void kill_context_dump(KillContext *c, FILE *f, const char *prefix);

const char *kill_mode_to_string(KillMode k) _const_;
KillMode kill_mode_from_string(const char *s) _pure_;

const char *kill_who_to_string(KillWho k) _const_;
KillWho kill_who_from_string(const char *s) _pure_;
