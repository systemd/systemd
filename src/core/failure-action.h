/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering
  Copyright 2012 Michael Olbrich

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

typedef enum FailureAction {
        FAILURE_ACTION_NONE,
        FAILURE_ACTION_REBOOT,
        FAILURE_ACTION_REBOOT_FORCE,
        FAILURE_ACTION_REBOOT_IMMEDIATE,
        FAILURE_ACTION_POWEROFF,
        FAILURE_ACTION_POWEROFF_FORCE,
        FAILURE_ACTION_POWEROFF_IMMEDIATE,
        _FAILURE_ACTION_MAX,
        _FAILURE_ACTION_INVALID = -1
} FailureAction;

#include "macro.h"
#include "manager.h"

int failure_action(Manager *m, FailureAction action, const char *reboot_arg);

const char* failure_action_to_string(FailureAction i) _const_;
FailureAction failure_action_from_string(const char *s) _pure_;
