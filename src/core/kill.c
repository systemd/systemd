/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "util.h"
#include "signal-util.h"
#include "kill.h"

void kill_context_init(KillContext *c) {
        assert(c);

        c->kill_signal = SIGTERM;
        c->send_sigkill = true;
        c->send_sighup = false;
}

void kill_context_dump(KillContext *c, FILE *f, const char *prefix) {
        assert(c);

        if (!prefix)
                prefix = "";

        fprintf(f,
                "%sKillMode: %s\n"
                "%sKillSignal: SIG%s\n"
                "%sSendSIGKILL: %s\n"
                "%sSendSIGHUP:  %s\n",
                prefix, kill_mode_to_string(c->kill_mode),
                prefix, signal_to_string(c->kill_signal),
                prefix, yes_no(c->send_sigkill),
                prefix, yes_no(c->send_sighup));
}

static const char* const kill_mode_table[_KILL_MODE_MAX] = {
        [KILL_CONTROL_GROUP] = "control-group",
        [KILL_PROCESS] = "process",
        [KILL_MIXED] = "mixed",
        [KILL_NONE] = "none"
};

DEFINE_STRING_TABLE_LOOKUP(kill_mode, KillMode);

static const char* const kill_who_table[_KILL_WHO_MAX] = {
        [KILL_MAIN] = "main",
        [KILL_CONTROL] = "control",
        [KILL_ALL] = "all",
        [KILL_MAIN_FAIL] = "main-fail",
        [KILL_CONTROL_FAIL] = "control-fail",
        [KILL_ALL_FAIL] = "all-fail"
};

DEFINE_STRING_TABLE_LOOKUP(kill_who, KillWho);
