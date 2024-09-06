/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "kill.h"
#include "signal-util.h"
#include "string-table.h"

void kill_context_init(KillContext *c) {
        assert(c);

        c->kill_signal = SIGTERM;
        /* restart_kill_signal is unset by default and we fall back to kill_signal */
        c->final_kill_signal = SIGKILL;
        c->send_sigkill = true;
        c->send_sighup = false;
        c->watchdog_signal = SIGABRT;
}

void kill_context_dump(KillContext *c, FILE *f, const char *prefix) {
        assert(c);

        prefix = strempty(prefix);

        fprintf(f,
                "%sKillMode: %s\n"
                "%sKillSignal: SIG%s\n"
                "%sRestartKillSignal: SIG%s\n"
                "%sFinalKillSignal: SIG%s\n"
                "%sSendSIGKILL: %s\n"
                "%sSendSIGHUP: %s\n",
                prefix, kill_mode_to_string(c->kill_mode),
                prefix, signal_to_string(c->kill_signal),
                prefix, signal_to_string(restart_kill_signal(c)),
                prefix, signal_to_string(c->final_kill_signal),
                prefix, yes_no(c->send_sigkill),
                prefix, yes_no(c->send_sighup));
}

static const char* const kill_mode_table[_KILL_MODE_MAX] = {
        [KILL_CONTROL_GROUP] = "control-group",
        [KILL_PROCESS]       = "process",
        [KILL_MIXED]         = "mixed",
        [KILL_NONE]          = "none",
};

DEFINE_STRING_TABLE_LOOKUP(kill_mode, KillMode);

static const char* const kill_whom_table[_KILL_WHOM_MAX] = {
        [KILL_MAIN]         = "main",
        [KILL_CONTROL]      = "control",
        [KILL_ALL]          = "all",
        [KILL_MAIN_FAIL]    = "main-fail",
        [KILL_CONTROL_FAIL] = "control-fail",
        [KILL_ALL_FAIL]     = "all-fail",
};

DEFINE_STRING_TABLE_LOOKUP(kill_whom, KillWhom);
