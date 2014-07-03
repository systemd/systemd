/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <stdlib.h>
#include <sys/wait.h>

#include "exit-status.h"
#include "set.h"
#include "macro.h"

const char* exit_status_to_string(ExitStatus status, ExitStatusLevel level) {

        /* We cast to int here, so that -Wenum doesn't complain that
         * EXIT_SUCCESS/EXIT_FAILURE aren't in the enum */

        switch ((int) status) {

        case EXIT_SUCCESS:
                return "SUCCESS";

        case EXIT_FAILURE:
                return "FAILURE";
        }


        if (level == EXIT_STATUS_SYSTEMD || level == EXIT_STATUS_LSB) {
                switch ((int) status) {

                case EXIT_CHDIR:
                        return "CHDIR";

                case EXIT_NICE:
                        return "NICE";

                case EXIT_FDS:
                        return "FDS";

                case EXIT_EXEC:
                        return "EXEC";

                case EXIT_MEMORY:
                        return "MEMORY";

                case EXIT_LIMITS:
                        return "LIMITS";

                case EXIT_OOM_ADJUST:
                        return "OOM_ADJUST";

                case EXIT_SIGNAL_MASK:
                        return "SIGNAL_MASK";

                case EXIT_STDIN:
                        return "STDIN";

                case EXIT_STDOUT:
                        return "STDOUT";

                case EXIT_CHROOT:
                        return "CHROOT";

                case EXIT_IOPRIO:
                        return "IOPRIO";

                case EXIT_TIMERSLACK:
                        return "TIMERSLACK";

                case EXIT_SECUREBITS:
                        return "SECUREBITS";

                case EXIT_SETSCHEDULER:
                        return "SETSCHEDULER";

                case EXIT_CPUAFFINITY:
                        return "CPUAFFINITY";

                case EXIT_GROUP:
                        return "GROUP";

                case EXIT_USER:
                        return "USER";

                case EXIT_CAPABILITIES:
                        return "CAPABILITIES";

                case EXIT_CGROUP:
                        return "CGROUP";

                case EXIT_SETSID:
                        return "SETSID";

                case EXIT_CONFIRM:
                        return "CONFIRM";

                case EXIT_STDERR:
                        return "STDERR";

                case EXIT_PAM:
                        return "PAM";

                case EXIT_NETWORK:
                        return "NETWORK";

                case EXIT_NAMESPACE:
                        return "NAMESPACE";

                case EXIT_NO_NEW_PRIVILEGES:
                        return "NO_NEW_PRIVILEGES";

                case EXIT_SECCOMP:
                        return "SECCOMP";

                case EXIT_SELINUX_CONTEXT:
                        return "SELINUX_CONTEXT";

                case EXIT_PERSONALITY:
                        return "PERSONALITY";

                case EXIT_APPARMOR_PROFILE:
                        return "APPARMOR";

                case EXIT_ADDRESS_FAMILIES:
                        return "ADDRESS_FAMILIES";

                case EXIT_RUNTIME_DIRECTORY:
                        return "RUNTIME_DIRECTORY";

                case EXIT_CHOWN:
                        return "CHOWN";

                case EXIT_MAKE_STARTER:
                        return "MAKE_STARTER";
                }
        }

        if (level == EXIT_STATUS_LSB) {
                switch ((int) status) {

                case EXIT_INVALIDARGUMENT:
                        return "INVALIDARGUMENT";

                case EXIT_NOTIMPLEMENTED:
                        return "NOTIMPLEMENTED";

                case EXIT_NOPERMISSION:
                        return "NOPERMISSION";

                case EXIT_NOTINSTALLED:
                        return "NOTINSSTALLED";

                case EXIT_NOTCONFIGURED:
                        return "NOTCONFIGURED";

                case EXIT_NOTRUNNING:
                        return "NOTRUNNING";
                }
        }

        return NULL;
}


bool is_clean_exit(int code, int status, ExitStatusSet *success_status) {

        if (code == CLD_EXITED)
                return status == 0 ||
                       (success_status &&
                       set_contains(success_status->status, INT_TO_PTR(status)));

        /* If a daemon does not implement handlers for some of the
         * signals that's not considered an unclean shutdown */
        if (code == CLD_KILLED)
                return
                        status == SIGHUP ||
                        status == SIGINT ||
                        status == SIGTERM ||
                        status == SIGPIPE ||
                        (success_status &&
                        set_contains(success_status->signal, INT_TO_PTR(status)));

        return false;
}

bool is_clean_exit_lsb(int code, int status, ExitStatusSet *success_status) {

        if (is_clean_exit(code, status, success_status))
                return true;

        return
                code == CLD_EXITED &&
                (status == EXIT_NOTINSTALLED || status == EXIT_NOTCONFIGURED);
}

void exit_status_set_free(ExitStatusSet *x) {
        assert(x);

        set_free(x->status);
        set_free(x->signal);
        x->status = x->signal = NULL;
}

bool exit_status_set_is_empty(ExitStatusSet *x) {
        if (!x)
                return true;

        return set_isempty(x->status) && set_isempty(x->signal);
}
