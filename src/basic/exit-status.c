/* SPDX-License-Identifier: LGPL-2.1+ */

#include <signal.h>
#include <stdlib.h>
#include <sysexits.h>

#include "exit-status.h"
#include "macro.h"
#include "set.h"

const char* exit_status_to_string(int status, ExitStatusLevel level) {

        /* Exit status ranges:
         *
         *   0…1   │ ISO C, EXIT_SUCCESS + EXIT_FAILURE
         *   2…7   │ LSB exit codes for init scripts
         *   8…63  │ (Currently unmapped)
         *  64…78  │ BSD defined exit codes
         *  79…199 │ (Currently unmapped)
         * 200…241 │ systemd's private error codes (might be extended to 254 in future development)
         * 242…254 │ (Currently unmapped, but see above)
         *   255   │ (We should probably stay away from that one, it's frequently used by applications to indicate an
         *         │ exit reason that cannot really be expressed in a single exit status value — such as a propagated
         *         │ signal or such)
         */

        switch (status) {  /* We always cover the ISO C ones */

        case EXIT_SUCCESS:
                return "SUCCESS";

        case EXIT_FAILURE:
                return "FAILURE";
        }

        if (IN_SET(level, EXIT_STATUS_SYSTEMD, EXIT_STATUS_LSB, EXIT_STATUS_FULL)) {
                switch (status) { /* Optionally we cover our own ones */

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

                case EXIT_SMACK_PROCESS_LABEL:
                        return "SMACK_PROCESS_LABEL";

                case EXIT_KEYRING:
                        return "KEYRING";

                case EXIT_STATE_DIRECTORY:
                        return "STATE_DIRECTORY";

                case EXIT_CACHE_DIRECTORY:
                        return "CACHE_DIRECTORY";

                case EXIT_LOGS_DIRECTORY:
                        return "LOGS_DIRECTORY";

                case EXIT_CONFIGURATION_DIRECTORY:
                        return "CONFIGURATION_DIRECTORY";
                }
        }

        if (IN_SET(level, EXIT_STATUS_LSB, EXIT_STATUS_FULL)) {
                switch (status) { /* Optionally we support LSB ones */

                case EXIT_INVALIDARGUMENT:
                        return "INVALIDARGUMENT";

                case EXIT_NOTIMPLEMENTED:
                        return "NOTIMPLEMENTED";

                case EXIT_NOPERMISSION:
                        return "NOPERMISSION";

                case EXIT_NOTINSTALLED:
                        return "NOTINSTALLED";

                case EXIT_NOTCONFIGURED:
                        return "NOTCONFIGURED";

                case EXIT_NOTRUNNING:
                        return "NOTRUNNING";
                }
        }

        if (level == EXIT_STATUS_FULL) {
                switch (status) { /* Optionally, we support BSD exit statusses */

                case EX_USAGE:
                        return "USAGE";

                case EX_DATAERR:
                        return "DATAERR";

                case EX_NOINPUT:
                        return "NOINPUT";

                case EX_NOUSER:
                        return "NOUSER";

                case EX_NOHOST:
                        return "NOHOST";

                case EX_UNAVAILABLE:
                        return "UNAVAILABLE";

                case EX_SOFTWARE:
                        return "SOFTWARE";

                case EX_OSERR:
                        return "OSERR";

                case EX_OSFILE:
                        return "OSFILE";

                case EX_CANTCREAT:
                        return "CANTCREAT";

                case EX_IOERR:
                        return "IOERR";

                case EX_TEMPFAIL:
                        return "TEMPFAIL";

                case EX_PROTOCOL:
                        return "PROTOCOL";

                case EX_NOPERM:
                        return "NOPERM";

                case EX_CONFIG:
                        return "CONFIG";
                }
        }

        return NULL;
}

bool is_clean_exit(int code, int status, ExitClean clean, ExitStatusSet *success_status) {

        if (code == CLD_EXITED)
                return status == 0 ||
                       (success_status &&
                        set_contains(success_status->status, INT_TO_PTR(status)));

        /* If a daemon does not implement handlers for some of the signals that's not considered an unclean shutdown */
        if (code == CLD_KILLED)
                return
                        (clean == EXIT_CLEAN_DAEMON && IN_SET(status, SIGHUP, SIGINT, SIGTERM, SIGPIPE)) ||
                        (success_status &&
                         set_contains(success_status->signal, INT_TO_PTR(status)));

        return false;
}

void exit_status_set_free(ExitStatusSet *x) {
        assert(x);

        x->status = set_free(x->status);
        x->signal = set_free(x->signal);
}

bool exit_status_set_is_empty(ExitStatusSet *x) {
        if (!x)
                return true;

        return set_isempty(x->status) && set_isempty(x->signal);
}

bool exit_status_set_test(ExitStatusSet *x, int code, int status) {

        if (exit_status_set_is_empty(x))
                return false;

        if (code == CLD_EXITED && set_contains(x->status, INT_TO_PTR(status)))
                return true;

        if (IN_SET(code, CLD_KILLED, CLD_DUMPED) && set_contains(x->signal, INT_TO_PTR(status)))
                return true;

        return false;
}
