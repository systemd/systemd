/* SPDX-License-Identifier: LGPL-2.1+ */

#include <signal.h>
#include <stdlib.h>
#include <sysexits.h>

#include "exit-status.h"
#include "macro.h"
#include "set.h"

const ExitStatusMapping exit_status_mappings[256] = {
        /* Exit status ranges:
         *
         *   0…1   │ ISO C, EXIT_SUCCESS + EXIT_FAILURE
         *   2…7   │ LSB exit codes for init scripts
         *   8…63  │ (Currently unmapped)
         *  64…78  │ BSD defined exit codes
         *  79…199 │ (Currently unmapped)
         * 200…241 │ systemd's private error codes (might be extended to 254 in future development)
         * 242…254 │ (Currently unmapped, but see above)
         *
         *   255   │ EXIT_EXCEPTION (We use this to propagate exit-by-signal events. It's frequently used by others apps (like bash)
         *         │ to indicate exit reason that cannot really be expressed in a single exit status value — such as a propagated
         *         │ signal or such, and we follow that logic here.)
         */

        [EXIT_SUCCESS] =                 { "SUCCESS",                 EXIT_STATUS_GLIBC },
        [EXIT_FAILURE] =                 { "FAILURE",                 EXIT_STATUS_GLIBC },

        [EXIT_CHDIR] =                   { "CHDIR",                   EXIT_STATUS_SYSTEMD },
        [EXIT_NICE] =                    { "NICE",                    EXIT_STATUS_SYSTEMD },
        [EXIT_FDS] =                     { "FDS",                     EXIT_STATUS_SYSTEMD },
        [EXIT_EXEC] =                    { "EXEC",                    EXIT_STATUS_SYSTEMD },
        [EXIT_MEMORY] =                  { "MEMORY",                  EXIT_STATUS_SYSTEMD },
        [EXIT_LIMITS] =                  { "LIMITS",                  EXIT_STATUS_SYSTEMD },
        [EXIT_OOM_ADJUST] =              { "OOM_ADJUST",              EXIT_STATUS_SYSTEMD },
        [EXIT_SIGNAL_MASK] =             { "SIGNAL_MASK",             EXIT_STATUS_SYSTEMD },
        [EXIT_STDIN] =                   { "STDIN",                   EXIT_STATUS_SYSTEMD },
        [EXIT_STDOUT] =                  { "STDOUT",                  EXIT_STATUS_SYSTEMD },
        [EXIT_CHROOT] =                  { "CHROOT",                  EXIT_STATUS_SYSTEMD },
        [EXIT_IOPRIO] =                  { "IOPRIO",                  EXIT_STATUS_SYSTEMD },
        [EXIT_TIMERSLACK] =              { "TIMERSLACK",              EXIT_STATUS_SYSTEMD },
        [EXIT_SECUREBITS] =              { "SECUREBITS",              EXIT_STATUS_SYSTEMD },
        [EXIT_SETSCHEDULER] =            { "SETSCHEDULER",            EXIT_STATUS_SYSTEMD },
        [EXIT_CPUAFFINITY] =             { "CPUAFFINITY",             EXIT_STATUS_SYSTEMD },
        [EXIT_GROUP] =                   { "GROUP",                   EXIT_STATUS_SYSTEMD },
        [EXIT_USER] =                    { "USER",                    EXIT_STATUS_SYSTEMD },
        [EXIT_CAPABILITIES] =            { "CAPABILITIES",            EXIT_STATUS_SYSTEMD },
        [EXIT_CGROUP] =                  { "CGROUP",                  EXIT_STATUS_SYSTEMD },
        [EXIT_SETSID] =                  { "SETSID",                  EXIT_STATUS_SYSTEMD },
        [EXIT_CONFIRM] =                 { "CONFIRM",                 EXIT_STATUS_SYSTEMD },
        [EXIT_STDERR] =                  { "STDERR",                  EXIT_STATUS_SYSTEMD },
        [EXIT_PAM] =                     { "PAM",                     EXIT_STATUS_SYSTEMD },
        [EXIT_NETWORK] =                 { "NETWORK",                 EXIT_STATUS_SYSTEMD },
        [EXIT_NAMESPACE] =               { "NAMESPACE",               EXIT_STATUS_SYSTEMD },
        [EXIT_NO_NEW_PRIVILEGES] =       { "NO_NEW_PRIVILEGES",       EXIT_STATUS_SYSTEMD },
        [EXIT_SECCOMP] =                 { "SECCOMP",                 EXIT_STATUS_SYSTEMD },
        [EXIT_SELINUX_CONTEXT] =         { "SELINUX_CONTEXT",         EXIT_STATUS_SYSTEMD },
        [EXIT_PERSONALITY] =             { "PERSONALITY",             EXIT_STATUS_SYSTEMD },
        [EXIT_APPARMOR_PROFILE] =        { "APPARMOR",                EXIT_STATUS_SYSTEMD },
        [EXIT_ADDRESS_FAMILIES] =        { "ADDRESS_FAMILIES",        EXIT_STATUS_SYSTEMD },
        [EXIT_RUNTIME_DIRECTORY] =       { "RUNTIME_DIRECTORY",       EXIT_STATUS_SYSTEMD },
        [EXIT_CHOWN] =                   { "CHOWN",                   EXIT_STATUS_SYSTEMD },
        [EXIT_SMACK_PROCESS_LABEL] =     { "SMACK_PROCESS_LABEL",     EXIT_STATUS_SYSTEMD },
        [EXIT_KEYRING] =                 { "KEYRING",                 EXIT_STATUS_SYSTEMD },
        [EXIT_STATE_DIRECTORY] =         { "STATE_DIRECTORY",         EXIT_STATUS_SYSTEMD },
        [EXIT_CACHE_DIRECTORY] =         { "CACHE_DIRECTORY",         EXIT_STATUS_SYSTEMD },
        [EXIT_LOGS_DIRECTORY] =          { "LOGS_DIRECTORY",          EXIT_STATUS_SYSTEMD },
        [EXIT_CONFIGURATION_DIRECTORY] = { "CONFIGURATION_DIRECTORY", EXIT_STATUS_SYSTEMD },
        [EXIT_NUMA_POLICY] =             { "NUMA_POLICY",             EXIT_STATUS_SYSTEMD },
        [EXIT_EXCEPTION] =               { "EXCEPTION",               EXIT_STATUS_SYSTEMD },

        [EXIT_INVALIDARGUMENT] =         { "INVALIDARGUMENT",         EXIT_STATUS_LSB },
        [EXIT_NOTIMPLEMENTED] =          { "NOTIMPLEMENTED",          EXIT_STATUS_LSB },
        [EXIT_NOPERMISSION] =            { "NOPERMISSION",            EXIT_STATUS_LSB },
        [EXIT_NOTINSTALLED] =            { "NOTINSTALLED",            EXIT_STATUS_LSB },
        [EXIT_NOTCONFIGURED] =           { "NOTCONFIGURED",           EXIT_STATUS_LSB },
        [EXIT_NOTRUNNING] =              { "NOTRUNNING",              EXIT_STATUS_LSB },

        [EX_USAGE] =                     { "USAGE",                   EXIT_STATUS_BSD },
        [EX_DATAERR] =                   { "DATAERR",                 EXIT_STATUS_BSD },
        [EX_NOINPUT] =                   { "NOINPUT",                 EXIT_STATUS_BSD },
        [EX_NOUSER] =                    { "NOUSER",                  EXIT_STATUS_BSD },
        [EX_NOHOST] =                    { "NOHOST",                  EXIT_STATUS_BSD },
        [EX_UNAVAILABLE] =               { "UNAVAILABLE",             EXIT_STATUS_BSD },
        [EX_SOFTWARE] =                  { "SOFTWARE",                EXIT_STATUS_BSD },
        [EX_OSERR] =                     { "OSERR",                   EXIT_STATUS_BSD },
        [EX_OSFILE] =                    { "OSFILE",                  EXIT_STATUS_BSD },
        [EX_CANTCREAT] =                 { "CANTCREAT",               EXIT_STATUS_BSD },
        [EX_IOERR] =                     { "IOERR",                   EXIT_STATUS_BSD },
        [EX_TEMPFAIL] =                  { "TEMPFAIL",                EXIT_STATUS_BSD },
        [EX_PROTOCOL] =                  { "PROTOCOL",                EXIT_STATUS_BSD },
        [EX_NOPERM] =                    { "NOPERM",                  EXIT_STATUS_BSD },
        [EX_CONFIG] =                    { "CONFIG",                  EXIT_STATUS_BSD },
};

const char* exit_status_to_string(int code, ExitStatusClass class) {
        if (code < 0 || (size_t) code >= ELEMENTSOF(exit_status_mappings))
                return NULL;
        return FLAGS_SET(exit_status_mappings[code].class, class) ? exit_status_mappings[code].name : NULL;
}

const char* exit_status_class(int code) {
        if (code < 0 || (size_t) code >= ELEMENTSOF(exit_status_mappings))
                return NULL;

        switch (exit_status_mappings[code].class) {
        case EXIT_STATUS_GLIBC:
                return "glibc";
        case EXIT_STATUS_SYSTEMD:
                return "systemd";
        case EXIT_STATUS_LSB:
                return "LSB";
        case EXIT_STATUS_BSD:
                return "BSD";
        default: return NULL;
        }
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
