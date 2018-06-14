/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "hashmap.h"
#include "macro.h"
#include "set.h"

/* This defines pretty names for the LSB 'start' verb exit codes. Note that they shouldn't be confused with the LSB
 * 'status' verb exit codes which are defined very differently. For details see:
 *
 * https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/iniscrptact.html
 */

enum {
        /* EXIT_SUCCESS defined by libc */
        /* EXIT_FAILURE defined by libc */
        EXIT_INVALIDARGUMENT = 2,
        EXIT_NOTIMPLEMENTED = 3,
        EXIT_NOPERMISSION = 4,
        EXIT_NOTINSTALLED = 5,
        EXIT_NOTCONFIGURED = 6,
        EXIT_NOTRUNNING = 7,

        /* BSD's sysexits.h defines a couple EX_xyz exit codes in the range 64 … 78 */

        /* The LSB suggests that error codes >= 200 are "reserved". We use them here under the assumption that they
         * hence are unused by init scripts. */
        EXIT_CHDIR = 200,
        EXIT_NICE,
        EXIT_FDS,
        EXIT_EXEC,
        EXIT_MEMORY,
        EXIT_LIMITS,
        EXIT_OOM_ADJUST,
        EXIT_SIGNAL_MASK,
        EXIT_STDIN,
        EXIT_STDOUT,
        EXIT_CHROOT,   /* 210 */
        EXIT_IOPRIO,
        EXIT_TIMERSLACK,
        EXIT_SECUREBITS,
        EXIT_SETSCHEDULER,
        EXIT_CPUAFFINITY,
        EXIT_GROUP,
        EXIT_USER,
        EXIT_CAPABILITIES,
        EXIT_CGROUP,
        EXIT_SETSID,   /* 220 */
        EXIT_CONFIRM,
        EXIT_STDERR,
        _EXIT_RESERVED, /* used to be tcpwrap, don't reuse! */
        EXIT_PAM,
        EXIT_NETWORK,
        EXIT_NAMESPACE,
        EXIT_NO_NEW_PRIVILEGES,
        EXIT_SECCOMP,
        EXIT_SELINUX_CONTEXT,
        EXIT_PERSONALITY,  /* 230 */
        EXIT_APPARMOR_PROFILE,
        EXIT_ADDRESS_FAMILIES,
        EXIT_RUNTIME_DIRECTORY,
        _EXIT_RESERVED2, /* used to be used by kdbus, don't reuse */
        EXIT_CHOWN,
        EXIT_SMACK_PROCESS_LABEL,
        EXIT_KEYRING,
        EXIT_STATE_DIRECTORY,
        EXIT_CACHE_DIRECTORY,
        EXIT_LOGS_DIRECTORY, /* 240 */
        EXIT_CONFIGURATION_DIRECTORY,
};

typedef enum ExitStatusLevel {
        EXIT_STATUS_MINIMAL,   /* only cover libc EXIT_STATUS/EXIT_FAILURE */
        EXIT_STATUS_SYSTEMD,   /* cover libc and systemd's own exit codes */
        EXIT_STATUS_LSB,       /* cover libc, systemd's own and LSB exit codes */
        EXIT_STATUS_FULL,      /* cover libc, systemd's own, LSB and BSD (EX_xyz) exit codes */
} ExitStatusLevel;

typedef struct ExitStatusSet {
        Set *status;
        Set *signal;
} ExitStatusSet;

const char* exit_status_to_string(int status, ExitStatusLevel level) _const_;

typedef enum ExitClean {
        EXIT_CLEAN_DAEMON,
        EXIT_CLEAN_COMMAND,
} ExitClean;

bool is_clean_exit(int code, int status, ExitClean clean, ExitStatusSet *success_status);

void exit_status_set_free(ExitStatusSet *x);
bool exit_status_set_is_empty(ExitStatusSet *x);
bool exit_status_set_test(ExitStatusSet *x, int code, int status);
