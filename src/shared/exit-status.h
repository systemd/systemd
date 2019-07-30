/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "bitmap.h"
#include "hashmap.h"
#include "macro.h"

/* This defines pretty names for the LSB 'start' verb exit codes. Note that they shouldn't be confused with
 * the LSB 'status' verb exit codes which are defined very differently. For details see:
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

        /* The LSB suggests that error codes >= 200 are "reserved". We use them here under the assumption
         * that they hence are unused by init scripts. */
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
        EXIT_NUMA_POLICY,

        EXIT_EXCEPTION = 255,  /* Whenever we want to propagate an abnormal/signal exit, in line with bash */
};

typedef enum ExitStatusClass {
        EXIT_STATUS_LIBC    = 1 << 0,  /* libc EXIT_STATUS/EXIT_FAILURE */
        EXIT_STATUS_SYSTEMD = 1 << 1,  /* systemd's own exit codes */
        EXIT_STATUS_LSB     = 1 << 2,  /* LSB exit codes */
        EXIT_STATUS_BSD     = 1 << 3,  /* BSD (EX_xyz) exit codes */
        EXIT_STATUS_FULL    = EXIT_STATUS_LIBC | EXIT_STATUS_SYSTEMD | EXIT_STATUS_LSB | EXIT_STATUS_BSD,
} ExitStatusClass;

typedef struct ExitStatusSet {
        Bitmap status;
        Bitmap signal;
} ExitStatusSet;

const char* exit_status_to_string(int code, ExitStatusClass class) _const_;
const char* exit_status_class(int code) _const_;
int exit_status_from_string(const char *s) _pure_;

typedef struct ExitStatusMapping {
        const char *name;
        ExitStatusClass class;
} ExitStatusMapping;

extern const ExitStatusMapping exit_status_mappings[256];

typedef enum ExitClean {
        EXIT_CLEAN_DAEMON,
        EXIT_CLEAN_COMMAND,
} ExitClean;

bool is_clean_exit(int code, int status, ExitClean clean, const ExitStatusSet *success_status);

void exit_status_set_free(ExitStatusSet *x);
bool exit_status_set_is_empty(const ExitStatusSet *x);
bool exit_status_set_test(const ExitStatusSet *x, int code, int status);
