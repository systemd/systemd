/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include <stdbool.h>

#include "set.h"

typedef enum ExitStatus {
        /* EXIT_SUCCESS defined by libc */
        /* EXIT_FAILURE defined by libc */
        EXIT_INVALIDARGUMENT = 2,
        EXIT_NOTIMPLEMENTED = 3,
        EXIT_NOPERMISSION = 4,
        EXIT_NOTINSTALLED = 5,
        EXIT_NOTCONFIGURED = 6,
        EXIT_NOTRUNNING = 7,

        /* The LSB suggests that error codes >= 200 are "reserved". We
         * use them here under the assumption that they hence are
         * unused by init scripts.
         *
         * http://refspecs.freestandards.org/LSB_3.1.0/LSB-Core-generic/LSB-Core-generic/iniscrptact.html */

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
        EXIT_MAKE_STARTER,
        EXIT_CHOWN,
} ExitStatus;

typedef enum ExitStatusLevel {
        EXIT_STATUS_MINIMAL,
        EXIT_STATUS_SYSTEMD,
        EXIT_STATUS_LSB,
        EXIT_STATUS_FULL = EXIT_STATUS_LSB
} ExitStatusLevel;

typedef struct ExitStatusSet {
        Set *status;
        Set *signal;
} ExitStatusSet;

const char* exit_status_to_string(ExitStatus status, ExitStatusLevel level) _const_;

bool is_clean_exit(int code, int status, ExitStatusSet *success_status);
bool is_clean_exit_lsb(int code, int status, ExitStatusSet *success_status);

void exit_status_set_free(ExitStatusSet *x);
bool exit_status_set_is_empty(ExitStatusSet *x);
