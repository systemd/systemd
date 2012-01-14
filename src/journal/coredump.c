/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <unistd.h>

#include <systemd/sd-journal.h>
#include <systemd/sd-login.h>

#include "log.h"
#include "util.h"

#define COREDUMP_MAX (24*1024*1024)

enum {
        ARG_PID = 1,
        ARG_UID,
        ARG_GID,
        ARG_SIGNAL,
        ARG_TIMESTAMP,
        ARG_COMM,
        _ARG_MAX
};

int main(int argc, char* argv[]) {
        int r, j = 0;
        char *p = NULL;
        ssize_t n;
        pid_t pid;
        uid_t uid;
        gid_t gid;
        struct iovec iovec[14];
        char *core_pid = NULL, *core_uid = NULL, *core_gid = NULL, *core_signal = NULL,
                *core_timestamp = NULL, *core_comm = NULL, *core_exe = NULL, *core_unit = NULL,
                *core_session = NULL, *core_message = NULL, *core_cmdline = NULL, *t;

        log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
        log_parse_environment();
        log_open();

        if (argc != _ARG_MAX) {
                log_error("Invalid number of arguments passed from kernel.");
                r = -EINVAL;
                goto finish;
        }

        r = parse_pid(argv[ARG_PID], &pid);
        if (r < 0) {
                log_error("Failed to parse PID.");
                goto finish;
        }

        r = parse_uid(argv[ARG_UID], &uid);
        if (r < 0) {
                log_error("Failed to parse UID.");
                goto finish;
        }

        r = parse_gid(argv[ARG_GID], &gid);
        if (r < 0) {
                log_error("Failed to parse GID.");
                goto finish;
        }

        core_pid = strappend("COREDUMP_PID=", argv[ARG_PID]);
        if (core_pid)
                IOVEC_SET_STRING(iovec[j++], core_pid);

        core_uid = strappend("COREDUMP_UID=", argv[ARG_UID]);
        if (core_uid)
                IOVEC_SET_STRING(iovec[j++], core_uid);

        core_gid = strappend("COREDUMP_GID=", argv[ARG_GID]);
        if (core_gid)
                IOVEC_SET_STRING(iovec[j++], core_gid);

        core_signal = strappend("COREDUMP_SIGNAL=", argv[ARG_SIGNAL]);
        if (core_signal)
                IOVEC_SET_STRING(iovec[j++], core_signal);

        core_comm = strappend("COREDUMP_COMM=", argv[ARG_COMM]);
        if (core_comm)
                IOVEC_SET_STRING(iovec[j++], core_comm);

        if (sd_pid_get_session(pid, &t) >= 0) {
                core_session = strappend("COREDUMP_SESSION=", t);
                free(t);

                if (core_session)
                        IOVEC_SET_STRING(iovec[j++], core_session);
        }

        if (sd_pid_get_unit(pid, &t) >= 0) {
                core_unit = strappend("COREDUMP_UNIT=", t);
                free(t);

                if (core_unit)
                        IOVEC_SET_STRING(iovec[j++], core_unit);
        }

        if (get_process_exe(pid, &t) >= 0) {
                core_exe = strappend("COREDUMP_EXE=", t);
                free(t);

                if (core_exe)
                        IOVEC_SET_STRING(iovec[j++], core_exe);
        }

        if (get_process_cmdline(pid, LINE_MAX, false, &t) >= 0) {
                core_cmdline = strappend("COREDUMP_CMDLINE=", t);
                free(t);

                if (core_cmdline)
                        IOVEC_SET_STRING(iovec[j++], core_cmdline);
        }

        core_timestamp = join("COREDUMP_TIMESTAMP=", argv[ARG_TIMESTAMP], "000000", NULL);
        if (core_timestamp)
                IOVEC_SET_STRING(iovec[j++], core_timestamp);

        IOVEC_SET_STRING(iovec[j++], "MESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1");
        IOVEC_SET_STRING(iovec[j++], "PRIORITY=2");

        core_message = join("MESSAGE=Process ", argv[ARG_PID], " (", argv[ARG_COMM], ") dumped core.", NULL);
        if (core_message)
                IOVEC_SET_STRING(iovec[j++], core_message);

        /* Now, let's drop privileges to become the user who owns the
         * segfaulted process and allocate the coredump memory under
         * his uid. This also ensures that the credentials journald
         * will see are the ones of the coredumping user, thus making
         * sure the user himself gets access to the core dump. */

        if (setresgid(gid, gid, gid) < 0 ||
            setresuid(uid, uid, uid) < 0) {
                log_error("Failed to drop privileges: %m");
                r = -errno;
                goto finish;
        }

        p = malloc(9 + COREDUMP_MAX);
        if (!p) {
                log_error("Out of memory");
                r = -ENOMEM;
                goto finish;
        }

        memcpy(p, "COREDUMP=", 9);

        n = loop_read(STDIN_FILENO, p + 9, COREDUMP_MAX, false);
        if (n < 0) {
                log_error("Failed to read core dump data: %s", strerror(-n));
                r = (int) n;
                goto finish;
        }

        iovec[j].iov_base = p;
        iovec[j].iov_len = 9 + n;
        j++;

        r = sd_journal_sendv(iovec, j);
        if (r < 0)
                log_error("Failed to send coredump: %s", strerror(-r));

finish:
        free(p);
        free(core_pid);
        free(core_uid);
        free(core_gid);
        free(core_signal);
        free(core_timestamp);
        free(core_comm);
        free(core_exe);
        free(core_cmdline);
        free(core_unit);
        free(core_session);
        free(core_message);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
