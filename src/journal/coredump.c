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

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/prctl.h>

#include <systemd/sd-journal.h>

#ifdef HAVE_LOGIND
#include <systemd/sd-login.h>
#endif

#include "log.h"
#include "util.h"
#include "macro.h"
#include "mkdir.h"
#include "special.h"
#include "cgroup-util.h"
#include "journald-native.h"

/* Few programs have less than 3MiB resident */
#define COREDUMP_MIN_START (3*1024*1024u)
/* Make sure to not make this larger than the maximum journal entry
 * size. See ENTRY_SIZE_MAX in journald-native.c. */
#define COREDUMP_MAX (767*1024*1024u)
assert_cc(COREDUMP_MAX <= ENTRY_SIZE_MAX);

enum {
        ARG_PID = 1,
        ARG_UID,
        ARG_GID,
        ARG_SIGNAL,
        ARG_TIMESTAMP,
        ARG_COMM,
        _ARG_MAX
};

static int divert_coredump(void) {
        _cleanup_fclose_ FILE *f = NULL;

        log_info("Detected coredump of the journal daemon itself, diverting coredump to /var/lib/systemd/coredump/.");

        mkdir_p_label("/var/lib/systemd/coredump", 0755);

        f = fopen("/var/lib/systemd/coredump/core.systemd-journald", "we");
        if (!f) {
                log_error("Failed to create coredump file: %m");
                return -errno;
        }

        for (;;) {
                uint8_t buffer[4096];
                size_t l, q;

                l = fread(buffer, 1, sizeof(buffer), stdin);
                if (l <= 0) {
                        if (ferror(f)) {
                                log_error("Failed to read coredump: %m");
                                return -errno;
                        }

                        break;
                }

                q = fwrite(buffer, 1, l, f);
                if (q != l) {
                        log_error("Failed to write coredump: %m");
                        return -errno;
                }
        }

        fflush(f);

        if (ferror(f)) {
                log_error("Failed to write coredump: %m");
                return -errno;
        }

        return 0;
}

int main(int argc, char* argv[]) {
        int r, j = 0;
        char *t;
        ssize_t n;
        pid_t pid;
        uid_t uid;
        gid_t gid;
        struct iovec iovec[14];
        size_t coredump_bufsize = 0, coredump_size = 0;
        _cleanup_free_ char *core_pid = NULL, *core_uid = NULL, *core_gid = NULL, *core_signal = NULL,
                *core_timestamp = NULL, *core_comm = NULL, *core_exe = NULL, *core_unit = NULL,
                *core_session = NULL, *core_message = NULL, *core_cmdline = NULL, *coredump_data = NULL;

        prctl(PR_SET_DUMPABLE, 0);

        if (argc != _ARG_MAX) {
                log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
                log_open();

                log_error("Invalid number of arguments passed from kernel.");
                r = -EINVAL;
                goto finish;
        }

        r = parse_pid(argv[ARG_PID], &pid);
        if (r < 0) {
                log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
                log_open();

                log_error("Failed to parse PID.");
                goto finish;
        }

        if (cg_pid_get_unit(pid, &t) >= 0) {

                if (streq(t, SPECIAL_JOURNALD_SERVICE)) {
                        /* Make sure we don't make use of the journal,
                         * if it's the journal which is crashing */
                        log_set_target(LOG_TARGET_KMSG);
                        log_open();

                        r = divert_coredump();
                        goto finish;
                }

                core_unit = strappend("COREDUMP_UNIT=", t);
        } else if (cg_pid_get_user_unit(pid, &t) >= 0)
                core_unit = strappend("COREDUMP_USER_UNIT=", t);

        if (core_unit)
                IOVEC_SET_STRING(iovec[j++], core_unit);

        /* OK, now we know it's not the journal, hence make use of
         * it */
        log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
        log_open();

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

#ifdef HAVE_LOGIND
        if (sd_pid_get_session(pid, &t) >= 0) {
                core_session = strappend("COREDUMP_SESSION=", t);
                free(t);

                if (core_session)
                        IOVEC_SET_STRING(iovec[j++], core_session);
        }

#endif

        if (get_process_exe(pid, &t) >= 0) {
                core_exe = strappend("COREDUMP_EXE=", t);
                free(t);

                if (core_exe)
                        IOVEC_SET_STRING(iovec[j++], core_exe);
        }

        if (get_process_cmdline(pid, 0, false, &t) >= 0) {
                core_cmdline = strappend("COREDUMP_CMDLINE=", t);
                free(t);

                if (core_cmdline)
                        IOVEC_SET_STRING(iovec[j++], core_cmdline);
        }

        core_timestamp = strjoin("COREDUMP_TIMESTAMP=", argv[ARG_TIMESTAMP], "000000", NULL);
        if (core_timestamp)
                IOVEC_SET_STRING(iovec[j++], core_timestamp);

        IOVEC_SET_STRING(iovec[j++], "MESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1");
        IOVEC_SET_STRING(iovec[j++], "PRIORITY=2");

        core_message = strjoin("MESSAGE=Process ", argv[ARG_PID], " (", argv[ARG_COMM], ") dumped core.", NULL);
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

        for (;;) {
                if (!GREEDY_REALLOC(coredump_data, coredump_bufsize,
                                    MAX(coredump_size + 1, COREDUMP_MIN_START/2))) {
                        log_warning("Failed to allocate memory for core, core will not be stored.");
                        goto finalize;
                }

                if (coredump_size == 0) {
                        memcpy(coredump_data, "COREDUMP=", 9);
                        coredump_size = 9;
                }

                n = loop_read(STDIN_FILENO, coredump_data + coredump_size,
                              coredump_bufsize - coredump_size, false);
                if (n < 0) {
                        log_error("Failed to read core data: %s", strerror(-n));
                        r = (int) n;
                        goto finish;
                } else if (n == 0)
                        break;

                coredump_size += n;

                if (coredump_size > COREDUMP_MAX) {
                        log_error("Core too large, core will not be stored.");
                        goto finalize;
                }
        }

        iovec[j].iov_base = coredump_data;
        iovec[j].iov_len = coredump_size;
        j++;

finalize:
        r = sd_journal_sendv(iovec, j);
        if (r < 0)
                log_error("Failed to log coredump: %s", strerror(-r));

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
