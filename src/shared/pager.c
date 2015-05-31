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

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/prctl.h>

#include "pager.h"
#include "util.h"
#include "process-util.h"
#include "macro.h"
#include "terminal-util.h"
#include "signal-util.h"

static pid_t pager_pid = 0;

noreturn static void pager_fallback(void) {
        ssize_t n;

        do {
                n = splice(STDIN_FILENO, NULL, STDOUT_FILENO, NULL, 64*1024, 0);
        } while (n > 0);

        if (n < 0) {
                log_error_errno(errno, "Internal pager failed: %m");
                _exit(EXIT_FAILURE);
        }

        _exit(EXIT_SUCCESS);
}

int pager_open(bool jump_to_end) {
        int fd[2];
        const char *pager;
        pid_t parent_pid;
        int r;

        if (pager_pid > 0)
                return 1;

        if ((pager = getenv("SYSTEMD_PAGER")) || (pager = getenv("PAGER")))
                if (!*pager || streq(pager, "cat"))
                        return 0;

        if (!on_tty())
                return 0;

        /* Determine and cache number of columns before we spawn the
         * pager so that we get the value from the actual tty */
        columns();

        if (pipe(fd) < 0)
                return log_error_errno(errno, "Failed to create pager pipe: %m");

        parent_pid = getpid();

        pager_pid = fork();
        if (pager_pid < 0) {
                r = -errno;
                log_error_errno(errno, "Failed to fork pager: %m");
                safe_close_pair(fd);
                return r;
        }

        /* In the child start the pager */
        if (pager_pid == 0) {
                const char* less_opts;

                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();

                dup2(fd[0], STDIN_FILENO);
                safe_close_pair(fd);

                less_opts = getenv("SYSTEMD_LESS");
                if (!less_opts)
                        less_opts = "FRSXMK";
                if (jump_to_end)
                        less_opts = strjoina(less_opts, " +G");
                setenv("LESS", less_opts, 1);

                /* Make sure the pager goes away when the parent dies */
                if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0)
                        _exit(EXIT_FAILURE);

                /* Check whether our parent died before we were able
                 * to set the death signal */
                if (getppid() != parent_pid)
                        _exit(EXIT_SUCCESS);

                if (pager) {
                        execlp(pager, pager, NULL);
                        execl("/bin/sh", "sh", "-c", pager, NULL);
                }

                /* Debian's alternatives command for pagers is
                 * called 'pager'. Note that we do not call
                 * sensible-pagers here, since that is just a
                 * shell script that implements a logic that
                 * is similar to this one anyway, but is
                 * Debian-specific. */
                execlp("pager", "pager", NULL);

                execlp("less", "less", NULL);
                execlp("more", "more", NULL);

                pager_fallback();
                /* not reached */
        }

        /* Return in the parent */
        if (dup2(fd[1], STDOUT_FILENO) < 0)
                return log_error_errno(errno, "Failed to duplicate pager pipe: %m");

        safe_close_pair(fd);
        return 1;
}

void pager_close(void) {

        if (pager_pid <= 0)
                return;

        /* Inform pager that we are done */
        fclose(stdout);
        kill(pager_pid, SIGCONT);
        (void) wait_for_terminate(pager_pid, NULL);
        pager_pid = 0;
}

bool pager_have(void) {
        return pager_pid > 0;
}

int show_man_page(const char *desc, bool null_stdio) {
        const char *args[4] = { "man", NULL, NULL, NULL };
        char *e = NULL;
        pid_t pid;
        size_t k;
        int r;
        siginfo_t status;

        k = strlen(desc);

        if (desc[k-1] == ')')
                e = strrchr(desc, '(');

        if (e) {
                char *page = NULL, *section = NULL;

                page = strndupa(desc, e - desc);
                section = strndupa(e + 1, desc + k - e - 2);

                args[1] = section;
                args[2] = page;
        } else
                args[1] = desc;

        pid = fork();
        if (pid < 0)
                return log_error_errno(errno, "Failed to fork: %m");

        if (pid == 0) {
                /* Child */

                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();

                if (null_stdio) {
                        r = make_null_stdio();
                        if (r < 0) {
                                log_error_errno(r, "Failed to kill stdio: %m");
                                _exit(EXIT_FAILURE);
                        }
                }

                execvp(args[0], (char**) args);
                log_error_errno(errno, "Failed to execute man: %m");
                _exit(EXIT_FAILURE);
        }

        r = wait_for_terminate(pid, &status);
        if (r < 0)
                return r;

        log_debug("Exit code %i status %i", status.si_code, status.si_status);
        return status.si_status;
}
