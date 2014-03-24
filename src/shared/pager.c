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

#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/prctl.h>

#include "pager.h"
#include "util.h"
#include "macro.h"

static pid_t pager_pid = 0;

noreturn static void pager_fallback(void) {
        ssize_t n;

        do {
                n = splice(STDIN_FILENO, NULL, STDOUT_FILENO, NULL, 64*1024, 0);
        } while (n > 0);

        if (n < 0) {
                log_error("Internal pager failed: %m");
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

        if (pipe(fd) < 0) {
                log_error("Failed to create pager pipe: %m");
                return -errno;
        }

        parent_pid = getpid();

        pager_pid = fork();
        if (pager_pid < 0) {
                r = -errno;
                log_error("Failed to fork pager: %m");
                safe_close_pair(fd);
                return r;
        }

        /* In the child start the pager */
        if (pager_pid == 0) {
                const char* less_opts;

                dup2(fd[0], STDIN_FILENO);
                safe_close_pair(fd);

                less_opts = getenv("SYSTEMD_LESS");
                if (!less_opts)
                        less_opts = "FRSXMK";
                if (jump_to_end)
                        less_opts = strappenda(less_opts, " +G");
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
        if (dup2(fd[1], STDOUT_FILENO) < 0) {
                log_error("Failed to duplicate pager pipe: %m");
                return -errno;
        }

        safe_close_pair(fd);
        return 1;
}

void pager_close(void) {

        if (pager_pid <= 0)
                return;

        /* Inform pager that we are done */
        fclose(stdout);
        kill(pager_pid, SIGCONT);
        wait_for_terminate(pager_pid, NULL);
        pager_pid = 0;
}

bool pager_have(void) {
        return pager_pid > 0;
}
