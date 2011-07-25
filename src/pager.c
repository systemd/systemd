/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/prctl.h>

#include "pager.h"
#include "util.h"
#include "macro.h"

static pid_t pager_pid = 0;

void pager_open(void) {
        int fd[2];
        const char *pager;
        pid_t parent_pid;

        if (pager_pid > 0)
                return;

        if ((pager = getenv("SYSTEMD_PAGER")) || (pager = getenv("PAGER")))
                if (!*pager || streq(pager, "cat"))
                        return;

        if (isatty(STDOUT_FILENO) <= 0)
                return;

        /* Determine and cache number of columns before we spawn the
         * pager so that we get the value from the actual tty */
        columns();

        if (pipe(fd) < 0) {
                log_error("Failed to create pager pipe: %m");
                return;
        }

        parent_pid = getpid();

        pager_pid = fork();
        if (pager_pid < 0) {
                log_error("Failed to fork pager: %m");
                close_pipe(fd);
                return;
        }

        /* In the child start the pager */
        if (pager_pid == 0) {

                dup2(fd[0], STDIN_FILENO);
                close_pipe(fd);

                setenv("LESS", "FRSX", 0);

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
                execlp("cat", "cat", NULL);

                log_error("Unable to execute pager: %m");
                _exit(EXIT_FAILURE);
        }

        /* Return in the parent */
        if (dup2(fd[1], STDOUT_FILENO) < 0)
                log_error("Failed to duplicate pager pipe: %m");

        close_pipe(fd);
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
