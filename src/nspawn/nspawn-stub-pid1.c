/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

#include <sys/reboot.h>
#include <sys/unistd.h>
#include <sys/wait.h>

#include "fd-util.h"
#include "log.h"
#include "nspawn-stub-pid1.h"
#include "process-util.h"
#include "signal-util.h"
#include "time-util.h"
#include "def.h"

int stub_pid1(void) {
        enum {
                STATE_RUNNING,
                STATE_REBOOT,
                STATE_POWEROFF,
        } state = STATE_RUNNING;

        sigset_t fullmask, oldmask, waitmask;
        usec_t quit_usec = USEC_INFINITY;
        pid_t pid;
        int r;

        /* Implements a stub PID 1, that reaps all processes and processes a couple of standard signals. This is useful
         * for allowing arbitrary processes run in a container, and still have all zombies reaped. */

        assert_se(sigfillset(&fullmask) >= 0);
        assert_se(sigprocmask(SIG_BLOCK, &fullmask, &oldmask) >= 0);

        pid = fork();
        if (pid < 0)
                return log_error_errno(errno, "Failed to fork child pid: %m");

        if (pid == 0) {
                /* Return in the child */
                assert_se(sigprocmask(SIG_SETMASK, &oldmask, NULL) >= 0);
                setsid();
                return 0;
        }

        reset_all_signal_handlers();

        log_close();
        close_all_fds(NULL, 0);
        log_open();

        rename_process("STUBINIT");

        assert_se(sigemptyset(&waitmask) >= 0);
        assert_se(sigset_add_many(&waitmask,
                                  SIGCHLD,          /* posix: process died */
                                  SIGINT,           /* sysv: ctrl-alt-del */
                                  SIGRTMIN+3,       /* systemd: halt */
                                  SIGRTMIN+4,       /* systemd: poweroff */
                                  SIGRTMIN+5,       /* systemd: reboot */
                                  SIGRTMIN+6,       /* systemd: kexec */
                                  SIGRTMIN+13,      /* systemd: halt */
                                  SIGRTMIN+14,      /* systemd: poweroff */
                                  SIGRTMIN+15,      /* systemd: reboot */
                                  SIGRTMIN+16,      /* systemd: kexec */
                                  -1) >= 0);

        /* Note that we ignore SIGTERM (sysv's reexec), SIGHUP (reload), and all other signals here, since we don't
         * support reexec/reloading in this stub process. */

        for (;;) {
                siginfo_t si;
                usec_t current_usec;

                si.si_pid = 0;
                r = waitid(P_ALL, 0, &si, WEXITED|WNOHANG);
                if (r < 0) {
                        r = log_error_errno(errno, "Failed to reap children: %m");
                        goto finish;
                }

                current_usec = now(CLOCK_MONOTONIC);

                if (si.si_pid == pid || current_usec >= quit_usec) {

                        /* The child we started ourselves died or we reached a timeout. */

                        if (state == STATE_REBOOT) { /* dispatch a queued reboot */
                                (void) reboot(RB_AUTOBOOT);
                                r = log_error_errno(errno, "Failed to reboot: %m");
                                goto finish;

                        } else if (state == STATE_POWEROFF)
                                (void) reboot(RB_POWER_OFF); /* if this fails, fall back to normal exit. */

                        if (si.si_pid == pid && si.si_code == CLD_EXITED)
                                r = si.si_status; /* pass on exit code */
                        else
                                r = 255; /* signal, coredump, timeout, … */

                        goto finish;
                }
                if (si.si_pid != 0)
                        /* We reaped something. Retry until there's nothing more to reap. */
                        continue;

                if (quit_usec == USEC_INFINITY)
                        r = sigwaitinfo(&waitmask, &si);
                else {
                        struct timespec ts;
                        r = sigtimedwait(&waitmask, &si, timespec_store(&ts, quit_usec - current_usec));
                }
                if (r < 0) {
                        if (errno == EINTR) /* strace -p attach can result in EINTR, let's handle this nicely. */
                                continue;
                        if (errno == EAGAIN) /* timeout reached */
                                continue;

                        r = log_error_errno(errno, "Failed to wait for signal: %m");
                        goto finish;
                }

                if (si.si_signo == SIGCHLD)
                        continue; /* Let's reap this */

                if (state != STATE_RUNNING)
                        continue;

                /* Would love to use a switch() statement here, but SIGRTMIN is actually a function call, not a
                 * constant… */

                if (si.si_signo == SIGRTMIN+3 ||
                    si.si_signo == SIGRTMIN+4 ||
                    si.si_signo == SIGRTMIN+13 ||
                    si.si_signo == SIGRTMIN+14)

                        state = STATE_POWEROFF;

                else if (si.si_signo == SIGINT ||
                         si.si_signo == SIGRTMIN+5 ||
                         si.si_signo == SIGRTMIN+6 ||
                         si.si_signo == SIGRTMIN+15 ||
                         si.si_signo == SIGRTMIN+16)

                        state = STATE_REBOOT;
                else
                        assert_not_reached("Got unexpected signal");

                /* (void) kill_and_sigcont(pid, SIGTERM); */
                quit_usec = now(CLOCK_MONOTONIC) + DEFAULT_TIMEOUT_USEC;
        }

finish:
        _exit(r < 0 ? EXIT_FAILURE : r);
}
