/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/reboot.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "def.h"
#include "exit-status.h"
#include "fd-util.h"
#include "log.h"
#include "missing.h"
#include "nspawn-stub-pid1.h"
#include "process-util.h"
#include "signal-util.h"
#include "time-util.h"

static int reset_environ(const char *new_environment, size_t length) {
        unsigned long start, end;

        start = (unsigned long) new_environment;
        end = start + length;

        if (prctl(PR_SET_MM, PR_SET_MM_ENV_START, start, 0, 0) < 0)
                return -errno;

        if (prctl(PR_SET_MM, PR_SET_MM_ENV_END, end, 0, 0) < 0)
                return -errno;

        return 0;
}

int stub_pid1(sd_id128_t uuid) {
        enum {
                STATE_RUNNING,
                STATE_REBOOT,
                STATE_POWEROFF,
        } state = STATE_RUNNING;

        sigset_t fullmask, oldmask, waitmask;
        usec_t quit_usec = USEC_INFINITY;
        pid_t pid;
        int r;

        /* The new environment we set up, on the stack. */
        char new_environment[] =
                "container=systemd-nspawn\0"
                "container_uuid=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

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
        (void) close_all_fds(NULL, 0);
        log_open();

        /* Flush out /proc/self/environ, so that we don't leak the environment from the host into the container. Also,
         * set $container= and $container_uuid= so that clients in the container that query it from /proc/1/environ
         * find them set. */
        sd_id128_to_string(uuid, new_environment + sizeof(new_environment) - SD_ID128_STRING_MAX);
        reset_environ(new_environment, sizeof(new_environment));

        (void) rename_process("(sd-stubinit)");

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
                                r = EXIT_EXCEPTION; /* signal, coredump, timeout, … */

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

                r = kill_and_sigcont(pid, SIGTERM);

                /* Let's send a SIGHUP after the SIGTERM, as shells tend to ignore SIGTERM but do react to SIGHUP. We
                 * do it strictly in this order, so that the SIGTERM is dispatched first, and SIGHUP second for those
                 * processes which handle both. That's because services tend to bind configuration reload or something
                 * else to SIGHUP. */

                if (r != -ESRCH)
                        (void) kill(pid, SIGHUP);

                quit_usec = now(CLOCK_MONOTONIC) + DEFAULT_TIMEOUT_USEC;
        }

finish:
        _exit(r < 0 ? EXIT_FAILURE : r);
}
