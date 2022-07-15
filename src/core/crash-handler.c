/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/reboot.h>

#include "crash-handler.h"
#include "exit-status.h"
#include "macro.h"
#include "main.h"
#include "missing_syscall.h"
#include "process-util.h"
#include "raw-clone.h"
#include "rlimit-util.h"
#include "signal-util.h"
#include "terminal-util.h"
#include "virt.h"

_noreturn_ void freeze_or_exit_or_reboot(void) {

        /* If we are running in a container, let's prefer exiting, after all we can propagate an exit code to
         * the container manager, and thus inform it that something went wrong. */
        if (detect_container() > 0) {
                log_emergency("Exiting PID 1...");
                _exit(EXIT_EXCEPTION);
        }

        if (arg_crash_reboot) {
                log_notice("Rebooting in 10s...");
                (void) sleep(10);

                log_notice("Rebooting now...");
                (void) reboot(RB_AUTOBOOT);
                log_emergency_errno(errno, "Failed to reboot: %m");
        }

        log_emergency("Freezing execution.");
        sync();
        freeze();
}

_noreturn_ static void crash(int sig, siginfo_t *siginfo, void *context) {
        struct sigaction sa;
        pid_t pid;

        /* NB: 💣 💣 💣 This is a signal handler, most likely executed in a situation where we have corrupted
         * memory. Thus: please avoid any libc memory allocation here, or any functions that internally use
         * memory allocation, as we cannot rely on memory allocation still working at this point! (Note that
         * memory allocation is not async-signal-safe anyway — see signal-safety(7) for details —, and thus
         * is not permissible in signal handlers.) */

        if (getpid_cached() != 1)
                /* Pass this on immediately, if this is not PID 1 */
                (void) raise(sig);
        else if (!arg_dump_core)
                log_emergency("Caught <%s>, not dumping core.", signal_to_string(sig));
        else {
                sa = (struct sigaction) {
                        .sa_handler = nop_signal_handler,
                        .sa_flags = SA_NOCLDSTOP|SA_RESTART,
                };

                /* We want to wait for the core process, hence let's enable SIGCHLD */
                (void) sigaction(SIGCHLD, &sa, NULL);

                pid = raw_clone(SIGCHLD);
                if (pid < 0)
                        log_emergency_errno(errno, "Caught <%s>, cannot fork for core dump: %m", signal_to_string(sig));
                else if (pid == 0) {
                        /* Enable default signal handler for core dump */

                        sa = (struct sigaction) {
                                .sa_handler = SIG_DFL,
                        };
                        (void) sigaction(sig, &sa, NULL);

                        /* Don't limit the coredump size */
                        (void) setrlimit(RLIMIT_CORE, &RLIMIT_MAKE_CONST(RLIM_INFINITY));

                        /* Just to be sure... */
                        (void) chdir("/");

                        /* Raise the signal again */
                        pid = raw_getpid();
                        (void) kill(pid, sig); /* raise() would kill the parent */

                        assert_not_reached();
                        _exit(EXIT_EXCEPTION);
                } else {
                        siginfo_t status;
                        int r;

                        if (siginfo) {
                                if (siginfo->si_pid == 0)
                                        log_emergency("Caught <%s> from unknown sender process.", signal_to_string(sig));
                                else if (siginfo->si_pid == 1)
                                        log_emergency("Caught <%s> from our own process.", signal_to_string(sig));
                                else
                                        log_emergency("Caught <%s> from PID "PID_FMT".", signal_to_string(sig), siginfo->si_pid);
                        }

                        /* Order things nicely. */
                        r = wait_for_terminate(pid, &status);
                        if (r < 0)
                                log_emergency_errno(r, "Caught <%s>, waitpid() failed: %m", signal_to_string(sig));
                        else if (status.si_code != CLD_DUMPED) {
                                const char *s = status.si_code == CLD_EXITED
                                        ? exit_status_to_string(status.si_status, EXIT_STATUS_LIBC)
                                        : signal_to_string(status.si_status);

                                log_emergency("Caught <%s>, core dump failed (child "PID_FMT", code=%s, status=%i/%s).",
                                              signal_to_string(sig),
                                              pid,
                                              sigchld_code_to_string(status.si_code),
                                              status.si_status, strna(s));
                        } else
                                log_emergency("Caught <%s>, dumped core as pid "PID_FMT".",
                                              signal_to_string(sig), pid);
                }
        }

        if (arg_crash_chvt >= 0)
                (void) chvt(arg_crash_chvt);

        sa = (struct sigaction) {
                .sa_handler = SIG_IGN,
                .sa_flags = SA_NOCLDSTOP|SA_NOCLDWAIT|SA_RESTART,
        };

        /* Let the kernel reap children for us */
        (void) sigaction(SIGCHLD, &sa, NULL);

        if (arg_crash_shell) {
                log_notice("Executing crash shell in 10s...");
                (void) sleep(10);

                pid = raw_clone(SIGCHLD);
                if (pid < 0)
                        log_emergency_errno(errno, "Failed to fork off crash shell: %m");
                else if (pid == 0) {
                        (void) setsid();
                        (void) make_console_stdio();
                        (void) rlimit_nofile_safe();
                        (void) execle("/bin/sh", "/bin/sh", NULL, environ);

                        log_emergency_errno(errno, "execle() failed: %m");
                        _exit(EXIT_EXCEPTION);
                } else {
                        log_info("Spawned crash shell as PID "PID_FMT".", pid);
                        (void) wait_for_terminate(pid, NULL);
                }
        }

        freeze_or_exit_or_reboot();
}

void install_crash_handler(void) {
        static const struct sigaction sa = {
                .sa_sigaction = crash,
                .sa_flags = SA_NODEFER | SA_SIGINFO, /* So that we can raise the signal again from the signal handler */
        };
        int r;

        /* We ignore the return value here, since, we don't mind if we cannot set up a crash handler */
        r = sigaction_many(&sa, SIGNALS_CRASH_HANDLER);
        if (r < 0)
                log_debug_errno(r, "I had trouble setting up the crash handler, ignoring: %m");
}
