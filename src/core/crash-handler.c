/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/reboot.h>

#include "sd-messages.h"

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
                log_struct(LOG_EMERG,
                           LOG_MESSAGE("Exiting PID 1..."),
                           "MESSAGE_ID=" SD_MESSAGE_CRASH_EXIT_STR);
                _exit(EXIT_EXCEPTION);
        }

        if (arg_crash_action == CRASH_POWEROFF) {
                log_notice("Shutting down...");
                (void) reboot(RB_POWER_OFF);
                log_struct_errno(LOG_EMERG, errno,
                                 LOG_MESSAGE("Failed to power off: %m"),
                                 "MESSAGE_ID=" SD_MESSAGE_CRASH_FAILED_STR);
        } else if (arg_crash_action == CRASH_REBOOT) {
                log_notice("Rebooting in 10s...");
                (void) sleep(10);

                log_notice("Rebooting now...");
                (void) reboot(RB_AUTOBOOT);
                log_struct_errno(LOG_EMERG, errno,
                                 LOG_MESSAGE("Failed to reboot: %m"),
                                 "MESSAGE_ID=" SD_MESSAGE_CRASH_FAILED_STR);
        }

        log_struct(LOG_EMERG,
                   LOG_MESSAGE("Freezing execution."),
                   "MESSAGE_ID=" SD_MESSAGE_CRASH_FREEZE_STR);
        sync();
        freeze();
}

_noreturn_ static void crash(int sig, siginfo_t *siginfo, void *context) {
        static const struct sigaction sa_nocldwait = {
                .sa_handler = SIG_IGN,
                .sa_flags = SA_NOCLDSTOP|SA_NOCLDWAIT|SA_RESTART,
        };

        pid_t pid;
        int r;

        /* NB: 💣 💣 💣 This is a signal handler, most likely executed in a situation where we have corrupted
         * memory. Thus: please avoid any libc memory allocation here, or any functions that internally use
         * memory allocation, as we cannot rely on memory allocation still working at this point! (Note that
         * memory allocation is not async-signal-safe anyway — see signal-safety(7) for details —, and thus
         * is not permissible in signal handlers.) */

        if (getpid_cached() != 1)
                /* Pass this on immediately, if this is not PID 1 */
                propagate_signal(sig, siginfo);
        else if (!arg_dump_core)
                log_struct(LOG_EMERG,
                           LOG_MESSAGE("Caught <%s>, not dumping core.", signal_to_string(sig)),
                           "MESSAGE_ID=" SD_MESSAGE_CRASH_NO_COREDUMP_STR);
        else {
                /* We want to wait for the core process, hence let's enable SIGCHLD */
                (void) sigaction(SIGCHLD, &sigaction_nop_nocldstop, NULL);

                pid = raw_clone(SIGCHLD);
                if (pid < 0)
                        log_struct_errno(LOG_EMERG, errno,
                                         LOG_MESSAGE("Caught <%s>, cannot fork for core dump: %m", signal_to_string(sig)),
                                         "MESSAGE_ID=" SD_MESSAGE_CRASH_NO_FORK_STR);
                else if (pid == 0) {
                        /* Enable default signal handler for core dump */

                        (void) sigaction(sig, &sigaction_default, NULL);

                        /* Don't limit the coredump size */
                        (void) setrlimit(RLIMIT_CORE, &RLIMIT_MAKE_CONST(RLIM_INFINITY));

                        /* Just to be sure... */
                        (void) chdir("/");

                        /* Raise the signal again */
                        propagate_signal(sig, siginfo);
                        assert_not_reached();
                        _exit(EXIT_EXCEPTION);
                } else {
                        siginfo_t status;

                        if (siginfo) {
                                if (siginfo->si_pid == 0)
                                        log_struct(LOG_EMERG,
                                                   LOG_MESSAGE("Caught <%s>, from unknown sender process.", signal_to_string(sig)),
                                                   "MESSAGE_ID=" SD_MESSAGE_CRASH_UNKNOWN_SIGNAL_STR);
                                else if (siginfo->si_pid == 1)
                                        log_struct(LOG_EMERG,
                                                   LOG_MESSAGE("Caught <%s>, from our own process.", signal_to_string(sig)),
                                                   "MESSAGE_ID=" SD_MESSAGE_CRASH_SYSTEMD_SIGNAL_STR);
                                else
                                        log_struct(LOG_EMERG,
                                                   LOG_MESSAGE("Caught <%s> from PID "PID_FMT".", signal_to_string(sig), siginfo->si_pid),
                                                   "MESSAGE_ID=" SD_MESSAGE_CRASH_PROCESS_SIGNAL_STR);
                        }

                        /* Order things nicely. */
                        r = wait_for_terminate(pid, &status);
                        if (r < 0)
                                log_struct_errno(LOG_EMERG, r,
                                                 LOG_MESSAGE("Caught <%s>, waitpid() failed: %m", signal_to_string(sig)),
                                                 "MESSAGE_ID=" SD_MESSAGE_CRASH_WAITPID_FAILED_STR);
                        else if (status.si_code != CLD_DUMPED) {
                                const char *s = status.si_code == CLD_EXITED ?
                                        exit_status_to_string(status.si_status, EXIT_STATUS_LIBC) :
                                        signal_to_string(status.si_status);

                                log_struct(LOG_EMERG,
                                           LOG_MESSAGE("Caught <%s>, core dump failed (child "PID_FMT", code=%s, status=%i/%s).",
                                                       signal_to_string(sig),
                                                       pid,
                                                       sigchld_code_to_string(status.si_code),
                                                       status.si_status,
                                                       strna(s)),
                                           "MESSAGE_ID=" SD_MESSAGE_CRASH_COREDUMP_FAILED_STR);
                        } else
                                log_struct(LOG_EMERG,
                                           LOG_MESSAGE("Caught <%s>, dumped core as pid "PID_FMT".",
                                                       signal_to_string(sig), pid),
                                           "MESSAGE_ID=" SD_MESSAGE_CRASH_COREDUMP_PID_STR);
                }
        }

        if (arg_crash_chvt >= 0)
                (void) chvt(arg_crash_chvt);

        /* Let the kernel reap children for us */
        (void) sigaction(SIGCHLD, &sa_nocldwait, NULL);

        if (arg_crash_shell) {
                log_notice("Executing crash shell...");

                pid = raw_clone(SIGCHLD);
                if (pid < 0)
                        log_struct_errno(LOG_EMERG, errno,
                                         LOG_MESSAGE("Failed to fork off crash shell: %m"),
                                         "MESSAGE_ID=" SD_MESSAGE_CRASH_SHELL_FORK_FAILED_STR);
                else if (pid == 0) {
                        (void) setsid();
                        (void) terminal_vhangup("/dev/console");
                        (void) make_console_stdio();
                        (void) rlimit_nofile_safe();
                        (void) execle("/bin/sh", "/bin/sh", NULL, environ);

                        log_struct_errno(LOG_EMERG, errno,
                                         LOG_MESSAGE("execle() failed: %m"),
                                         "MESSAGE_ID=" SD_MESSAGE_CRASH_EXECLE_FAILED_STR);
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
