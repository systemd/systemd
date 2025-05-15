/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "build-path.h"
#include "escape.h"
#include "event-util.h"
#include "exit-status.h"
#include "fork-journal.h"
#include "log.h"
#include "notify-recv.h"
#include "parse-util.h"
#include "pidref.h"
#include "process-util.h"
#include "runtime-scope.h"
#include "signal-util.h"
#include "strv.h"

static int on_child_exit(sd_event_source *s, const siginfo_t *si, void *userdata) {
        PidRef *child = ASSERT_PTR(userdata);

        assert(si);
        assert(si->si_pid == child->pid);

        /* Let's first do some debug logging about the exit status of the child */

        if (si->si_code == CLD_EXITED) {
                if (si->si_status == EXIT_SUCCESS)
                        log_debug("journalctl " PID_FMT " exited successfully.", si->si_pid);
                else
                        log_debug("journalctl " PID_FMT " died with a failure exit status %i, ignoring.", si->si_pid, si->si_status);
        } else if (si->si_code == CLD_KILLED)
                log_debug("journalctl " PID_FMT " was killed by signal %s, ignoring.", si->si_pid, signal_to_string(si->si_status));
        else if (si->si_code == CLD_DUMPED)
                log_debug("journalctl " PID_FMT " dumped core by signal %s, ignoring.", si->si_pid, signal_to_string(si->si_status));
        else
                log_debug("Got unexpected exit code %i via SIGCHLD, ignoring.", si->si_code);

        /* And let's then fail the whole thing, because regardless what the exit status of the child is
         * (i.e. even if successful), if it exits before sending READY=1 something is wrong. */

        return log_debug_errno(SYNTHETIC_ERRNO(EPROTO), "Child " PID_FMT " died before sending notification message.", child->pid);
}

static int on_child_notify(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        PidRef *child = ASSERT_PTR(userdata);
        int r;

        assert(s);
        assert(fd >= 0);

        _cleanup_strv_free_ char **msg = NULL;
        _cleanup_(pidref_done) PidRef sender = PIDREF_NULL;
        r = notify_recv_strv(fd, &msg, /* ret_ucred= */ NULL, &sender);
        if (r == -EAGAIN)
                return 0;
        if (r < 0)
                return r;

        if (!pidref_equal(child, &sender)) {
                log_warning("Received notification message from unexpected process " PID_FMT " (expected " PID_FMT "), ignoring.",
                            sender.pid, child->pid);
                return 0;
        }

        if (strv_contains(msg, "READY=1"))
                return sd_event_exit(sd_event_source_get_event(s), EXIT_SUCCESS);

        const char *e = strv_find_startswith(msg, "ERRNO=");
        if (e) {
                int error;

                r = safe_atoi(e, &error);
                if (r < 0) {
                        log_debug_errno(r, "Received invalid ERRNO= notification message, ignoring: %s", e);
                        return 0;
                }
                if (error <= 0) {
                        log_debug("Received non-positive ERRNO= notification message, ignoring: %m");
                        return 0;
                }

                return -error;
        }

        return 0;
}

int journal_fork(RuntimeScope scope, char * const *units, PidRef *ret_pidref) {
        int r;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);
        assert(ret_pidref);

        if (!is_main_thread())
                return -EPERM;

        if (strv_isempty(units))
                return 0;

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        r = sd_event_new(&event);
        if (r < 0)
                return r;

        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *notify_event_source = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;
        _cleanup_free_ char *addr_string = NULL;
        r = notify_socket_prepare(
                        event,
                        SD_EVENT_PRIORITY_NORMAL-10, /* We want the notification message from the child before the SIGCHLD */
                        on_child_notify,
                        &child,
                        &addr_string,
                        &notify_event_source);
        if (r < 0)
                return r;

        r = sd_event_source_set_exit_on_failure(notify_event_source, true);
        if (r < 0)
                return r;

        _cleanup_strv_free_ char **argv = strv_new(
                        "journalctl",
                        "-q",
                        "--follow",
                        "--no-pager",
                        "--lines=1",
                        "--synchronize-on-exit=yes");
        if (!argv)
                return log_oom_debug();

        STRV_FOREACH(u, units)
                if (strv_extendf(&argv,
                                 scope == RUNTIME_SCOPE_SYSTEM ? "--unit=%s" : "--user-unit=%s",
                                 *u) < 0)
                        return log_oom_debug();

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *l = quote_command_line(argv, SHELL_ESCAPE_EMPTY);
                log_debug("Invoking '%s' as child.", strnull(l));
        }

        BLOCK_SIGNALS(SIGCHLD);

        r = pidref_safe_fork_full(
                        "(journalctl)",
                        (const int[3]) { -EBADF, STDOUT_FILENO, STDERR_FILENO },
                        /* except_fds= */ NULL,
                        /* n_except_fds= */ 0,
                        FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_CLOSE_ALL_FDS|FORK_REARRANGE_STDIO,
                        &child);
        if (r < 0)
                return r;
        if (r == 0) {
                /* In the child: */

                if (setenv("NOTIFY_SOCKET", addr_string, /* overwrite= */ true) < 0) {
                        log_debug_errno(errno, "Failed to set $NOTIFY_SOCKET: %m");
                        _exit(EXIT_MEMORY);
                }

                r = invoke_callout_binary(argv[0], argv);
                log_debug_errno(r, "Failed to invoke journalctl: %m");
                _exit(EXIT_EXEC);
        }

        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *child_event_source = NULL;
        r = event_add_child_pidref(event, &child_event_source, &child, WEXITED, on_child_exit, &child);
        if (r < 0)
                return r;

        r = sd_event_source_set_exit_on_failure(child_event_source, true);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(child_event_source, "fork-journal-child");

        r = sd_event_loop(event);
        if (r < 0)
                return r;
        assert(r == 0);

        *ret_pidref = TAKE_PIDREF(child);

        return 0;
}

void journal_terminate(PidRef *pidref) {
        int r;

        if (!pidref_is_set(pidref))
                return;

        r = pidref_kill(pidref, SIGTERM);
        if (r < 0)
                log_debug_errno(r, "Failed to send SIGTERM to journalctl child " PID_FMT ", ignoring: %m", pidref->pid);

        (void) pidref_wait_for_terminate_and_check("journalctl", pidref, /* flags= */ 0);
        pidref_done(pidref);
}
