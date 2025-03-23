/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/types.h>
#include <unistd.h>

#include "build-path.h"
#include "escape.h"
#include "event-util.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fork-journal.h"
#include "notify-recv.h"
#include "parse-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "strv.h"

static int on_child_exit(sd_event_source *s, const siginfo_t *si, void *userdata) {
        PidRef *child = ASSERT_PTR(userdata);

        assert(si->si_pid == child->pid);

        log_debug("Child " PID_FMT " died before sending notification message.", child->pid);
        return -EPROTO;
}

static int on_child_notify(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        PidRef *child = ASSERT_PTR(userdata);
        int r;

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

        if (strv_find(msg, "READY=1"))
                return sd_event_exit(sd_event_source_get_event(s), EXIT_SUCCESS);

        const char *e = strv_find_startswith(msg, "ERRNO=");
        if (e) {
                int error;

                r = safe_atoi(e, &error);
                if (r < 0) {
                        log_debug_errno(r, "Received invalid ERRNO= notification message, ignoring: %m");
                        return 0;
                }
                if (error <= 0) {
                        log_debug("Received non-positive ERRNO= notification message, ignoring: %m");
                        return 0;
                }

                return sd_event_exit(sd_event_source_get_event(s), -error);
        }

        return 0;
}

int journal_fork(RuntimeScope scope, Set **pids, const char *unit) {
        int r;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);
        assert(unit);

        if (!is_main_thread())
                return -EPERM;

        _cleanup_close_ int notify_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (notify_fd < 0)
                return log_debug_errno(errno, "Failed to allocate AF_UNIX socket for notifications: %m");

        r = setsockopt_int(notify_fd, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to enable SO_PASSCRED: %m");

        r = setsockopt_int(notify_fd, SOL_SOCKET, SO_PASSPIDFD, true);
        if (r < 0)
                log_debug_errno(r, "Failed to enable SO_PASSPIDFD, ignoring: %m");

        /* Pick an address via auto-bind */
        union sockaddr_union sa = {
                .sa.sa_family = AF_UNIX,
        };
        if (bind(notify_fd, &sa.sa, offsetof(union sockaddr_union, un.sun_path)) < 0)
                return log_debug_errno(errno, "Failed to bind AF_UNIX socket: %m");

        _cleanup_free_ char *addr_string = NULL;
        r = getsockname_pretty(notify_fd, &addr_string);
        if (r < 0)
                return log_debug_errno(r, "Failed to get socket name: %m");

        const char *const argv[] = {
                "journalctl",
                "--follow",
                "--no-pager",
                "--lines=1",
                scope == RUNTIME_SCOPE_SYSTEM ? "--unit" : "--user-unit",
                unit,
                NULL,
        };

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *l = quote_command_line((char**) argv, SHELL_ESCAPE_EMPTY);
                log_debug("Invoking '%s' as child.", strnull(l));
        }

        BLOCK_SIGNALS(SIGCHLD);

        _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;
        r = pidref_safe_fork_full(
                        "(journalctl)",
                        (const int[3]) { -EBADF, STDOUT_FILENO, STDERR_FILENO },
                        /* except_fds= */ NULL,
                        /* n_except_fds= */ 0,
                        FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_CLOSE_ALL_FDS|FORK_RLIMIT_NOFILE_SAFE|FORK_REARRANGE_STDIO,
                        &child);
        if (r < 0)
                return r;
        if (r == 0) {
                /* In the child: */

                if (setenv("NOTIFY_SOCKET", addr_string, /* overwrite= */ true) < 0) {
                        log_debug_errno(errno, "Failed to set $NOTIFY_SOCKET: %m");
                        _exit(EXIT_MEMORY);
                }

                r = invoke_callout_binary(argv[0], (char**) argv);
                log_debug_errno(r, "Failed to invoke journalctl: %m");
                _exit(EXIT_EXEC);
        }

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        r = sd_event_new(&event);
        if (r < 0)
                return r;

        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *child_event_source = NULL;
        r = event_add_child_pidref(event, &child_event_source, &child, WEXITED, on_child_exit, &child);
        if (r < 0)
                return r;

        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *notify_event_source = NULL;
        r = sd_event_add_io(event, &notify_event_source, notify_fd, EPOLLIN, on_child_notify, &child);
        if (r < 0)
                return r;

        /* We want the notification message from the child before the SIGCHLD */
        r = sd_event_source_set_priority(notify_event_source, SD_EVENT_PRIORITY_NORMAL-10);
        if (r < 0)
                return r;

        r = sd_event_loop(event);
        if (r < 0)
                return r;
        assert(r == 0);

        if (pids) {
                _cleanup_(pidref_freep) PidRef *copy = NULL;

                r = pidref_dup(&child, &copy);
                if (r < 0)
                        return r;

                r = set_ensure_consume(pids, &pidref_hash_ops_free, TAKE_PTR(copy));
                if (r < 0)
                        return r;
        }

        pidref_done(&child); /* Disarm auto-kill */

        return 0;
}

Set *journal_terminate(Set *pids) {
        int r;

        for (;;) {
                _cleanup_(pidref_freep) PidRef *pid = set_steal_first(pids);
                if (!pid)
                        break;

                r = pidref_kill(pid, SIGTERM);
                if (r < 0) {
                        log_debug_errno(r, "Failed to send SIGTERM to journalctl child " PID_FMT ", skipping: %m", pid->pid);
                        continue;
                }

                (void) pidref_wait_for_terminate_and_check("journalctl", pid, /* flags= */ 0);
        }

        return set_free(pids);
}
