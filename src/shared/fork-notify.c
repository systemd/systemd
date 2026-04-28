/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "build-path.h"
#include "chase.h"
#include "chattr-util.h"
#include "escape.h"
#include "event-util.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fork-notify.h"
#include "log.h"
#include "notify-recv.h"
#include "parse-util.h"
#include "path-util.h"
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
                        log_debug("Child process " PID_FMT " exited successfully.", si->si_pid);
                else
                        log_debug("Child process " PID_FMT " died with a failure exit status %i, ignoring.", si->si_pid, si->si_status);
        } else if (si->si_code == CLD_KILLED)
                log_debug("Child process " PID_FMT " was killed by signal %s, ignoring.", si->si_pid, signal_to_string(si->si_status));
        else if (si->si_code == CLD_DUMPED)
                log_debug("Child process " PID_FMT " dumped core by signal %s, ignoring.", si->si_pid, signal_to_string(si->si_status));
        else
                log_debug("Got unexpected exit code %i from child, ignoring.", si->si_code);

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
                        log_debug("Received non-positive ERRNO= notification message, ignoring: %d", error);
                        return 0;
                }

                return -error;
        }

        return 0;
}

int fork_notify(char * const *argv, fork_notify_handler_t child_handler, void *child_userdata, PidRef *ret_pidref) {
        int r;

        assert(argv);
        assert(ret_pidref);

        if (!is_main_thread())
                return -EPERM;

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        r = sd_event_new(&event);
        if (r < 0)
                return r;

        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *notify_event_source = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;
        _cleanup_free_ char *addr_string = NULL;
        r = notify_socket_prepare_full(
                        event,
                        SD_EVENT_PRIORITY_NORMAL-10, /* We want the notification message from the child before the child exit */
                        on_child_notify,
                        &child,
                        /* accept_fds= */ false,
                        &addr_string,
                        &notify_event_source);
        if (r < 0)
                return r;

        r = sd_event_source_set_exit_on_failure(notify_event_source, true);
        if (r < 0)
                return r;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *l = quote_command_line(argv, SHELL_ESCAPE_EMPTY);
                log_debug("Invoking '%s' as child.", strnull(l));
        }

        r = pidref_safe_fork_full(
                        "(fork-notify)",
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

                /* After fork and before exec one can execute custom code in this function
                 * but since all open FDs were closed only limited actions are safe (e.g., setenv),
                 * akin to how in a signal handler only certain things are safe. */
                if (child_handler)
                        child_handler(child_userdata);

                r = invoke_callout_binary(argv[0], argv);
                log_debug_errno(r, "Failed to invoke %s: %m", argv[0]);
                _exit(EXIT_EXEC);
        }

        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *child_event_source = NULL;
        r = event_add_child_pidref(event, &child_event_source, &child, WEXITED, on_child_exit, &child);
        if (r < 0)
                return r;

        r = sd_event_source_set_exit_on_failure(child_event_source, true);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(child_event_source, "fork-notify-child");

        r = sd_event_loop(event);
        if (r < 0)
                return r;
        assert(r == 0);

        *ret_pidref = TAKE_PIDREF(child);

        return 0;
}

static void fork_notify_terminate_internal(PidRef *pidref) {
        int r;

        if (!pidref_is_set(pidref))
                return;

        r = pidref_kill(pidref, SIGTERM);
        if (r < 0 && r != -ESRCH)
                log_debug_errno(r, "Failed to send SIGTERM to child " PID_FMT ", ignoring: %m", pidref->pid);

        (void) pidref_wait_for_terminate_and_check(/* name= */ NULL, pidref, /* flags= */ 0);
}

void fork_notify_terminate(PidRef *pidref) {
        fork_notify_terminate_internal(pidref);
        pidref_done(pidref);
}

void fork_notify_terminate_many(sd_event_source **array, size_t n) {
        int r;

        assert(array || n == 0);

        FOREACH_ARRAY(s, array, n) {
                PidRef child;

                r = event_source_get_child_pidref(*s, &child);
                if (r >= 0)
                        fork_notify_terminate_internal(&child);
                else
                        log_debug_errno(r, "Could not get pidref for event source: %m");

                sd_event_source_unref(*s);
        }

        free(array);
}

int journal_fork(RuntimeScope scope, char * const* units, OutputMode output, PidRef *ret_pidref) {
        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);

        if (strv_isempty(units))
                return 0;

        _cleanup_strv_free_ char **argv = strv_new(
                        "journalctl",
                        "-q",
                        "--follow",
                        "--no-pager",
                        "--lines=0",
                        "--synchronize-on-exit=yes");
        if (!argv)
                return log_oom_debug();

        STRV_FOREACH(u, units)
                if (strv_extendf(&argv,
                                 scope == RUNTIME_SCOPE_SYSTEM ? "--unit=%s" : "--user-unit=%s",
                                 *u) < 0)
                        return log_oom_debug();

        if (output >= 0)
                if (strv_extendf(&argv, "--output=%s", output_mode_to_string(output)) < 0)
                        return log_oom_debug();

        return fork_notify(argv, /* child_handler= */ NULL, /* child_userdata= */ NULL, ret_pidref);
}

static void set_journal_remote_config(void *userdata) {
        if (setenv("SYSTEMD_JOURNAL_REMOTE_CONFIG_FILE", "/dev/null", /* overwrite= */ true) < 0) {
                log_debug_errno(errno, "Failed to set $SYSTEMD_JOURNAL_REMOTE_CONFIG_FILE: %m");
                _exit(EXIT_MEMORY);
        }
}

int fork_journal_remote(
                const char *listen_address,
                const char *output,
                uint64_t max_use,
                uint64_t keep_free,
                uint64_t max_file_size,
                uint64_t max_files,
                PidRef *ret_pidref) {

        int r;

        assert(listen_address);
        assert(output);
        assert(ret_pidref);

        ChaseFlags chase_flags = CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY;
        if (endswith(output, ".journal"))
                chase_flags |= CHASE_PARENT;

        _cleanup_close_ int fd = -EBADF;
        r = chase(output, /* root= */ NULL, chase_flags, /* ret_path= */ NULL, &fd);
        if (r < 0)
                return log_error_errno(r, "Failed to create journal directory for '%s': %m", output);

        r = chattr_fd(fd, FS_NOCOW_FL, FS_NOCOW_FL);
        if (r < 0)
                log_debug_errno(r, "Failed to set NOCOW flag on journal directory for '%s', ignoring: %m", output);

        _cleanup_free_ char *sd_socket_activate = NULL;
        r = find_executable("systemd-socket-activate", &sd_socket_activate);
        if (r < 0)
                return log_error_errno(r, "Failed to find systemd-socket-activate binary: %m");

        _cleanup_free_ char *sd_journal_remote = NULL;
        r = find_executable_full(
                        "systemd-journal-remote",
                        /* root= */ NULL,
                        STRV_MAKE(LIBEXECDIR),
                        /* use_path_envvar= */ true,
                        &sd_journal_remote,
                        /* ret_fd= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to find systemd-journal-remote binary: %m");

        _cleanup_strv_free_ char **argv = strv_new(
                        sd_socket_activate,
                        "--listen", listen_address,
                        sd_journal_remote,
                        "--output", output,
                        "--split-mode", endswith(output, ".journal") ? "none" : "host");
        if (!argv)
                return log_oom();

        if (max_use != UINT64_MAX &&
            strv_extendf(&argv, "--max-use=%" PRIu64, max_use) < 0)
                return log_oom();

        if (keep_free != UINT64_MAX &&
            strv_extendf(&argv, "--keep-free=%" PRIu64, keep_free) < 0)
                return log_oom();

        if (max_file_size != UINT64_MAX &&
            strv_extendf(&argv, "--max-file-size=%" PRIu64, max_file_size) < 0)
                return log_oom();

        if (max_files != UINT64_MAX &&
            strv_extendf(&argv, "--max-files=%" PRIu64, max_files) < 0)
                return log_oom();

        return fork_notify(argv, set_journal_remote_config, /* child_userdata= */ NULL, ret_pidref);
}
