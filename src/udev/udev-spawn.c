/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "sd-event.h"

#include "device-private.h"
#include "device-util.h"
#include "fd-util.h"
#include "path-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "udev-builtin.h"
#include "udev-event.h"
#include "udev-spawn.h"
#include "udev-trace.h"

typedef struct Spawn {
        sd_device *device;
        const char *cmd;
        pid_t pid;
        usec_t timeout_warn_usec;
        usec_t timeout_usec;
        int timeout_signal;
        usec_t event_birth_usec;
        bool accept_failure;
        int fd_stdout;
        int fd_stderr;
        char *result;
        size_t result_size;
        size_t result_len;
        bool truncated;
} Spawn;

static int on_spawn_io(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Spawn *spawn = ASSERT_PTR(userdata);
        char buf[4096], *p;
        size_t size;
        ssize_t l;
        int r;

        assert(fd == spawn->fd_stdout || fd == spawn->fd_stderr);
        assert(!spawn->result || spawn->result_len < spawn->result_size);

        if (fd == spawn->fd_stdout && spawn->result) {
                p = spawn->result + spawn->result_len;
                size = spawn->result_size - spawn->result_len;
        } else {
                p = buf;
                size = sizeof(buf);
        }

        l = read(fd, p, size - (p == buf));
        if (l < 0) {
                if (errno == EAGAIN)
                        goto reenable;

                log_device_error_errno(spawn->device, errno,
                                       "Failed to read stdout of '%s': %m", spawn->cmd);

                return 0;
        }

        if ((size_t) l == size) {
                log_device_warning(spawn->device, "Truncating stdout of '%s' up to %zu byte.",
                                   spawn->cmd, spawn->result_size);
                l--;
                spawn->truncated = true;
        }

        p[l] = '\0';
        if (fd == spawn->fd_stdout && spawn->result)
                spawn->result_len += l;

        /* Log output only if we watch stderr. */
        if (l > 0 && spawn->fd_stderr >= 0) {
                _cleanup_strv_free_ char **v = NULL;

                r = strv_split_newlines_full(&v, p, EXTRACT_RETAIN_ESCAPE);
                if (r < 0)
                        log_device_debug(spawn->device,
                                         "Failed to split output from '%s'(%s), ignoring: %m",
                                         spawn->cmd, fd == spawn->fd_stdout ? "out" : "err");

                STRV_FOREACH(q, v)
                        log_device_debug(spawn->device, "'%s'(%s) '%s'", spawn->cmd,
                                         fd == spawn->fd_stdout ? "out" : "err", *q);
        }

        if (l == 0 || spawn->truncated)
                return 0;

reenable:
        /* Re-enable the event source if we did not encounter EOF */

        r = sd_event_source_set_enabled(s, SD_EVENT_ONESHOT);
        if (r < 0)
                log_device_error_errno(spawn->device, r,
                                       "Failed to reactivate IO source of '%s'", spawn->cmd);
        return 0;
}

static int on_spawn_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        Spawn *spawn = ASSERT_PTR(userdata);

        DEVICE_TRACE_POINT(spawn_timeout, spawn->device, spawn->cmd);

        log_device_error(spawn->device, "Spawned process '%s' ["PID_FMT"] timed out after %s, killing.",
                         spawn->cmd, spawn->pid,
                         FORMAT_TIMESPAN(spawn->timeout_usec, USEC_PER_SEC));

        kill_and_sigcont(spawn->pid, spawn->timeout_signal);
        return 1;
}

static int on_spawn_timeout_warning(sd_event_source *s, uint64_t usec, void *userdata) {
        Spawn *spawn = ASSERT_PTR(userdata);

        log_device_warning(spawn->device, "Spawned process '%s' ["PID_FMT"] is taking longer than %s to complete.",
                           spawn->cmd, spawn->pid,
                           FORMAT_TIMESPAN(spawn->timeout_warn_usec, USEC_PER_SEC));

        return 1;
}

static int on_spawn_sigchld(sd_event_source *s, const siginfo_t *si, void *userdata) {
        Spawn *spawn = ASSERT_PTR(userdata);
        int ret = -EIO;

        switch (si->si_code) {
        case CLD_EXITED:
                if (si->si_status == 0)
                        log_device_debug(spawn->device, "Process '%s' succeeded.", spawn->cmd);
                else
                        log_device_full(spawn->device, spawn->accept_failure ? LOG_DEBUG : LOG_WARNING,
                                        "Process '%s' failed with exit code %i.", spawn->cmd, si->si_status);
                ret = si->si_status;
                break;
        case CLD_KILLED:
        case CLD_DUMPED:
                log_device_error(spawn->device, "Process '%s' terminated by signal %s.", spawn->cmd, signal_to_string(si->si_status));
                break;
        default:
                log_device_error(spawn->device, "Process '%s' failed due to unknown reason.", spawn->cmd);
        }

        DEVICE_TRACE_POINT(spawn_exit, spawn->device, spawn->cmd);

        sd_event_exit(sd_event_source_get_event(s), ret);
        return 1;
}

static int spawn_wait(Spawn *spawn) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *sigchld_source = NULL;
        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *stdout_source = NULL;
        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *stderr_source = NULL;
        int r;

        assert(spawn);

        r = sd_event_new(&e);
        if (r < 0)
                return log_device_debug_errno(spawn->device, r, "Failed to allocate sd-event object: %m");

        if (spawn->timeout_usec > 0) {
                usec_t usec, age_usec;

                usec = now(CLOCK_MONOTONIC);
                age_usec = usec - spawn->event_birth_usec;
                if (age_usec < spawn->timeout_usec) {
                        if (spawn->timeout_warn_usec > 0 &&
                            spawn->timeout_warn_usec < spawn->timeout_usec &&
                            spawn->timeout_warn_usec > age_usec) {
                                spawn->timeout_warn_usec -= age_usec;

                                r = sd_event_add_time(e, NULL, CLOCK_MONOTONIC,
                                                      usec + spawn->timeout_warn_usec, USEC_PER_SEC,
                                                      on_spawn_timeout_warning, spawn);
                                if (r < 0)
                                        return log_device_debug_errno(spawn->device, r, "Failed to create timeout warning event source: %m");
                        }

                        spawn->timeout_usec -= age_usec;

                        r = sd_event_add_time(e, NULL, CLOCK_MONOTONIC,
                                              usec + spawn->timeout_usec, USEC_PER_SEC, on_spawn_timeout, spawn);
                        if (r < 0)
                                return log_device_debug_errno(spawn->device, r, "Failed to create timeout event source: %m");
                }
        }

        if (spawn->fd_stdout >= 0) {
                r = sd_event_add_io(e, &stdout_source, spawn->fd_stdout, EPOLLIN, on_spawn_io, spawn);
                if (r < 0)
                        return log_device_debug_errno(spawn->device, r, "Failed to create stdio event source: %m");
                r = sd_event_source_set_enabled(stdout_source, SD_EVENT_ONESHOT);
                if (r < 0)
                        return log_device_debug_errno(spawn->device, r, "Failed to enable stdio event source: %m");
        }

        if (spawn->fd_stderr >= 0) {
                r = sd_event_add_io(e, &stderr_source, spawn->fd_stderr, EPOLLIN, on_spawn_io, spawn);
                if (r < 0)
                        return log_device_debug_errno(spawn->device, r, "Failed to create stderr event source: %m");
                r = sd_event_source_set_enabled(stderr_source, SD_EVENT_ONESHOT);
                if (r < 0)
                        return log_device_debug_errno(spawn->device, r, "Failed to enable stderr event source: %m");
        }

        r = sd_event_add_child(e, &sigchld_source, spawn->pid, WEXITED, on_spawn_sigchld, spawn);
        if (r < 0)
                return log_device_debug_errno(spawn->device, r, "Failed to create sigchild event source: %m");
        /* SIGCHLD should be processed after IO is complete */
        r = sd_event_source_set_priority(sigchld_source, SD_EVENT_PRIORITY_NORMAL + 1);
        if (r < 0)
                return log_device_debug_errno(spawn->device, r, "Failed to set priority to sigchild event source: %m");

        return sd_event_loop(e);
}

int udev_event_spawn(
                UdevEvent *event,
                usec_t timeout_usec,
                int timeout_signal,
                bool accept_failure,
                const char *cmd,
                char *result,
                size_t result_size,
                bool *ret_truncated) {

        _cleanup_close_pair_ int outpipe[2] = EBADF_PAIR, errpipe[2] = EBADF_PAIR;
        _cleanup_strv_free_ char **argv = NULL;
        char **envp = NULL;
        Spawn spawn;
        pid_t pid;
        int r;

        assert(event);
        assert(event->dev);
        assert(result || result_size == 0);

        /* pipes from child to parent */
        if (result || log_get_max_level() >= LOG_INFO)
                if (pipe2(outpipe, O_NONBLOCK|O_CLOEXEC) != 0)
                        return log_device_error_errno(event->dev, errno,
                                                      "Failed to create pipe for command '%s': %m", cmd);

        if (log_get_max_level() >= LOG_INFO)
                if (pipe2(errpipe, O_NONBLOCK|O_CLOEXEC) != 0)
                        return log_device_error_errno(event->dev, errno,
                                                      "Failed to create pipe for command '%s': %m", cmd);

        r = strv_split_full(&argv, cmd, NULL, EXTRACT_UNQUOTE | EXTRACT_RELAX | EXTRACT_RETAIN_ESCAPE);
        if (r < 0)
                return log_device_error_errno(event->dev, r, "Failed to split command: %m");

        if (isempty(argv[0]))
                return log_device_error_errno(event->dev, SYNTHETIC_ERRNO(EINVAL),
                                              "Invalid command '%s'", cmd);

        /* allow programs in /usr/lib/udev/ to be called without the path */
        if (!path_is_absolute(argv[0])) {
                char *program;

                program = path_join(UDEVLIBEXECDIR, argv[0]);
                if (!program)
                        return log_oom();

                free_and_replace(argv[0], program);
        }

        r = device_get_properties_strv(event->dev, &envp);
        if (r < 0)
                return log_device_error_errno(event->dev, r, "Failed to get device properties");

        log_device_debug(event->dev, "Starting '%s'", cmd);

        r = safe_fork_full("(spawn)",
                           (int[]) { -EBADF, outpipe[WRITE_END], errpipe[WRITE_END] },
                           NULL, 0,
                           FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REARRANGE_STDIO|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE,
                           &pid);
        if (r < 0)
                return log_device_error_errno(event->dev, r,
                                              "Failed to fork() to execute command '%s': %m", cmd);
        if (r == 0) {
                DEVICE_TRACE_POINT(spawn_exec, event->dev, cmd);
                execve(argv[0], argv, envp);
                _exit(EXIT_FAILURE);
        }

        /* parent closed child's ends of pipes */
        outpipe[WRITE_END] = safe_close(outpipe[WRITE_END]);
        errpipe[WRITE_END] = safe_close(errpipe[WRITE_END]);

        spawn = (Spawn) {
                .device = event->dev,
                .cmd = cmd,
                .pid = pid,
                .accept_failure = accept_failure,
                .timeout_warn_usec = udev_warn_timeout(timeout_usec),
                .timeout_usec = timeout_usec,
                .timeout_signal = timeout_signal,
                .event_birth_usec = event->birth_usec,
                .fd_stdout = outpipe[READ_END],
                .fd_stderr = errpipe[READ_END],
                .result = result,
                .result_size = result_size,
        };
        r = spawn_wait(&spawn);
        if (r < 0)
                return log_device_error_errno(event->dev, r,
                                              "Failed to wait for spawned command '%s': %m", cmd);

        if (result)
                result[spawn.result_len] = '\0';

        if (ret_truncated)
                *ret_truncated = spawn.truncated;

        return r; /* 0 for success, and positive if the program failed */
}

void udev_event_execute_run(UdevEvent *event, usec_t timeout_usec, int timeout_signal) {
        const char *command;
        void *val;
        int r;

        ORDERED_HASHMAP_FOREACH_KEY(val, command, event->run_list) {
                UdevBuiltinCommand builtin_cmd = PTR_TO_UDEV_BUILTIN_CMD(val);

                if (builtin_cmd != _UDEV_BUILTIN_INVALID) {
                        log_device_debug(event->dev, "Running built-in command \"%s\"", command);
                        r = udev_builtin_run(event, builtin_cmd, command, false);
                        if (r < 0)
                                log_device_debug_errno(event->dev, r, "Failed to run built-in command \"%s\", ignoring: %m", command);
                } else {
                        if (event->exec_delay_usec > 0) {
                                log_device_debug(event->dev, "Delaying execution of \"%s\" for %s.",
                                                 command, FORMAT_TIMESPAN(event->exec_delay_usec, USEC_PER_SEC));
                                (void) usleep_safe(event->exec_delay_usec);
                        }

                        log_device_debug(event->dev, "Running command \"%s\"", command);

                        r = udev_event_spawn(event, timeout_usec, timeout_signal, false, command, NULL, 0, NULL);
                        if (r < 0)
                                log_device_warning_errno(event->dev, r, "Failed to execute '%s', ignoring: %m", command);
                        else if (r > 0) /* returned value is positive when program fails */
                                log_device_debug(event->dev, "Command \"%s\" returned %d (error), ignoring.", command, r);
                }
        }
}
