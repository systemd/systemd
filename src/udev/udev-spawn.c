/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <unistd.h>

#include "sd-event.h"

#include "build-path.h"
#include "device-private.h"
#include "device-util.h"
#include "errno-util.h"
#include "event-util.h"
#include "exec-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "format-util.h"
#include "hashmap.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "udev-builtin.h"
#include "udev-event.h"
#include "udev-spawn.h"
#include "udev-trace.h"
#include "udev-worker.h"

typedef struct Spawn {
        sd_device *device;
        const char *cmd;
        PidRef pidref;
        usec_t timeout_warn_usec;
        usec_t timeout_usec;
        int timeout_signal;
        usec_t event_birth_usec;
        usec_t cmd_birth_usec;
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
        bool read_to_result;
        char buf[4096], *p;
        size_t size;
        ssize_t l;
        int r;

        assert(fd == spawn->fd_stdout || fd == spawn->fd_stderr);
        assert(!spawn->result || spawn->result_len < spawn->result_size);

        if (fd == spawn->fd_stdout && spawn->result && !spawn->truncated) {
                /* When reading to the result buffer, use the maximum available size, to detect truncation. */
                read_to_result = true;
                p = spawn->result + spawn->result_len;
                size = spawn->result_size - spawn->result_len;
                assert(size > 0);
        } else {
                /* When reading to the local buffer, keep the space for the trailing NUL. */
                read_to_result = false;
                p = buf;
                size = sizeof(buf) - 1;
        }

        l = read(fd, p, size);
        if (l < 0) {
                log_device_full_errno(spawn->device,
                                      ERRNO_IS_TRANSIENT(errno) ? LOG_DEBUG : LOG_WARNING,
                                      errno,
                                      "Failed to read %s of '%s', ignoring: %m",
                                      fd == spawn->fd_stdout ? "stdout" : "stderr",
                                      spawn->cmd);
                return 0;
        }
        if (l == 0) { /* EOF */
                r = sd_event_source_set_enabled(s, SD_EVENT_OFF);
                if (r < 0) {
                        log_device_warning_errno(spawn->device, r,
                                                 "Failed to disable %s event source of '%s': %m",
                                                 fd == spawn->fd_stdout ? "stdout" : "stderr",
                                                 spawn->cmd);
                        (void) sd_event_exit(sd_event_source_get_event(s), r); /* propagate negative errno */
                        return r;
                }
                return 0;
        }

        if (read_to_result) {
                if ((size_t) l == size) {
                        log_device_warning(spawn->device, "Truncating stdout of '%s' up to %zu byte.",
                                           spawn->cmd, spawn->result_size - 1);
                        l--;
                        spawn->truncated = true;
                }

                spawn->result_len += l;
        }

        p[l] = '\0';

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

        return 0;
}

static int on_spawn_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        Spawn *spawn = ASSERT_PTR(userdata);

        DEVICE_TRACE_POINT(spawn_timeout, spawn->device, spawn->cmd);

        log_device_error(spawn->device, "Spawned process '%s' ["PID_FMT"] timed out after %s, killing.",
                         spawn->cmd, spawn->pidref.pid,
                         FORMAT_TIMESPAN(spawn->timeout_usec, USEC_PER_SEC));

        (void) pidref_kill_and_sigcont(&spawn->pidref, spawn->timeout_signal);
        return 1;
}

static int on_spawn_timeout_warning(sd_event_source *s, uint64_t usec, void *userdata) {
        Spawn *spawn = ASSERT_PTR(userdata);

        log_device_warning(spawn->device, "Spawned process '%s' ["PID_FMT"] is taking longer than %s to complete.",
                           spawn->cmd, spawn->pidref.pid,
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

        if (spawn->timeout_usec != USEC_INFINITY) {
                if (spawn->timeout_warn_usec < spawn->timeout_usec) {
                        r = sd_event_add_time(e, NULL, CLOCK_MONOTONIC,
                                              usec_add(spawn->cmd_birth_usec, spawn->timeout_warn_usec), USEC_PER_SEC,
                                              on_spawn_timeout_warning, spawn);
                        if (r < 0)
                                return log_device_debug_errno(spawn->device, r, "Failed to create timeout warning event source: %m");
                }

                r = sd_event_add_time(e, NULL, CLOCK_MONOTONIC,
                                      usec_add(spawn->cmd_birth_usec, spawn->timeout_usec), USEC_PER_SEC,
                                      on_spawn_timeout, spawn);
                if (r < 0)
                        return log_device_debug_errno(spawn->device, r, "Failed to create timeout event source: %m");
        }

        if (spawn->fd_stdout >= 0) {
                r = sd_event_add_io(e, &stdout_source, spawn->fd_stdout, EPOLLIN, on_spawn_io, spawn);
                if (r < 0)
                        return log_device_debug_errno(spawn->device, r, "Failed to create stdio event source: %m");
        }

        if (spawn->fd_stderr >= 0) {
                r = sd_event_add_io(e, &stderr_source, spawn->fd_stderr, EPOLLIN, on_spawn_io, spawn);
                if (r < 0)
                        return log_device_debug_errno(spawn->device, r, "Failed to create stderr event source: %m");
        }

        r = event_add_child_pidref(e, &sigchld_source, &spawn->pidref, WEXITED, on_spawn_sigchld, spawn);
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
                bool accept_failure,
                const char *cmd,
                char *result,
                size_t result_size,
                bool *ret_truncated) {

        int r;

        assert(event);
        assert(IN_SET(event->event_mode, EVENT_UDEV_WORKER, EVENT_UDEVADM_TEST, EVENT_TEST_RULE_RUNNER, EVENT_TEST_SPAWN));
        assert(event->dev);
        assert(cmd);
        assert(result || result_size == 0);

        if (event->event_mode == EVENT_UDEVADM_TEST &&
            !STARTSWITH_SET(cmd, "ata_id", "cdrom_id", "dmi_memory_id", "fido_id", "mtd_probe", "scsi_id")) {
                log_device_debug(event->dev, "Running in test mode, skipping execution of '%s'.", cmd);
                result[0] = '\0';
                if (ret_truncated)
                        *ret_truncated = false;
                return 0;
        }

        int timeout_signal = event->worker ? event->worker->config.timeout_signal : SIGKILL;
        usec_t timeout_usec = event->worker ? event->worker->config.timeout_usec : DEFAULT_WORKER_TIMEOUT_USEC;
        usec_t now_usec = now(CLOCK_MONOTONIC);
        usec_t age_usec = usec_sub_unsigned(now_usec, event->birth_usec);
        usec_t cmd_timeout_usec = usec_sub_unsigned(timeout_usec, age_usec);
        if (cmd_timeout_usec <= 0)
                return log_device_warning_errno(event->dev, SYNTHETIC_ERRNO(ETIME),
                                                "The event already takes longer (%s) than the timeout (%s), skipping execution of '%s'.",
                                                FORMAT_TIMESPAN(age_usec, 1), FORMAT_TIMESPAN(timeout_usec, 1), cmd);

        /* pipes from child to parent */
        _cleanup_close_pair_ int outpipe[2] = EBADF_PAIR;
        if (result || log_get_max_level() >= LOG_INFO)
                if (pipe2(outpipe, O_NONBLOCK|O_CLOEXEC) != 0)
                        return log_device_error_errno(event->dev, errno,
                                                      "Failed to create pipe for command '%s': %m", cmd);

        _cleanup_close_pair_ int errpipe[2] = EBADF_PAIR;
        if (log_get_max_level() >= LOG_INFO)
                if (pipe2(errpipe, O_NONBLOCK|O_CLOEXEC) != 0)
                        return log_device_error_errno(event->dev, errno,
                                                      "Failed to create pipe for command '%s': %m", cmd);

        _cleanup_strv_free_ char **argv = NULL;
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

        char *found;
        _cleanup_close_ int fd_executable = r = pin_callout_binary(argv[0], &found);
        if (r < 0)
                return log_device_error_errno(event->dev, r, "Failed to find and pin callout binary \"%s\": %m", argv[0]);

        log_device_debug(event->dev, "Found callout binary: \"%s\".", found);
        free_and_replace(argv[0], found);

        char **envp;
        r = device_get_properties_strv(event->dev, &envp);
        if (r < 0)
                return log_device_error_errno(event->dev, r, "Failed to get device properties");

        log_device_debug(event->dev, "Starting '%s'", cmd);

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork_full(
                        "(spawn)",
                        (int[]) { -EBADF, outpipe[WRITE_END], errpipe[WRITE_END] },
                        &fd_executable, 1,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REARRANGE_STDIO|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE,
                        &pidref);
        if (r < 0)
                return log_device_error_errno(event->dev, r,
                                              "Failed to fork() to execute command '%s': %m", cmd);
        if (r == 0) {
                DEVICE_TRACE_POINT(spawn_exec, event->dev, cmd);
                (void) fexecve_or_execve(fd_executable, argv[0], argv, envp);
                _exit(EXIT_FAILURE);
        }

        /* parent closed child's ends of pipes */
        outpipe[WRITE_END] = safe_close(outpipe[WRITE_END]);
        errpipe[WRITE_END] = safe_close(errpipe[WRITE_END]);

        Spawn spawn = {
                .device = event->dev,
                .cmd = cmd,
                .pidref = pidref, /* Do not take ownership */
                .accept_failure = accept_failure,
                .timeout_warn_usec = udev_warn_timeout(cmd_timeout_usec),
                .timeout_usec = cmd_timeout_usec,
                .timeout_signal = timeout_signal,
                .event_birth_usec = event->birth_usec,
                .cmd_birth_usec = now_usec,
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

void udev_event_execute_run(UdevEvent *event) {
        const char *command;
        void *val;
        int r;

        assert(event);

        ORDERED_HASHMAP_FOREACH_KEY(val, command, event->run_list) {
                UdevBuiltinCommand builtin_cmd = PTR_TO_UDEV_BUILTIN_CMD(val);

                if (builtin_cmd >= 0) {
                        log_device_debug(event->dev, "Running built-in command \"%s\"", command);
                        r = udev_builtin_run(event, builtin_cmd, command);
                        if (r < 0)
                                log_device_debug_errno(event->dev, r, "Failed to run built-in command \"%s\", ignoring: %m", command);
                } else {
                        if (event->worker && event->worker->config.exec_delay_usec > 0) {
                                usec_t now_usec = now(CLOCK_MONOTONIC);
                                usec_t age_usec = usec_sub_unsigned(now_usec, event->birth_usec);

                                if (event->worker->config.exec_delay_usec >= usec_sub_unsigned(event->worker->config.timeout_usec, age_usec)) {
                                        log_device_warning(event->dev,
                                                           "Cannot delay execution of \"%s\" for %s, skipping.",
                                                           command, FORMAT_TIMESPAN(event->worker->config.exec_delay_usec, USEC_PER_SEC));
                                        continue;
                                }

                                log_device_debug(event->dev, "Delaying execution of \"%s\" for %s.",
                                                 command, FORMAT_TIMESPAN(event->worker->config.exec_delay_usec, USEC_PER_SEC));
                                (void) usleep_safe(event->worker->config.exec_delay_usec);
                        }

                        log_device_debug(event->dev, "Running command \"%s\"", command);

                        r = udev_event_spawn(event, /* accept_failure = */ false, command, NULL, 0, NULL);
                        if (r < 0)
                                log_device_warning_errno(event->dev, r, "Failed to execute '%s', ignoring: %m", command);
                        else if (r > 0) /* returned value is positive when program fails */
                                log_device_debug(event->dev, "Command \"%s\" returned %d (error), ignoring.", command, r);
                }
        }
}
