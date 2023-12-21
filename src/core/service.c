/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <math.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "async.h"
#include "bus-error.h"
#include "bus-kernel.h"
#include "bus-util.h"
#include "chase.h"
#include "constants.h"
#include "dbus-service.h"
#include "dbus-unit.h"
#include "devnum-util.h"
#include "env-util.h"
#include "escape.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "load-dropin.h"
#include "load-fragment.h"
#include "log.h"
#include "manager.h"
#include "missing_audit.h"
#include "open-file.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "selinux-util.h"
#include "serialize.h"
#include "service.h"
#include "signal-util.h"
#include "special.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "unit.h"
#include "utf8.h"

#define service_spawn(...) service_spawn_internal(__func__, __VA_ARGS__)

static const UnitActiveState state_translation_table[_SERVICE_STATE_MAX] = {
        [SERVICE_DEAD] = UNIT_INACTIVE,
        [SERVICE_CONDITION] = UNIT_ACTIVATING,
        [SERVICE_START_PRE] = UNIT_ACTIVATING,
        [SERVICE_START] = UNIT_ACTIVATING,
        [SERVICE_START_POST] = UNIT_ACTIVATING,
        [SERVICE_RUNNING] = UNIT_ACTIVE,
        [SERVICE_EXITED] = UNIT_ACTIVE,
        [SERVICE_RELOAD] = UNIT_RELOADING,
        [SERVICE_RELOAD_SIGNAL] = UNIT_RELOADING,
        [SERVICE_RELOAD_NOTIFY] = UNIT_RELOADING,
        [SERVICE_STOP] = UNIT_DEACTIVATING,
        [SERVICE_STOP_WATCHDOG] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_STOP_POST] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_WATCHDOG] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_FAILED] = UNIT_FAILED,
        [SERVICE_DEAD_BEFORE_AUTO_RESTART] = UNIT_INACTIVE,
        [SERVICE_FAILED_BEFORE_AUTO_RESTART] = UNIT_FAILED,
        [SERVICE_DEAD_RESOURCES_PINNED] = UNIT_INACTIVE,
        [SERVICE_AUTO_RESTART] = UNIT_ACTIVATING,
        [SERVICE_AUTO_RESTART_QUEUED] = UNIT_ACTIVATING,
        [SERVICE_CLEANING] = UNIT_MAINTENANCE,
};

/* For Type=idle we never want to delay any other jobs, hence we
 * consider idle jobs active as soon as we start working on them */
static const UnitActiveState state_translation_table_idle[_SERVICE_STATE_MAX] = {
        [SERVICE_DEAD] = UNIT_INACTIVE,
        [SERVICE_CONDITION] = UNIT_ACTIVE,
        [SERVICE_START_PRE] = UNIT_ACTIVE,
        [SERVICE_START] = UNIT_ACTIVE,
        [SERVICE_START_POST] = UNIT_ACTIVE,
        [SERVICE_RUNNING] = UNIT_ACTIVE,
        [SERVICE_EXITED] = UNIT_ACTIVE,
        [SERVICE_RELOAD] = UNIT_RELOADING,
        [SERVICE_RELOAD_SIGNAL] = UNIT_RELOADING,
        [SERVICE_RELOAD_NOTIFY] = UNIT_RELOADING,
        [SERVICE_STOP] = UNIT_DEACTIVATING,
        [SERVICE_STOP_WATCHDOG] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_STOP_POST] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_WATCHDOG] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_FAILED] = UNIT_FAILED,
        [SERVICE_DEAD_BEFORE_AUTO_RESTART] = UNIT_INACTIVE,
        [SERVICE_FAILED_BEFORE_AUTO_RESTART] = UNIT_FAILED,
        [SERVICE_DEAD_RESOURCES_PINNED] = UNIT_INACTIVE,
        [SERVICE_AUTO_RESTART] = UNIT_ACTIVATING,
        [SERVICE_AUTO_RESTART_QUEUED] = UNIT_ACTIVATING,
        [SERVICE_CLEANING] = UNIT_MAINTENANCE,
};

static int service_dispatch_inotify_io(sd_event_source *source, int fd, uint32_t events, void *userdata);
static int service_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata);
static int service_dispatch_watchdog(sd_event_source *source, usec_t usec, void *userdata);
static int service_dispatch_exec_io(sd_event_source *source, int fd, uint32_t events, void *userdata);

static void service_enter_signal(Service *s, ServiceState state, ServiceResult f);
static void service_enter_reload_by_notify(Service *s);

static void service_init(Unit *u) {
        Service *s = SERVICE(u);

        assert(u);
        assert(u->load_state == UNIT_STUB);

        s->timeout_start_usec = u->manager->defaults.timeout_start_usec;
        s->timeout_stop_usec = u->manager->defaults.timeout_stop_usec;
        s->timeout_abort_usec = u->manager->defaults.timeout_abort_usec;
        s->timeout_abort_set = u->manager->defaults.timeout_abort_set;
        s->restart_usec = u->manager->defaults.restart_usec;
        s->restart_max_delay_usec = USEC_INFINITY;
        s->runtime_max_usec = USEC_INFINITY;
        s->type = _SERVICE_TYPE_INVALID;
        s->socket_fd = -EBADF;
        s->stdin_fd = s->stdout_fd = s->stderr_fd = -EBADF;
        s->guess_main_pid = true;
        s->main_pid = PIDREF_NULL;
        s->control_pid = PIDREF_NULL;
        s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;

        s->exec_context.keyring_mode = MANAGER_IS_SYSTEM(u->manager) ?
                EXEC_KEYRING_PRIVATE : EXEC_KEYRING_INHERIT;

        s->notify_access_override = _NOTIFY_ACCESS_INVALID;

        s->watchdog_original_usec = USEC_INFINITY;

        s->oom_policy = _OOM_POLICY_INVALID;
        s->reload_begin_usec = USEC_INFINITY;
        s->reload_signal = SIGHUP;

        s->fd_store_preserve_mode = EXEC_PRESERVE_RESTART;
}

static void service_unwatch_control_pid(Service *s) {
        assert(s);

        if (!pidref_is_set(&s->control_pid))
                return;

        unit_unwatch_pidref(UNIT(s), &s->control_pid);
        pidref_done(&s->control_pid);
}

static void service_unwatch_main_pid(Service *s) {
        assert(s);

        if (!pidref_is_set(&s->main_pid))
                return;

        unit_unwatch_pidref(UNIT(s), &s->main_pid);
        pidref_done(&s->main_pid);
}

static void service_unwatch_pid_file(Service *s) {
        if (!s->pid_file_pathspec)
                return;

        log_unit_debug(UNIT(s), "Stopping watch for PID file %s", s->pid_file_pathspec->path);
        path_spec_unwatch(s->pid_file_pathspec);
        path_spec_done(s->pid_file_pathspec);
        s->pid_file_pathspec = mfree(s->pid_file_pathspec);
}

static int service_set_main_pidref(Service *s, PidRef *pidref) {
        int r;

        assert(s);

        /* Takes ownership of the specified pidref on success, but not on failure. */

        if (!pidref_is_set(pidref))
                return -ESRCH;

        if (pidref->pid <= 1)
                return -EINVAL;

        if (pidref_is_self(pidref))
                return -EINVAL;

        if (pidref_equal(&s->main_pid, pidref) && s->main_pid_known) {
                pidref_done(pidref);
                return 0;
        }

        if (!pidref_equal(&s->main_pid, pidref)) {
                service_unwatch_main_pid(s);
                exec_status_start(&s->main_exec_status, pidref->pid);
        }

        s->main_pid = TAKE_PIDREF(*pidref);
        s->main_pid_known = true;

        r = pidref_is_my_child(&s->main_pid);
        if (r < 0)
                log_unit_warning_errno(UNIT(s), r, "Can't determine if process "PID_FMT" is our child, assuming it is not: %m", s->main_pid.pid);
        else if (r == 0)
                log_unit_warning(UNIT(s), "Supervising process "PID_FMT" which is not our child. We'll most likely not notice when it exits.", s->main_pid.pid);

        s->main_pid_alien = r <= 0;
        return 0;
}

void service_release_socket_fd(Service *s) {
        assert(s);

        if (s->socket_fd < 0 && !UNIT_ISSET(s->accept_socket) && !s->socket_peer)
                return;

        log_unit_debug(UNIT(s), "Closing connection socket.");

        /* Undo the effect of service_set_socket_fd(). */

        s->socket_fd = asynchronous_close(s->socket_fd);

        if (UNIT_ISSET(s->accept_socket)) {
                socket_connection_unref(SOCKET(UNIT_DEREF(s->accept_socket)));
                unit_ref_unset(&s->accept_socket);
        }

        s->socket_peer = socket_peer_unref(s->socket_peer);
}

static void service_override_notify_access(Service *s, NotifyAccess notify_access_override) {
        assert(s);

        s->notify_access_override = notify_access_override;

        log_unit_debug(UNIT(s), "notify_access=%s", notify_access_to_string(s->notify_access));
        log_unit_debug(UNIT(s), "notify_access_override=%s", notify_access_to_string(s->notify_access_override));
}

static void service_stop_watchdog(Service *s) {
        assert(s);

        s->watchdog_event_source = sd_event_source_disable_unref(s->watchdog_event_source);
        s->watchdog_timestamp = DUAL_TIMESTAMP_NULL;
}

static void service_start_watchdog(Service *s) {
        usec_t watchdog_usec;
        int r;

        assert(s);

        watchdog_usec = service_get_watchdog_usec(s);
        if (!timestamp_is_set(watchdog_usec)) {
                service_stop_watchdog(s);
                return;
        }

        if (s->watchdog_event_source) {
                r = sd_event_source_set_time(s->watchdog_event_source, usec_add(s->watchdog_timestamp.monotonic, watchdog_usec));
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to reset watchdog timer: %m");
                        return;
                }

                r = sd_event_source_set_enabled(s->watchdog_event_source, SD_EVENT_ONESHOT);
        } else {
                r = sd_event_add_time(
                                UNIT(s)->manager->event,
                                &s->watchdog_event_source,
                                CLOCK_MONOTONIC,
                                usec_add(s->watchdog_timestamp.monotonic, watchdog_usec), 0,
                                service_dispatch_watchdog, s);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to add watchdog timer: %m");
                        return;
                }

                (void) sd_event_source_set_description(s->watchdog_event_source, "service-watchdog");

                /* Let's process everything else which might be a sign
                 * of living before we consider a service died. */
                r = sd_event_source_set_priority(s->watchdog_event_source, SD_EVENT_PRIORITY_IDLE);
        }
        if (r < 0)
                log_unit_warning_errno(UNIT(s), r, "Failed to install watchdog timer: %m");
}

usec_t service_restart_usec_next(Service *s) {
        unsigned n_restarts_next;

        assert(s);

        /* When the service state is in SERVICE_*_BEFORE_AUTO_RESTART or SERVICE_AUTO_RESTART, we still need
         * to add 1 to s->n_restarts manually, because s->n_restarts is not updated until a restart job is
         * enqueued, i.e. state has transitioned to SERVICE_AUTO_RESTART_QUEUED. */
        n_restarts_next = s->n_restarts + (s->state == SERVICE_AUTO_RESTART_QUEUED ? 0 : 1);

        if (n_restarts_next <= 1 ||
            s->restart_steps == 0 ||
            s->restart_usec == 0 ||
            s->restart_max_delay_usec == USEC_INFINITY ||
            s->restart_usec >= s->restart_max_delay_usec)
                return s->restart_usec;

        if (n_restarts_next > s->restart_steps)
                return s->restart_max_delay_usec;

        /* Enforced in service_verify() and above */
        assert(s->restart_max_delay_usec > s->restart_usec);

        /* r_i / r_0 = (r_n / r_0) ^ (i / n)
         * where,
         *   r_0 : initial restart usec (s->restart_usec),
         *   r_i : i-th restart usec (value),
         *   r_n : maximum restart usec (s->restart_max_delay_usec),
         *   i : index of the next step (n_restarts_next - 1)
         *   n : num maximum steps (s->restart_steps) */
        return (usec_t) (s->restart_usec * powl((long double) s->restart_max_delay_usec / s->restart_usec,
                                                (long double) (n_restarts_next - 1) / s->restart_steps));
}

static void service_extend_event_source_timeout(Service *s, sd_event_source *source, usec_t extended) {
        usec_t current;
        int r;

        assert(s);

        /* Extends the specified event source timer to at least the specified time, unless it is already later
         * anyway. */

        if (!source)
                return;

        r = sd_event_source_get_time(source, &current);
        if (r < 0) {
                const char *desc;
                (void) sd_event_source_get_description(s->timer_event_source, &desc);
                log_unit_warning_errno(UNIT(s), r, "Failed to retrieve timeout time for event source '%s', ignoring: %m", strna(desc));
                return;
        }

        if (current >= extended) /* Current timeout is already longer, ignore this. */
                return;

        r = sd_event_source_set_time(source, extended);
        if (r < 0) {
                const char *desc;
                (void) sd_event_source_get_description(s->timer_event_source, &desc);
                log_unit_warning_errno(UNIT(s), r, "Failed to set timeout time for event source '%s', ignoring %m", strna(desc));
        }
}

static void service_extend_timeout(Service *s, usec_t extend_timeout_usec) {
        usec_t extended;

        assert(s);

        if (!timestamp_is_set(extend_timeout_usec))
                return;

        extended = usec_add(now(CLOCK_MONOTONIC), extend_timeout_usec);

        service_extend_event_source_timeout(s, s->timer_event_source, extended);
        service_extend_event_source_timeout(s, s->watchdog_event_source, extended);
}

static void service_reset_watchdog(Service *s) {
        assert(s);

        dual_timestamp_now(&s->watchdog_timestamp);
        service_start_watchdog(s);
}

static void service_override_watchdog_timeout(Service *s, usec_t watchdog_override_usec) {
        assert(s);

        s->watchdog_override_enable = true;
        s->watchdog_override_usec = watchdog_override_usec;
        service_reset_watchdog(s);

        log_unit_debug(UNIT(s), "watchdog_usec="USEC_FMT, s->watchdog_usec);
        log_unit_debug(UNIT(s), "watchdog_override_usec="USEC_FMT, s->watchdog_override_usec);
}

static ServiceFDStore* service_fd_store_unlink(ServiceFDStore *fs) {
        if (!fs)
                return NULL;

        if (fs->service) {
                assert(fs->service->n_fd_store > 0);
                LIST_REMOVE(fd_store, fs->service->fd_store, fs);
                fs->service->n_fd_store--;
        }

        sd_event_source_disable_unref(fs->event_source);

        free(fs->fdname);
        asynchronous_close(fs->fd);
        return mfree(fs);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(ServiceFDStore*, service_fd_store_unlink);

static void service_release_fd_store(Service *s) {
        assert(s);

        if (!s->fd_store)
                return;

        log_unit_debug(UNIT(s), "Releasing all stored fds");

        while (s->fd_store)
                service_fd_store_unlink(s->fd_store);

        assert(s->n_fd_store == 0);
}

static void service_release_stdio_fd(Service *s) {
        assert(s);

        if (s->stdin_fd < 0 && s->stdout_fd < 0 && s->stdout_fd < 0)
                return;

        log_unit_debug(UNIT(s), "Releasing stdin/stdout/stderr file descriptors.");

        s->stdin_fd = asynchronous_close(s->stdin_fd);
        s->stdout_fd = asynchronous_close(s->stdout_fd);
        s->stderr_fd = asynchronous_close(s->stderr_fd);
}
static void service_done(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        open_file_free_many(&s->open_files);

        s->pid_file = mfree(s->pid_file);
        s->status_text = mfree(s->status_text);

        s->exec_runtime = exec_runtime_free(s->exec_runtime);
        exec_command_free_array(s->exec_command, _SERVICE_EXEC_COMMAND_MAX);
        s->control_command = NULL;
        s->main_command = NULL;

        exit_status_set_free(&s->restart_prevent_status);
        exit_status_set_free(&s->restart_force_status);
        exit_status_set_free(&s->success_status);

        /* This will leak a process, but at least no memory or any of our resources */
        service_unwatch_main_pid(s);
        service_unwatch_control_pid(s);
        service_unwatch_pid_file(s);

        if (s->bus_name)  {
                unit_unwatch_bus_name(u, s->bus_name);
                s->bus_name = mfree(s->bus_name);
        }

        s->bus_name_owner = mfree(s->bus_name_owner);

        s->usb_function_descriptors = mfree(s->usb_function_descriptors);
        s->usb_function_strings = mfree(s->usb_function_strings);

        service_stop_watchdog(s);

        s->timer_event_source = sd_event_source_disable_unref(s->timer_event_source);
        s->exec_fd_event_source = sd_event_source_disable_unref(s->exec_fd_event_source);

        s->bus_name_pid_lookup_slot = sd_bus_slot_unref(s->bus_name_pid_lookup_slot);

        service_release_socket_fd(s);
        service_release_stdio_fd(s);
        service_release_fd_store(s);
}

static int on_fd_store_io(sd_event_source *e, int fd, uint32_t revents, void *userdata) {
        ServiceFDStore *fs = ASSERT_PTR(userdata);

        assert(e);

        /* If we get either EPOLLHUP or EPOLLERR, it's time to remove this entry from the fd store */
        log_unit_debug(UNIT(fs->service),
                       "Received %s on stored fd %d (%s), closing.",
                       revents & EPOLLERR ? "EPOLLERR" : "EPOLLHUP",
                       fs->fd, strna(fs->fdname));
        service_fd_store_unlink(fs);
        return 0;
}

static int service_add_fd_store(Service *s, int fd_in, const char *name, bool do_poll) {
        _cleanup_(service_fd_store_unlinkp) ServiceFDStore *fs = NULL;
        _cleanup_(asynchronous_closep) int fd = ASSERT_FD(fd_in);
        struct stat st;
        int r;

        /* fd is always consumed even if the function fails. */

        assert(s);

        if (fstat(fd, &st) < 0)
                return -errno;

        log_unit_debug(UNIT(s), "Trying to stash fd for dev=" DEVNUM_FORMAT_STR "/inode=%" PRIu64, DEVNUM_FORMAT_VAL(st.st_dev), (uint64_t) st.st_ino);

        if (s->n_fd_store >= s->n_fd_store_max)
                /* Our store is full.  Use this errno rather than E[NM]FILE to distinguish from the case
                 * where systemd itself hits the file limit. */
                return log_unit_debug_errno(UNIT(s), SYNTHETIC_ERRNO(EXFULL), "Hit fd store limit.");

        LIST_FOREACH(fd_store, i, s->fd_store) {
                r = same_fd(i->fd, fd);
                if (r < 0)
                        return r;
                if (r > 0) {
                        log_unit_debug(UNIT(s), "Suppressing duplicate fd %i in fd store.", fd);
                        return 0; /* fd already included */
                }
        }

        fs = new(ServiceFDStore, 1);
        if (!fs)
                return -ENOMEM;

        *fs = (ServiceFDStore) {
                .fd = TAKE_FD(fd),
                .do_poll = do_poll,
                .fdname = strdup(name ?: "stored"),
        };

        if (!fs->fdname)
                return -ENOMEM;

        if (do_poll) {
                r = sd_event_add_io(UNIT(s)->manager->event, &fs->event_source, fs->fd, 0, on_fd_store_io, fs);
                if (r < 0 && r != -EPERM) /* EPERM indicates fds that aren't pollable, which is OK */
                        return r;
                else if (r >= 0)
                        (void) sd_event_source_set_description(fs->event_source, "service-fd-store");
        }

        fs->service = s;
        LIST_PREPEND(fd_store, s->fd_store, fs);
        s->n_fd_store++;

        log_unit_debug(UNIT(s), "Added fd %i (%s) to fd store.", fs->fd, fs->fdname);

        TAKE_PTR(fs);
        return 1; /* fd newly stored */
}

static int service_add_fd_store_set(Service *s, FDSet *fds, const char *name, bool do_poll) {
        int r;

        assert(s);

        for (;;) {
                int fd;

                fd = fdset_steal_first(fds);
                if (fd < 0)
                        break;

                r = service_add_fd_store(s, fd, name, do_poll);
                if (r == -EXFULL)
                        return log_unit_warning_errno(UNIT(s), r,
                                                      "Cannot store more fds than FileDescriptorStoreMax=%u, closing remaining.",
                                                      s->n_fd_store_max);
                if (r < 0)
                        return log_unit_error_errno(UNIT(s), r, "Failed to add fd to store: %m");
        }

        return 0;
}

static void service_remove_fd_store(Service *s, const char *name) {
        assert(s);
        assert(name);

        LIST_FOREACH(fd_store, fs, s->fd_store) {
                if (!streq(fs->fdname, name))
                        continue;

                log_unit_debug(UNIT(s), "Got explicit request to remove fd %i (%s), closing.", fs->fd, name);
                service_fd_store_unlink(fs);
        }
}

static usec_t service_running_timeout(Service *s) {
        usec_t delta = 0;

        assert(s);

        if (s->runtime_rand_extra_usec != 0) {
                delta = random_u64_range(s->runtime_rand_extra_usec);
                log_unit_debug(UNIT(s), "Adding delta of %s sec to timeout", FORMAT_TIMESPAN(delta, USEC_PER_SEC));
        }

        return usec_add(usec_add(UNIT(s)->active_enter_timestamp.monotonic,
                                 s->runtime_max_usec),
                        delta);
}

static int service_arm_timer(Service *s, bool relative, usec_t usec) {
        assert(s);

        return unit_arm_timer(UNIT(s), &s->timer_event_source, relative, usec, service_dispatch_timer);
}

static int service_verify(Service *s) {
        assert(s);
        assert(UNIT(s)->load_state == UNIT_LOADED);

        for (ServiceExecCommand c = 0; c < _SERVICE_EXEC_COMMAND_MAX; c++)
                LIST_FOREACH(command, command, s->exec_command[c]) {
                        if (!path_is_absolute(command->path) && !filename_is_valid(command->path))
                                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC),
                                                            "Service %s= binary path \"%s\" is neither a valid executable name nor an absolute path. Refusing.",
                                                            command->path,
                                                            service_exec_command_to_string(c));
                        if (strv_isempty(command->argv))
                                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC),
                                                            "Service has an empty argv in %s=. Refusing.",
                                                            service_exec_command_to_string(c));
                }

        if (!s->exec_command[SERVICE_EXEC_START] && !s->exec_command[SERVICE_EXEC_STOP] &&
            UNIT(s)->success_action == EMERGENCY_ACTION_NONE)
                /* FailureAction= only makes sense if one of the start or stop commands is specified.
                 * SuccessAction= will be executed unconditionally if no commands are specified. Hence,
                 * either a command or SuccessAction= are required. */

                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC), "Service has no ExecStart=, ExecStop=, or SuccessAction=. Refusing.");

        if (s->type != SERVICE_ONESHOT && !s->exec_command[SERVICE_EXEC_START])
                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC), "Service has no ExecStart= setting, which is only allowed for Type=oneshot services. Refusing.");

        if (!s->remain_after_exit && !s->exec_command[SERVICE_EXEC_START] && UNIT(s)->success_action == EMERGENCY_ACTION_NONE)
                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC), "Service has no ExecStart= and no SuccessAction= settings and does not have RemainAfterExit=yes set. Refusing.");

        if (s->type != SERVICE_ONESHOT && s->exec_command[SERVICE_EXEC_START]->command_next)
                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC), "Service has more than one ExecStart= setting, which is only allowed for Type=oneshot services. Refusing.");

        if (s->type == SERVICE_ONESHOT &&
            !IN_SET(s->restart, SERVICE_RESTART_NO, SERVICE_RESTART_ON_FAILURE, SERVICE_RESTART_ON_ABNORMAL, SERVICE_RESTART_ON_WATCHDOG, SERVICE_RESTART_ON_ABORT))
                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC), "Service has Restart= set to either always or on-success, which isn't allowed for Type=oneshot services. Refusing.");

        if (s->type == SERVICE_ONESHOT && !exit_status_set_is_empty(&s->restart_force_status))
                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC), "Service has RestartForceExitStatus= set, which isn't allowed for Type=oneshot services. Refusing.");

        if (s->type == SERVICE_ONESHOT && s->exit_type == SERVICE_EXIT_CGROUP)
                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC), "Service has ExitType=cgroup set, which isn't allowed for Type=oneshot services. Refusing.");

        if (s->type == SERVICE_DBUS && !s->bus_name)
                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC), "Service is of type D-Bus but no D-Bus service name has been specified. Refusing.");

        if (s->exec_context.pam_name && !IN_SET(s->kill_context.kill_mode, KILL_CONTROL_GROUP, KILL_MIXED))
                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC), "Service has PAM enabled. Kill mode must be set to 'control-group' or 'mixed'. Refusing.");

        if (s->usb_function_descriptors && !s->usb_function_strings)
                log_unit_warning(UNIT(s), "Service has USBFunctionDescriptors= setting, but no USBFunctionStrings=. Ignoring.");

        if (!s->usb_function_descriptors && s->usb_function_strings)
                log_unit_warning(UNIT(s), "Service has USBFunctionStrings= setting, but no USBFunctionDescriptors=. Ignoring.");

        if (s->runtime_max_usec != USEC_INFINITY && s->type == SERVICE_ONESHOT)
                log_unit_warning(UNIT(s), "RuntimeMaxSec= has no effect in combination with Type=oneshot. Ignoring.");

        if (s->runtime_max_usec == USEC_INFINITY && s->runtime_rand_extra_usec != 0)
                log_unit_warning(UNIT(s), "Service has RuntimeRandomizedExtraSec= setting, but no RuntimeMaxSec=. Ignoring.");

        if (s->exit_type == SERVICE_EXIT_CGROUP && cg_unified() < CGROUP_UNIFIED_SYSTEMD)
                log_unit_warning(UNIT(s), "Service has ExitType=cgroup set, but we are running with legacy cgroups v1, which might not work correctly. Continuing.");

        if (s->restart_max_delay_usec == USEC_INFINITY && s->restart_steps > 0)
                log_unit_warning(UNIT(s), "Service has RestartSteps= but no RestartMaxDelaySec= setting. Ignoring.");

        if (s->restart_max_delay_usec != USEC_INFINITY && s->restart_steps == 0)
                log_unit_warning(UNIT(s), "Service has RestartMaxDelaySec= but no RestartSteps= setting. Ignoring.");

        if (s->restart_max_delay_usec < s->restart_usec) {
                log_unit_warning(UNIT(s), "RestartMaxDelaySec= has a value smaller than RestartSec=, resetting RestartSec= to RestartMaxDelaySec=.");
                s->restart_usec = s->restart_max_delay_usec;
        }

        return 0;
}

static int service_add_default_dependencies(Service *s) {
        int r;

        assert(s);

        if (!UNIT(s)->default_dependencies)
                return 0;

        /* Add a number of automatic dependencies useful for the
         * majority of services. */

        if (MANAGER_IS_SYSTEM(UNIT(s)->manager)) {
                /* First, pull in the really early boot stuff, and
                 * require it, so that we fail if we can't acquire
                 * it. */

                r = unit_add_two_dependencies_by_name(UNIT(s), UNIT_AFTER, UNIT_REQUIRES, SPECIAL_SYSINIT_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
                if (r < 0)
                        return r;
        } else {

                /* In the --user instance there's no sysinit.target,
                 * in that case require basic.target instead. */

                r = unit_add_dependency_by_name(UNIT(s), UNIT_REQUIRES, SPECIAL_BASIC_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
                if (r < 0)
                        return r;
        }

        /* Second, if the rest of the base system is in the same
         * transaction, order us after it, but do not pull it in or
         * even require it. */
        r = unit_add_dependency_by_name(UNIT(s), UNIT_AFTER, SPECIAL_BASIC_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
        if (r < 0)
                return r;

        /* Third, add us in for normal shutdown. */
        return unit_add_two_dependencies_by_name(UNIT(s), UNIT_BEFORE, UNIT_CONFLICTS, SPECIAL_SHUTDOWN_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
}

static void service_fix_stdio(Service *s) {
        assert(s);

        /* Note that EXEC_INPUT_NULL and EXEC_OUTPUT_INHERIT play a special role here: they are both the
         * default value that is subject to automatic overriding triggered by other settings and an explicit
         * choice the user can make. We don't distinguish between these cases currently. */

        if (s->exec_context.std_input == EXEC_INPUT_NULL &&
            s->exec_context.stdin_data_size > 0)
                s->exec_context.std_input = EXEC_INPUT_DATA;

        if (IN_SET(s->exec_context.std_input,
                    EXEC_INPUT_TTY,
                    EXEC_INPUT_TTY_FORCE,
                    EXEC_INPUT_TTY_FAIL,
                    EXEC_INPUT_SOCKET,
                    EXEC_INPUT_NAMED_FD))
                return;

        /* We assume these listed inputs refer to bidirectional streams, and hence duplicating them from
         * stdin to stdout/stderr makes sense and hence leaving EXEC_OUTPUT_INHERIT in place makes sense,
         * too. Outputs such as regular files or sealed data memfds otoh don't really make sense to be
         * duplicated for both input and output at the same time (since they then would cause a feedback
         * loop), hence override EXEC_OUTPUT_INHERIT with the default stderr/stdout setting.  */

        if (s->exec_context.std_error == EXEC_OUTPUT_INHERIT &&
            s->exec_context.std_output == EXEC_OUTPUT_INHERIT)
                s->exec_context.std_error = UNIT(s)->manager->defaults.std_error;

        if (s->exec_context.std_output == EXEC_OUTPUT_INHERIT)
                s->exec_context.std_output = UNIT(s)->manager->defaults.std_output;
}

static int service_setup_bus_name(Service *s) {
        int r;

        assert(s);

        /* If s->bus_name is not set, then the unit will be refused by service_verify() later. */
        if (!s->bus_name)
                return 0;

        if (s->type == SERVICE_DBUS) {
                r = unit_add_dependency_by_name(UNIT(s), UNIT_REQUIRES, SPECIAL_DBUS_SOCKET, true, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return log_unit_error_errno(UNIT(s), r, "Failed to add dependency on " SPECIAL_DBUS_SOCKET ": %m");

                /* We always want to be ordered against dbus.socket if both are in the transaction. */
                r = unit_add_dependency_by_name(UNIT(s), UNIT_AFTER, SPECIAL_DBUS_SOCKET, true, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return log_unit_error_errno(UNIT(s), r, "Failed to add dependency on " SPECIAL_DBUS_SOCKET ": %m");
        }

        r = unit_watch_bus_name(UNIT(s), s->bus_name);
        if (r == -EEXIST)
                return log_unit_error_errno(UNIT(s), r, "Two services allocated for the same bus name %s, refusing operation.", s->bus_name);
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r, "Cannot watch bus name %s: %m", s->bus_name);

        return 0;
}

static int service_add_extras(Service *s) {
        int r;

        assert(s);

        if (s->type == _SERVICE_TYPE_INVALID) {
                /* Figure out a type automatically */
                if (s->bus_name)
                        s->type = SERVICE_DBUS;
                else if (s->exec_command[SERVICE_EXEC_START])
                        s->type = SERVICE_SIMPLE;
                else
                        s->type = SERVICE_ONESHOT;
        }

        /* Oneshot services have disabled start timeout by default */
        if (s->type == SERVICE_ONESHOT && !s->start_timeout_defined)
                s->timeout_start_usec = USEC_INFINITY;

        service_fix_stdio(s);

        r = unit_patch_contexts(UNIT(s));
        if (r < 0)
                return r;

        r = unit_add_exec_dependencies(UNIT(s), &s->exec_context);
        if (r < 0)
                return r;

        r = unit_set_default_slice(UNIT(s));
        if (r < 0)
                return r;

        /* If the service needs the notify socket, let's enable it automatically. */
        if (s->notify_access == NOTIFY_NONE &&
            (IN_SET(s->type, SERVICE_NOTIFY, SERVICE_NOTIFY_RELOAD) || s->watchdog_usec > 0 || s->n_fd_store_max > 0))
                s->notify_access = NOTIFY_MAIN;

        /* If no OOM policy was explicitly set, then default to the configure default OOM policy. Except when
         * delegation is on, in that case it we assume the payload knows better what to do and can process
         * things in a more focused way. */
        if (s->oom_policy < 0)
                s->oom_policy = s->cgroup_context.delegate ? OOM_CONTINUE : UNIT(s)->manager->defaults.oom_policy;

        /* Let the kernel do the killing if that's requested. */
        s->cgroup_context.memory_oom_group = s->oom_policy == OOM_KILL;

        r = service_add_default_dependencies(s);
        if (r < 0)
                return r;

        r = service_setup_bus_name(s);
        if (r < 0)
                return r;

        return 0;
}

static int service_load(Unit *u) {
        Service *s = SERVICE(u);
        int r;

        r = unit_load_fragment_and_dropin(u, true);
        if (r < 0)
                return r;

        if (u->load_state != UNIT_LOADED)
                return 0;

        /* This is a new unit? Then let's add in some extras */
        r = service_add_extras(s);
        if (r < 0)
                return r;

        return service_verify(s);
}

static void service_dump_fdstore(Service *s, FILE *f, const char *prefix) {
        assert(s);
        assert(f);
        assert(prefix);

        LIST_FOREACH(fd_store, i, s->fd_store) {
                _cleanup_free_ char *path = NULL;
                struct stat st;
                int flags;

                if (fstat(i->fd, &st) < 0) {
                        log_debug_errno(errno, "Failed to stat fdstore entry: %m");
                        continue;
                }

                flags = fcntl(i->fd, F_GETFL);
                if (flags < 0) {
                        log_debug_errno(errno, "Failed to get fdstore entry flags: %m");
                        continue;
                }

                (void) fd_get_path(i->fd, &path);

                fprintf(f,
                        "%s%s '%s' (type=%s; dev=" DEVNUM_FORMAT_STR "; inode=%" PRIu64 "; rdev=" DEVNUM_FORMAT_STR "; path=%s; access=%s)\n",
                        prefix, i == s->fd_store ? "File Descriptor Store Entry:" : "                            ",
                        i->fdname,
                        inode_type_to_string(st.st_mode),
                        DEVNUM_FORMAT_VAL(st.st_dev),
                        (uint64_t) st.st_ino,
                        DEVNUM_FORMAT_VAL(st.st_rdev),
                        strna(path),
                        accmode_to_string(flags));
        }
}

static void service_dump(Unit *u, FILE *f, const char *prefix) {
        Service *s = SERVICE(u);
        const char *prefix2;

        assert(s);

        prefix = strempty(prefix);
        prefix2 = strjoina(prefix, "\t");

        fprintf(f,
                "%sService State: %s\n"
                "%sResult: %s\n"
                "%sReload Result: %s\n"
                "%sClean Result: %s\n"
                "%sPermissionsStartOnly: %s\n"
                "%sRootDirectoryStartOnly: %s\n"
                "%sRemainAfterExit: %s\n"
                "%sGuessMainPID: %s\n"
                "%sType: %s\n"
                "%sRestart: %s\n"
                "%sNotifyAccess: %s\n"
                "%sNotifyState: %s\n"
                "%sOOMPolicy: %s\n"
                "%sReloadSignal: %s\n",
                prefix, service_state_to_string(s->state),
                prefix, service_result_to_string(s->result),
                prefix, service_result_to_string(s->reload_result),
                prefix, service_result_to_string(s->clean_result),
                prefix, yes_no(s->permissions_start_only),
                prefix, yes_no(s->root_directory_start_only),
                prefix, yes_no(s->remain_after_exit),
                prefix, yes_no(s->guess_main_pid),
                prefix, service_type_to_string(s->type),
                prefix, service_restart_to_string(s->restart),
                prefix, notify_access_to_string(service_get_notify_access(s)),
                prefix, notify_state_to_string(s->notify_state),
                prefix, oom_policy_to_string(s->oom_policy),
                prefix, signal_to_string(s->reload_signal));

        if (pidref_is_set(&s->control_pid))
                fprintf(f,
                        "%sControl PID: "PID_FMT"\n",
                        prefix, s->control_pid.pid);

        if (pidref_is_set(&s->main_pid))
                fprintf(f,
                        "%sMain PID: "PID_FMT"\n"
                        "%sMain PID Known: %s\n"
                        "%sMain PID Alien: %s\n",
                        prefix, s->main_pid.pid,
                        prefix, yes_no(s->main_pid_known),
                        prefix, yes_no(s->main_pid_alien));

        if (s->pid_file)
                fprintf(f,
                        "%sPIDFile: %s\n",
                        prefix, s->pid_file);

        if (s->bus_name)
                fprintf(f,
                        "%sBusName: %s\n"
                        "%sBus Name Good: %s\n",
                        prefix, s->bus_name,
                        prefix, yes_no(s->bus_name_good));

        if (UNIT_ISSET(s->accept_socket))
                fprintf(f,
                        "%sAccept Socket: %s\n",
                        prefix, UNIT_DEREF(s->accept_socket)->id);

        fprintf(f,
                "%sRestartSec: %s\n"
                "%sRestartSteps: %u\n"
                "%sRestartMaxDelaySec: %s\n"
                "%sTimeoutStartSec: %s\n"
                "%sTimeoutStopSec: %s\n"
                "%sTimeoutStartFailureMode: %s\n"
                "%sTimeoutStopFailureMode: %s\n",
                prefix, FORMAT_TIMESPAN(s->restart_usec, USEC_PER_SEC),
                prefix, s->restart_steps,
                prefix, FORMAT_TIMESPAN(s->restart_max_delay_usec, USEC_PER_SEC),
                prefix, FORMAT_TIMESPAN(s->timeout_start_usec, USEC_PER_SEC),
                prefix, FORMAT_TIMESPAN(s->timeout_stop_usec, USEC_PER_SEC),
                prefix, service_timeout_failure_mode_to_string(s->timeout_start_failure_mode),
                prefix, service_timeout_failure_mode_to_string(s->timeout_stop_failure_mode));

        if (s->timeout_abort_set)
                fprintf(f,
                        "%sTimeoutAbortSec: %s\n",
                        prefix, FORMAT_TIMESPAN(s->timeout_abort_usec, USEC_PER_SEC));

        fprintf(f,
                "%sRuntimeMaxSec: %s\n"
                "%sRuntimeRandomizedExtraSec: %s\n"
                "%sWatchdogSec: %s\n",
                prefix, FORMAT_TIMESPAN(s->runtime_max_usec, USEC_PER_SEC),
                prefix, FORMAT_TIMESPAN(s->runtime_rand_extra_usec, USEC_PER_SEC),
                prefix, FORMAT_TIMESPAN(s->watchdog_usec, USEC_PER_SEC));

        kill_context_dump(&s->kill_context, f, prefix);
        exec_context_dump(&s->exec_context, f, prefix);

        for (ServiceExecCommand c = 0; c < _SERVICE_EXEC_COMMAND_MAX; c++) {
                if (!s->exec_command[c])
                        continue;

                fprintf(f, "%s-> %s:\n",
                        prefix, service_exec_command_to_string(c));

                exec_command_dump_list(s->exec_command[c], f, prefix2);
        }

        if (s->status_text)
                fprintf(f, "%sStatus Text: %s\n",
                        prefix, s->status_text);

        if (s->n_fd_store_max > 0)
                fprintf(f,
                        "%sFile Descriptor Store Max: %u\n"
                        "%sFile Descriptor Store Pin: %s\n"
                        "%sFile Descriptor Store Current: %zu\n",
                        prefix, s->n_fd_store_max,
                        prefix, exec_preserve_mode_to_string(s->fd_store_preserve_mode),
                        prefix, s->n_fd_store);

        service_dump_fdstore(s, f, prefix);

        if (s->open_files)
                LIST_FOREACH(open_files, of, s->open_files) {
                        _cleanup_free_ char *ofs = NULL;
                        int r;

                        r = open_file_to_string(of, &ofs);
                        if (r < 0) {
                                log_debug_errno(r,
                                                "Failed to convert OpenFile= setting to string, ignoring: %m");
                                continue;
                        }

                        fprintf(f, "%sOpen File: %s\n", prefix, ofs);
                }

        cgroup_context_dump(UNIT(s), f, prefix);
}

static int service_is_suitable_main_pid(Service *s, PidRef *pid, int prio) {
        Unit *owner;
        int r;

        assert(s);
        assert(pidref_is_set(pid));

        /* Checks whether the specified PID is suitable as main PID for this service. returns negative if not, 0 if the
         * PID is questionnable but should be accepted if the source of configuration is trusted. > 0 if the PID is
         * good */

        if (pidref_is_self(pid) || pid->pid == 1)
                return log_unit_full_errno(UNIT(s), prio, SYNTHETIC_ERRNO(EPERM), "New main PID "PID_FMT" is the manager, refusing.", pid->pid);

        if (pidref_equal(pid, &s->control_pid))
                return log_unit_full_errno(UNIT(s), prio, SYNTHETIC_ERRNO(EPERM), "New main PID "PID_FMT" is the control process, refusing.", pid->pid);

        r = pidref_is_alive(pid);
        if (r < 0)
                return log_unit_full_errno(UNIT(s), prio, r, "Failed to check if main PID "PID_FMT" exists or is a zombie: %m", pid->pid);
        if (r == 0)
                return log_unit_full_errno(UNIT(s), prio, SYNTHETIC_ERRNO(ESRCH), "New main PID "PID_FMT" does not exist or is a zombie.", pid->pid);

        owner = manager_get_unit_by_pidref(UNIT(s)->manager, pid);
        if (owner == UNIT(s)) {
                log_unit_debug(UNIT(s), "New main PID "PID_FMT" belongs to service, we are happy.", pid->pid);
                return 1; /* Yay, it's definitely a good PID */
        }

        return 0; /* Hmm it's a suspicious PID, let's accept it if configuration source is trusted */
}

static int service_load_pid_file(Service *s, bool may_warn) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        bool questionable_pid_file = false;
        _cleanup_free_ char *k = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r, prio;

        assert(s);

        if (!s->pid_file)
                return -ENOENT;

        prio = may_warn ? LOG_INFO : LOG_DEBUG;

        r = chase(s->pid_file, NULL, CHASE_SAFE, NULL, &fd);
        if (r == -ENOLINK) {
                log_unit_debug_errno(UNIT(s), r,
                                     "Potentially unsafe symlink chain, will now retry with relaxed checks: %s", s->pid_file);

                questionable_pid_file = true;

                r = chase(s->pid_file, NULL, 0, NULL, &fd);
        }
        if (r < 0)
                return log_unit_full_errno(UNIT(s), prio, r,
                                           "Can't open PID file %s (yet?) after %s: %m", s->pid_file, service_state_to_string(s->state));

        /* Let's read the PID file now that we chased it down. But we need to convert the O_PATH fd
         * chase() returned us into a proper fd first. */
        r = read_one_line_file(FORMAT_PROC_FD_PATH(fd), &k);
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r,
                                            "Can't convert PID files %s O_PATH file descriptor to proper file descriptor: %m",
                                            s->pid_file);

        r = pidref_set_pidstr(&pidref, k);
        if (r < 0)
                return log_unit_full_errno(UNIT(s), prio, r, "Failed to parse PID from file %s: %m", s->pid_file);

        if (s->main_pid_known && pidref_equal(&pidref, &s->main_pid))
                return 0;

        r = service_is_suitable_main_pid(s, &pidref, prio);
        if (r < 0)
                return r;
        if (r == 0) {
                struct stat st;

                if (questionable_pid_file)
                        return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(EPERM),
                                                    "Refusing to accept PID outside of service control group, acquired through unsafe symlink chain: %s", s->pid_file);

                /* Hmm, it's not clear if the new main PID is safe. Let's allow this if the PID file is owned by root */

                if (fstat(fd, &st) < 0)
                        return log_unit_error_errno(UNIT(s), errno, "Failed to fstat() PID file O_PATH fd: %m");

                if (st.st_uid != 0)
                        return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(EPERM),
                                                    "New main PID "PID_FMT" does not belong to service, and PID file is not owned by root. Refusing.", pidref.pid);

                log_unit_debug(UNIT(s), "New main PID "PID_FMT" does not belong to service, but we'll accept it since PID file is owned by root.", pidref.pid);
        }

        if (s->main_pid_known) {
                log_unit_debug(UNIT(s), "Main PID changing: "PID_FMT" -> "PID_FMT, s->main_pid.pid, pidref.pid);

                service_unwatch_main_pid(s);
                s->main_pid_known = false;
        } else
                log_unit_debug(UNIT(s), "Main PID loaded: "PID_FMT, pidref.pid);

        r = service_set_main_pidref(s, &pidref);
        if (r < 0)
                return r;

        r = unit_watch_pidref(UNIT(s), &s->main_pid, /* exclusive= */ false);
        if (r < 0) /* FIXME: we need to do something here */
                return log_unit_warning_errno(UNIT(s), r, "Failed to watch PID "PID_FMT" for service: %m", s->main_pid.pid);

        return 1;
}

static void service_search_main_pid(Service *s) {
        _cleanup_(pidref_done) PidRef pid = PIDREF_NULL;
        int r;

        assert(s);

        /* If we know it anyway, don't ever fall back to unreliable heuristics */
        if (s->main_pid_known)
                return;

        if (!s->guess_main_pid)
                return;

        assert(!pidref_is_set(&s->main_pid));

        if (unit_search_main_pid(UNIT(s), &pid) < 0)
                return;

        log_unit_debug(UNIT(s), "Main PID guessed: "PID_FMT, pid.pid);
        if (service_set_main_pidref(s, &pid) < 0)
                return;

        r = unit_watch_pidref(UNIT(s), &s->main_pid, /* exclusive= */ false);
        if (r < 0)
                /* FIXME: we need to do something here */
                log_unit_warning_errno(UNIT(s), r, "Failed to watch PID "PID_FMT" from: %m", s->main_pid.pid);
}

static void service_set_state(Service *s, ServiceState state) {
        ServiceState old_state;
        const UnitActiveState *table;

        assert(s);

        if (s->state != state)
                bus_unit_send_pending_change_signal(UNIT(s), false);

        table = s->type == SERVICE_IDLE ? state_translation_table_idle : state_translation_table;

        old_state = s->state;
        s->state = state;

        service_unwatch_pid_file(s);

        if (!IN_SET(state,
                    SERVICE_CONDITION, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST,
                    SERVICE_RUNNING,
                    SERVICE_RELOAD, SERVICE_RELOAD_SIGNAL, SERVICE_RELOAD_NOTIFY,
                    SERVICE_STOP, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                    SERVICE_FINAL_WATCHDOG, SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL,
                    SERVICE_AUTO_RESTART,
                    SERVICE_CLEANING))
                s->timer_event_source = sd_event_source_disable_unref(s->timer_event_source);

        if (!IN_SET(state,
                    SERVICE_START, SERVICE_START_POST,
                    SERVICE_RUNNING,
                    SERVICE_RELOAD, SERVICE_RELOAD_SIGNAL, SERVICE_RELOAD_NOTIFY,
                    SERVICE_STOP, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                    SERVICE_FINAL_WATCHDOG, SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL)) {
                service_unwatch_main_pid(s);
                s->main_command = NULL;
        }

        if (!IN_SET(state,
                    SERVICE_CONDITION, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST,
                    SERVICE_RELOAD, SERVICE_RELOAD_SIGNAL, SERVICE_RELOAD_NOTIFY,
                    SERVICE_STOP, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                    SERVICE_FINAL_WATCHDOG, SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL,
                    SERVICE_CLEANING)) {
                service_unwatch_control_pid(s);
                s->control_command = NULL;
                s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;
        }

        if (IN_SET(state,
                   SERVICE_DEAD, SERVICE_FAILED,
                   SERVICE_DEAD_BEFORE_AUTO_RESTART, SERVICE_FAILED_BEFORE_AUTO_RESTART, SERVICE_AUTO_RESTART, SERVICE_AUTO_RESTART_QUEUED,
                   SERVICE_DEAD_RESOURCES_PINNED)) {
                unit_unwatch_all_pids(UNIT(s));
                unit_dequeue_rewatch_pids(UNIT(s));
        }

        if (state != SERVICE_START)
                s->exec_fd_event_source = sd_event_source_disable_unref(s->exec_fd_event_source);

        if (!IN_SET(state, SERVICE_START_POST, SERVICE_RUNNING, SERVICE_RELOAD, SERVICE_RELOAD_SIGNAL, SERVICE_RELOAD_NOTIFY))
                service_stop_watchdog(s);

        /* For the inactive states unit_notify() will trim the cgroup,
         * but for exit we have to do that ourselves... */
        if (state == SERVICE_EXITED && !MANAGER_IS_RELOADING(UNIT(s)->manager))
                unit_prune_cgroup(UNIT(s));

        if (old_state != state)
                log_unit_debug(UNIT(s), "Changed %s -> %s", service_state_to_string(old_state), service_state_to_string(state));

        unit_notify(UNIT(s), table[old_state], table[state], s->reload_result == SERVICE_SUCCESS);
}

static usec_t service_coldplug_timeout(Service *s) {
        assert(s);

        switch (s->deserialized_state) {

        case SERVICE_CONDITION:
        case SERVICE_START_PRE:
        case SERVICE_START:
        case SERVICE_START_POST:
        case SERVICE_RELOAD:
        case SERVICE_RELOAD_SIGNAL:
        case SERVICE_RELOAD_NOTIFY:
                return usec_add(UNIT(s)->state_change_timestamp.monotonic, s->timeout_start_usec);

        case SERVICE_RUNNING:
                return service_running_timeout(s);

        case SERVICE_STOP:
        case SERVICE_STOP_SIGTERM:
        case SERVICE_STOP_SIGKILL:
        case SERVICE_STOP_POST:
        case SERVICE_FINAL_SIGTERM:
        case SERVICE_FINAL_SIGKILL:
                return usec_add(UNIT(s)->state_change_timestamp.monotonic, s->timeout_stop_usec);

        case SERVICE_STOP_WATCHDOG:
        case SERVICE_FINAL_WATCHDOG:
                return usec_add(UNIT(s)->state_change_timestamp.monotonic, service_timeout_abort_usec(s));

        case SERVICE_AUTO_RESTART:
                return usec_add(UNIT(s)->inactive_enter_timestamp.monotonic, service_restart_usec_next(s));

        case SERVICE_CLEANING:
                return usec_add(UNIT(s)->state_change_timestamp.monotonic, s->exec_context.timeout_clean_usec);

        default:
                return USEC_INFINITY;
        }
}

static int service_coldplug(Unit *u) {
        Service *s = SERVICE(u);
        int r;

        assert(s);
        assert(s->state == SERVICE_DEAD);

        if (s->deserialized_state == s->state)
                return 0;

        r = service_arm_timer(s, /* relative= */ false, service_coldplug_timeout(s));
        if (r < 0)
                return r;

        if (pidref_is_set(&s->main_pid) &&
            pidref_is_unwaited(&s->main_pid) > 0 &&
            (IN_SET(s->deserialized_state,
                    SERVICE_START, SERVICE_START_POST,
                    SERVICE_RUNNING,
                    SERVICE_RELOAD, SERVICE_RELOAD_SIGNAL, SERVICE_RELOAD_NOTIFY,
                    SERVICE_STOP, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                    SERVICE_FINAL_WATCHDOG, SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL))) {
                r = unit_watch_pidref(UNIT(s), &s->main_pid, /* exclusive= */ false);
                if (r < 0)
                        return r;
        }

        if (pidref_is_set(&s->control_pid) &&
            pidref_is_unwaited(&s->control_pid) > 0 &&
            IN_SET(s->deserialized_state,
                   SERVICE_CONDITION, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST,
                   SERVICE_RELOAD, SERVICE_RELOAD_SIGNAL, SERVICE_RELOAD_NOTIFY,
                   SERVICE_STOP, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                   SERVICE_FINAL_WATCHDOG, SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL,
                   SERVICE_CLEANING)) {
                r = unit_watch_pidref(UNIT(s), &s->control_pid, /* exclusive= */ false);
                if (r < 0)
                        return r;
        }

        if (!IN_SET(s->deserialized_state,
                    SERVICE_DEAD, SERVICE_FAILED,
                    SERVICE_DEAD_BEFORE_AUTO_RESTART, SERVICE_FAILED_BEFORE_AUTO_RESTART, SERVICE_AUTO_RESTART, SERVICE_AUTO_RESTART_QUEUED,
                    SERVICE_CLEANING,
                    SERVICE_DEAD_RESOURCES_PINNED)) {
                (void) unit_enqueue_rewatch_pids(u);
                (void) unit_setup_exec_runtime(u);
        }

        if (IN_SET(s->deserialized_state, SERVICE_START_POST, SERVICE_RUNNING, SERVICE_RELOAD, SERVICE_RELOAD_SIGNAL, SERVICE_RELOAD_NOTIFY))
                service_start_watchdog(s);

        if (UNIT_ISSET(s->accept_socket)) {
                Socket* socket = SOCKET(UNIT_DEREF(s->accept_socket));

                if (socket->max_connections_per_source > 0) {
                        SocketPeer *peer;

                        /* Make a best-effort attempt at bumping the connection count */
                        if (socket_acquire_peer(socket, s->socket_fd, &peer) > 0) {
                                socket_peer_unref(s->socket_peer);
                                s->socket_peer = peer;
                        }
                }
        }

        service_set_state(s, s->deserialized_state);
        return 0;
}

static int service_collect_fds(
                Service *s,
                int **fds,
                char ***fd_names,
                size_t *n_socket_fds,
                size_t *n_storage_fds) {

        _cleanup_strv_free_ char **rfd_names = NULL;
        _cleanup_free_ int *rfds = NULL;
        size_t rn_socket_fds = 0, rn_storage_fds = 0;
        int r;

        assert(s);
        assert(fds);
        assert(fd_names);
        assert(n_socket_fds);
        assert(n_storage_fds);

        if (s->socket_fd >= 0) {

                /* Pass the per-connection socket */

                rfds = newdup(int, &s->socket_fd, 1);
                if (!rfds)
                        return -ENOMEM;

                rfd_names = strv_new("connection");
                if (!rfd_names)
                        return -ENOMEM;

                rn_socket_fds = 1;
        } else {
                Unit *u;

                /* Pass all our configured sockets for singleton services */

                UNIT_FOREACH_DEPENDENCY(u, UNIT(s), UNIT_ATOM_TRIGGERED_BY) {
                        _cleanup_free_ int *cfds = NULL;
                        Socket *sock;
                        int cn_fds;

                        if (u->type != UNIT_SOCKET)
                                continue;

                        sock = SOCKET(u);

                        cn_fds = socket_collect_fds(sock, &cfds);
                        if (cn_fds < 0)
                                return cn_fds;

                        if (cn_fds <= 0)
                                continue;

                        if (!rfds) {
                                rfds = TAKE_PTR(cfds);
                                rn_socket_fds = cn_fds;
                        } else {
                                int *t;

                                t = reallocarray(rfds, rn_socket_fds + cn_fds, sizeof(int));
                                if (!t)
                                        return -ENOMEM;

                                memcpy(t + rn_socket_fds, cfds, cn_fds * sizeof(int));

                                rfds = t;
                                rn_socket_fds += cn_fds;
                        }

                        r = strv_extend_n(&rfd_names, socket_fdname(sock), cn_fds);
                        if (r < 0)
                                return r;
                }
        }

        if (s->n_fd_store > 0) {
                size_t n_fds;
                char **nl;
                int *t;

                t = reallocarray(rfds, rn_socket_fds + s->n_fd_store, sizeof(int));
                if (!t)
                        return -ENOMEM;

                rfds = t;

                nl = reallocarray(rfd_names, rn_socket_fds + s->n_fd_store + 1, sizeof(char *));
                if (!nl)
                        return -ENOMEM;

                rfd_names = nl;
                n_fds = rn_socket_fds;

                LIST_FOREACH(fd_store, fs, s->fd_store) {
                        rfds[n_fds] = fs->fd;
                        rfd_names[n_fds] = strdup(strempty(fs->fdname));
                        if (!rfd_names[n_fds])
                                return -ENOMEM;

                        rn_storage_fds++;
                        n_fds++;
                }

                rfd_names[n_fds] = NULL;
        }

        *fds = TAKE_PTR(rfds);
        *fd_names = TAKE_PTR(rfd_names);
        *n_socket_fds = rn_socket_fds;
        *n_storage_fds = rn_storage_fds;

        return 0;
}

static int service_allocate_exec_fd_event_source(
                Service *s,
                int fd,
                sd_event_source **ret_event_source) {

        _cleanup_(sd_event_source_unrefp) sd_event_source *source = NULL;
        int r;

        assert(s);
        assert(fd >= 0);
        assert(ret_event_source);

        r = sd_event_add_io(UNIT(s)->manager->event, &source, fd, 0, service_dispatch_exec_io, s);
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r, "Failed to allocate exec_fd event source: %m");

        /* This is a bit lower priority than SIGCHLD, as that carries a lot more interesting failure information */

        r = sd_event_source_set_priority(source, SD_EVENT_PRIORITY_NORMAL-3);
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r, "Failed to adjust priority of exec_fd event source: %m");

        (void) sd_event_source_set_description(source, "service exec_fd");

        r = sd_event_source_set_io_fd_own(source, true);
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r, "Failed to pass ownership of fd to event source: %m");

        *ret_event_source = TAKE_PTR(source);
        return 0;
}

static int service_allocate_exec_fd(
                Service *s,
                sd_event_source **ret_event_source,
                int *ret_exec_fd) {

        _cleanup_close_pair_ int p[] = EBADF_PAIR;
        int r;

        assert(s);
        assert(ret_event_source);
        assert(ret_exec_fd);

        if (pipe2(p, O_CLOEXEC|O_NONBLOCK) < 0)
                return log_unit_error_errno(UNIT(s), errno, "Failed to allocate exec_fd pipe: %m");

        r = service_allocate_exec_fd_event_source(s, p[0], ret_event_source);
        if (r < 0)
                return r;

        TAKE_FD(p[0]);
        *ret_exec_fd = TAKE_FD(p[1]);

        return 0;
}

static bool service_exec_needs_notify_socket(Service *s, ExecFlags flags) {
        assert(s);

        /* Notifications are accepted depending on the process and
         * the access setting of the service:
         *     process: \ access:  NONE  MAIN  EXEC   ALL
         *     main                  no   yes   yes   yes
         *     control               no    no   yes   yes
         *     other (forked)        no    no    no   yes */

        if (flags & EXEC_IS_CONTROL)
                /* A control process */
                return IN_SET(service_get_notify_access(s), NOTIFY_EXEC, NOTIFY_ALL);

        /* We only spawn main processes and control processes, so any
         * process that is not a control process is a main process */
        return service_get_notify_access(s) != NOTIFY_NONE;
}

static Service *service_get_triggering_service(Service *s) {
        Unit *candidate = NULL, *other;

        assert(s);

        /* Return the service which triggered service 's', this means dependency
         * types which include the UNIT_ATOM_ON_{FAILURE,SUCCESS}_OF atoms.
         *
         * N.B. if there are multiple services which could trigger 's' via OnFailure=
         * or OnSuccess= then we return NULL. This is since we don't know from which
         * one to propagate the exit status. */

        UNIT_FOREACH_DEPENDENCY(other, UNIT(s), UNIT_ATOM_ON_FAILURE_OF) {
                if (candidate)
                        goto have_other;
                candidate = other;
        }

        UNIT_FOREACH_DEPENDENCY(other, UNIT(s), UNIT_ATOM_ON_SUCCESS_OF) {
                if (candidate)
                        goto have_other;
                candidate = other;
        }

        return SERVICE(candidate);

 have_other:
        log_unit_warning(UNIT(s), "multiple trigger source candidates for exit status propagation (%s, %s), skipping.",
                         candidate->id, other->id);
        return NULL;
}

static int service_spawn_internal(
                const char *caller,
                Service *s,
                ExecCommand *c,
                usec_t timeout,
                ExecFlags flags,
                PidRef *ret_pid) {

        _cleanup_(exec_params_shallow_clear) ExecParameters exec_params = EXEC_PARAMETERS_INIT(flags);
        _cleanup_(sd_event_source_unrefp) sd_event_source *exec_fd_source = NULL;
        _cleanup_strv_free_ char **final_env = NULL, **our_env = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        size_t n_env = 0;
        pid_t pid;
        int r;

        assert(caller);
        assert(s);
        assert(c);
        assert(ret_pid);

        log_unit_debug(UNIT(s), "Will spawn child (%s): %s", caller, c->path);

        r = unit_prepare_exec(UNIT(s)); /* This realizes the cgroup, among other things */
        if (r < 0)
                return r;

        assert(!s->exec_fd_event_source);

        if (flags & EXEC_IS_CONTROL) {
                /* If this is a control process, mask the permissions/chroot application if this is requested. */
                if (s->permissions_start_only)
                        exec_params.flags &= ~EXEC_APPLY_SANDBOXING;
                if (s->root_directory_start_only)
                        exec_params.flags &= ~EXEC_APPLY_CHROOT;
        }

        if ((flags & EXEC_PASS_FDS) ||
            s->exec_context.std_input == EXEC_INPUT_SOCKET ||
            s->exec_context.std_output == EXEC_OUTPUT_SOCKET ||
            s->exec_context.std_error == EXEC_OUTPUT_SOCKET) {

                r = service_collect_fds(s,
                                        &exec_params.fds,
                                        &exec_params.fd_names,
                                        &exec_params.n_socket_fds,
                                        &exec_params.n_storage_fds);
                if (r < 0)
                        return r;

                exec_params.open_files = s->open_files;

                log_unit_debug(UNIT(s), "Passing %zu fds to service", exec_params.n_socket_fds + exec_params.n_storage_fds);
        }

        if (!FLAGS_SET(flags, EXEC_IS_CONTROL) && s->type == SERVICE_EXEC) {
                r = service_allocate_exec_fd(s, &exec_fd_source, &exec_params.exec_fd);
                if (r < 0)
                        return r;
        }

        r = service_arm_timer(s, /* relative= */ true, timeout);
        if (r < 0)
                return r;

        our_env = new0(char*, 13);
        if (!our_env)
                return -ENOMEM;

        if (service_exec_needs_notify_socket(s, flags)) {
                if (asprintf(our_env + n_env++, "NOTIFY_SOCKET=%s", UNIT(s)->manager->notify_socket) < 0)
                        return -ENOMEM;

                exec_params.notify_socket = UNIT(s)->manager->notify_socket;

                if (s->n_fd_store_max > 0)
                        if (asprintf(our_env + n_env++, "FDSTORE=%u", s->n_fd_store_max) < 0)
                                return -ENOMEM;
        }

        if (pidref_is_set(&s->main_pid))
                if (asprintf(our_env + n_env++, "MAINPID="PID_FMT, s->main_pid.pid) < 0)
                        return -ENOMEM;

        if (MANAGER_IS_USER(UNIT(s)->manager))
                if (asprintf(our_env + n_env++, "MANAGERPID="PID_FMT, getpid_cached()) < 0)
                        return -ENOMEM;

        if (s->pid_file)
                if (asprintf(our_env + n_env++, "PIDFILE=%s", s->pid_file) < 0)
                        return -ENOMEM;

        if (s->socket_fd >= 0) {
                union sockaddr_union sa;
                socklen_t salen = sizeof(sa);

                /* If this is a per-connection service instance, let's set $REMOTE_ADDR and $REMOTE_PORT to something
                 * useful. Note that we do this only when we are still connected at this point in time, which we might
                 * very well not be. Hence we ignore all errors when retrieving peer information (as that might result
                 * in ENOTCONN), and just use whate we can use. */

                if (getpeername(s->socket_fd, &sa.sa, &salen) >= 0 &&
                    IN_SET(sa.sa.sa_family, AF_INET, AF_INET6, AF_VSOCK)) {
                        _cleanup_free_ char *addr = NULL;
                        char *t;
                        unsigned port;

                        r = sockaddr_pretty(&sa.sa, salen, true, false, &addr);
                        if (r < 0)
                                return r;

                        t = strjoin("REMOTE_ADDR=", addr);
                        if (!t)
                                return -ENOMEM;
                        our_env[n_env++] = t;

                        r = sockaddr_port(&sa.sa, &port);
                        if (r < 0)
                                return r;

                        if (asprintf(&t, "REMOTE_PORT=%u", port) < 0)
                                return -ENOMEM;
                        our_env[n_env++] = t;
                }
        }

        Service *env_source = NULL;
        const char *monitor_prefix;
        if (flags & EXEC_SETENV_RESULT) {
                env_source = s;
                monitor_prefix = "";
        } else if (flags & EXEC_SETENV_MONITOR_RESULT) {
                env_source = service_get_triggering_service(s);
                monitor_prefix = "MONITOR_";
        }

        if (env_source) {
                if (asprintf(our_env + n_env++, "%sSERVICE_RESULT=%s", monitor_prefix, service_result_to_string(env_source->result)) < 0)
                        return -ENOMEM;

                if (env_source->main_exec_status.pid > 0 &&
                    dual_timestamp_is_set(&env_source->main_exec_status.exit_timestamp)) {
                        if (asprintf(our_env + n_env++, "%sEXIT_CODE=%s", monitor_prefix, sigchld_code_to_string(env_source->main_exec_status.code)) < 0)
                                return -ENOMEM;

                        if (env_source->main_exec_status.code == CLD_EXITED)
                                r = asprintf(our_env + n_env++, "%sEXIT_STATUS=%i", monitor_prefix, env_source->main_exec_status.status);
                        else
                                r = asprintf(our_env + n_env++, "%sEXIT_STATUS=%s", monitor_prefix, signal_to_string(env_source->main_exec_status.status));

                        if (r < 0)
                                return -ENOMEM;
                }

                if (env_source != s) {
                        if (!sd_id128_is_null(UNIT(env_source)->invocation_id)) {
                                r = asprintf(our_env + n_env++, "%sINVOCATION_ID=" SD_ID128_FORMAT_STR,
                                             monitor_prefix, SD_ID128_FORMAT_VAL(UNIT(env_source)->invocation_id));
                                if (r < 0)
                                        return -ENOMEM;
                        }

                        if (asprintf(our_env + n_env++, "%sUNIT=%s", monitor_prefix, UNIT(env_source)->id) < 0)
                                return -ENOMEM;
                }
        }

        if (UNIT(s)->activation_details) {
                r = activation_details_append_env(UNIT(s)->activation_details, &our_env);
                if (r < 0)
                        return r;
                /* The number of env vars added here can vary, rather than keeping the allocation block in
                 * sync manually, these functions simply use the strv methods to append to it, so we need
                 * to update n_env when we are done in case of future usage. */
                n_env += r;
        }

        r = unit_set_exec_params(UNIT(s), &exec_params);
        if (r < 0)
                return r;

        final_env = strv_env_merge(exec_params.environment, our_env);
        if (!final_env)
                return -ENOMEM;

        /* System D-Bus needs nss-systemd disabled, so that we don't deadlock */
        SET_FLAG(exec_params.flags, EXEC_NSS_DYNAMIC_BYPASS,
                 MANAGER_IS_SYSTEM(UNIT(s)->manager) && unit_has_name(UNIT(s), SPECIAL_DBUS_SERVICE));

        strv_free_and_replace(exec_params.environment, final_env);
        exec_params.watchdog_usec = service_get_watchdog_usec(s);
        exec_params.selinux_context_net = s->socket_fd_selinux_context_net;
        if (s->type == SERVICE_IDLE)
                exec_params.idle_pipe = UNIT(s)->manager->idle_pipe;
        exec_params.stdin_fd = s->stdin_fd;
        exec_params.stdout_fd = s->stdout_fd;
        exec_params.stderr_fd = s->stderr_fd;

        r = exec_spawn(UNIT(s),
                       c,
                       &s->exec_context,
                       &exec_params,
                       s->exec_runtime,
                       &s->cgroup_context,
                       &pid);
        if (r < 0)
                return r;

        s->exec_fd_event_source = TAKE_PTR(exec_fd_source);
        s->exec_fd_hot = false;

        r = pidref_set_pid(&pidref, pid);
        if (r < 0)
                return r;

        r = unit_watch_pidref(UNIT(s), &pidref, /* exclusive= */ true);
        if (r < 0)
                return r;

        *ret_pid = TAKE_PIDREF(pidref);
        return 0;
}

static int main_pid_good(Service *s) {
        assert(s);

        /* Returns 0 if the pid is dead, > 0 if it is good, < 0 if we don't know */

        /* If we know the pid file, then let's just check if it is still valid */
        if (s->main_pid_known) {

                /* If it's an alien child let's check if it is still alive ... */
                if (s->main_pid_alien && pidref_is_set(&s->main_pid))
                        return pidref_is_alive(&s->main_pid);

                /* .. otherwise assume we'll get a SIGCHLD for it, which we really should wait for to collect
                 * exit status and code */
                return pidref_is_set(&s->main_pid);
        }

        /* We don't know the pid */
        return -EAGAIN;
}

static int control_pid_good(Service *s) {
        assert(s);

        /* Returns 0 if the control PID is dead, > 0 if it is good. We never actually return < 0 here, but in order to
         * make this function as similar as possible to main_pid_good() and cgroup_good(), we pretend that < 0 also
         * means: we can't figure it out. */

        return pidref_is_set(&s->control_pid);
}

static int cgroup_good(Service *s) {
        int r;

        assert(s);

        /* Returns 0 if the cgroup is empty or doesn't exist, > 0 if it is exists and is populated, < 0 if we can't
         * figure it out */

        if (!UNIT(s)->cgroup_path)
                return 0;

        r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, UNIT(s)->cgroup_path);
        if (r < 0)
                return r;

        return r == 0;
}

static bool service_shall_restart(Service *s, const char **reason) {
        assert(s);

        /* Don't restart after manual stops */
        if (s->forbid_restart) {
                *reason = "manual stop";
                return false;
        }

        /* Never restart if this is configured as special exception */
        if (exit_status_set_test(&s->restart_prevent_status, s->main_exec_status.code, s->main_exec_status.status)) {
                *reason = "prevented by exit status";
                return false;
        }

        /* Restart if the exit code/status are configured as restart triggers */
        if (exit_status_set_test(&s->restart_force_status,  s->main_exec_status.code, s->main_exec_status.status)) {
                *reason = "forced by exit status";
                return true;
        }

        *reason = "restart setting";
        switch (s->restart) {

        case SERVICE_RESTART_NO:
                return false;

        case SERVICE_RESTART_ALWAYS:
                return s->result != SERVICE_SKIP_CONDITION;

        case SERVICE_RESTART_ON_SUCCESS:
                return s->result == SERVICE_SUCCESS;

        case SERVICE_RESTART_ON_FAILURE:
                return !IN_SET(s->result, SERVICE_SUCCESS, SERVICE_SKIP_CONDITION);

        case SERVICE_RESTART_ON_ABNORMAL:
                return !IN_SET(s->result, SERVICE_SUCCESS, SERVICE_FAILURE_EXIT_CODE, SERVICE_SKIP_CONDITION);

        case SERVICE_RESTART_ON_WATCHDOG:
                return s->result == SERVICE_FAILURE_WATCHDOG;

        case SERVICE_RESTART_ON_ABORT:
                return IN_SET(s->result, SERVICE_FAILURE_SIGNAL, SERVICE_FAILURE_CORE_DUMP);

        default:
                assert_not_reached();
        }
}

static bool service_will_restart(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        if (IN_SET(s->state, SERVICE_DEAD_BEFORE_AUTO_RESTART, SERVICE_FAILED_BEFORE_AUTO_RESTART, SERVICE_AUTO_RESTART, SERVICE_AUTO_RESTART_QUEUED))
                return true;

        return unit_will_restart_default(u);
}

static ServiceState service_determine_dead_state(Service *s) {
        assert(s);

        return s->fd_store && s->fd_store_preserve_mode == EXEC_PRESERVE_YES ? SERVICE_DEAD_RESOURCES_PINNED : SERVICE_DEAD;
}

static void service_enter_dead(Service *s, ServiceResult f, bool allow_restart) {
        ServiceState end_state, restart_state;
        int r;

        assert(s);

        /* If there's a stop job queued before we enter the DEAD state, we shouldn't act on Restart=, in order to not
         * undo what has already been enqueued. */
        if (unit_stop_pending(UNIT(s)))
                allow_restart = false;

        if (s->result == SERVICE_SUCCESS)
                s->result = f;

        if (s->result == SERVICE_SUCCESS) {
                unit_log_success(UNIT(s));
                end_state = service_determine_dead_state(s);
                restart_state = SERVICE_DEAD_BEFORE_AUTO_RESTART;
        } else if (s->result == SERVICE_SKIP_CONDITION) {
                unit_log_skip(UNIT(s), service_result_to_string(s->result));
                end_state = service_determine_dead_state(s);
                restart_state = SERVICE_DEAD_BEFORE_AUTO_RESTART;
        } else {
                unit_log_failure(UNIT(s), service_result_to_string(s->result));
                end_state = SERVICE_FAILED;
                restart_state = SERVICE_FAILED_BEFORE_AUTO_RESTART;
        }
        unit_warn_leftover_processes(UNIT(s), unit_log_leftover_process_stop);

        if (!allow_restart)
                log_unit_debug(UNIT(s), "Service restart not allowed.");
        else {
                const char *reason;

                allow_restart = service_shall_restart(s, &reason);
                log_unit_debug(UNIT(s), "Service will %srestart (%s)",
                                        allow_restart ? "" : "not ",
                                        reason);
        }

        if (allow_restart) {
                usec_t restart_usec_next;

                /* We make two state changes here: one that maps to the high-level UNIT_INACTIVE/UNIT_FAILED
                 * state (i.e. a state indicating deactivation), and then one that that maps to the
                 * high-level UNIT_STARTING state (i.e. a state indicating activation). We do this so that
                 * external software can watch the state changes and see all service failures, even if they
                 * are only transitionary and followed by an automatic restart. We have fine-grained
                 * low-level states for this though so that software can distinguish the permanent UNIT_INACTIVE
                 * state from this transitionary UNIT_INACTIVE state by looking at the low-level states. */
                if (s->restart_mode != SERVICE_RESTART_MODE_DIRECT)
                        service_set_state(s, restart_state);

                restart_usec_next = service_restart_usec_next(s);

                r = service_arm_timer(s, /* relative= */ true, restart_usec_next);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to install restart timer: %m");
                        service_enter_dead(s, SERVICE_FAILURE_RESOURCES, /* allow_restart= */ false);
                        return;
                }

                log_unit_debug(UNIT(s), "Next restart interval calculated as: %s", FORMAT_TIMESPAN(restart_usec_next, 0));

                service_set_state(s, SERVICE_AUTO_RESTART);
        } else {
                service_set_state(s, end_state);

                /* If we shan't restart, then flush out the restart counter. But don't do that immediately, so that the
                 * user can still introspect the counter. Do so on the next start. */
                s->flush_n_restarts = true;
        }

        /* The new state is in effect, let's decrease the fd store ref counter again. Let's also re-add us to the GC
         * queue, so that the fd store is possibly gc'ed again */
        unit_add_to_gc_queue(UNIT(s));

        /* The next restart might not be a manual stop, hence reset the flag indicating manual stops */
        s->forbid_restart = false;

        /* Reset NotifyAccess override */
        s->notify_access_override = _NOTIFY_ACCESS_INVALID;

        /* We want fresh tmpdirs and ephemeral snapshots in case the service is started again immediately. */
        s->exec_runtime = exec_runtime_destroy(s->exec_runtime);

        /* Also, remove the runtime directory */
        unit_destroy_runtime_data(UNIT(s), &s->exec_context);

        /* Also get rid of the fd store, if that's configured. */
        if (s->fd_store_preserve_mode == EXEC_PRESERVE_NO)
                service_release_fd_store(s);

        /* Get rid of the IPC bits of the user */
        unit_unref_uid_gid(UNIT(s), true);

        /* Try to delete the pid file. At this point it will be
         * out-of-date, and some software might be confused by it, so
         * let's remove it. */
        if (s->pid_file)
                (void) unlink(s->pid_file);

        /* Reset TTY ownership if necessary */
        exec_context_revert_tty(&s->exec_context);
}

static void service_enter_stop_post(Service *s, ServiceResult f) {
        int r;
        assert(s);

        if (s->result == SERVICE_SUCCESS)
                s->result = f;

        service_unwatch_control_pid(s);
        (void) unit_enqueue_rewatch_pids(UNIT(s));

        s->control_command = s->exec_command[SERVICE_EXEC_STOP_POST];
        if (s->control_command) {
                s->control_command_id = SERVICE_EXEC_STOP_POST;
                pidref_done(&s->control_pid);

                r = service_spawn(s,
                                  s->control_command,
                                  s->timeout_stop_usec,
                                  EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_APPLY_TTY_STDIN|EXEC_IS_CONTROL|EXEC_SETENV_RESULT|EXEC_CONTROL_CGROUP,
                                  &s->control_pid);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to spawn 'stop-post' task: %m");
                        service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_FAILURE_RESOURCES);
                        return;
                }

                service_set_state(s, SERVICE_STOP_POST);
        } else
                service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_SUCCESS);
}

static int state_to_kill_operation(Service *s, ServiceState state) {
        switch (state) {

        case SERVICE_STOP_WATCHDOG:
        case SERVICE_FINAL_WATCHDOG:
                return KILL_WATCHDOG;

        case SERVICE_STOP_SIGTERM:
                if (unit_has_job_type(UNIT(s), JOB_RESTART))
                        return KILL_RESTART;
                _fallthrough_;

        case SERVICE_FINAL_SIGTERM:
                return KILL_TERMINATE;

        case SERVICE_STOP_SIGKILL:
        case SERVICE_FINAL_SIGKILL:
                return KILL_KILL;

        default:
                return _KILL_OPERATION_INVALID;
        }
}

static void service_enter_signal(Service *s, ServiceState state, ServiceResult f) {
        int kill_operation, r;

        assert(s);

        if (s->result == SERVICE_SUCCESS)
                s->result = f;

        /* Before sending any signal, make sure we track all members of this cgroup */
        (void) unit_watch_all_pids(UNIT(s));

        /* Also, enqueue a job that we recheck all our PIDs a bit later, given that it's likely some processes have
         * died now */
        (void) unit_enqueue_rewatch_pids(UNIT(s));

        kill_operation = state_to_kill_operation(s, state);
        r = unit_kill_context(
                        UNIT(s),
                        &s->kill_context,
                        kill_operation,
                        &s->main_pid,
                        &s->control_pid,
                        s->main_pid_alien);
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to kill processes: %m");
                goto fail;
        }

        if (r > 0) {
                r = service_arm_timer(s, /* relative= */ true,
                                      kill_operation == KILL_WATCHDOG ? service_timeout_abort_usec(s) : s->timeout_stop_usec);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to install timer: %m");
                        goto fail;
                }

                service_set_state(s, state);
        } else if (IN_SET(state, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM) && s->kill_context.send_sigkill)
                service_enter_signal(s, SERVICE_STOP_SIGKILL, SERVICE_SUCCESS);
        else if (IN_SET(state, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL))
                service_enter_stop_post(s, SERVICE_SUCCESS);
        else if (IN_SET(state, SERVICE_FINAL_WATCHDOG, SERVICE_FINAL_SIGTERM) && s->kill_context.send_sigkill)
                service_enter_signal(s, SERVICE_FINAL_SIGKILL, SERVICE_SUCCESS);
        else
                service_enter_dead(s, SERVICE_SUCCESS, /* allow_restart= */ true);

        return;

fail:
        if (IN_SET(state, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL))
                service_enter_stop_post(s, SERVICE_FAILURE_RESOURCES);
        else
                service_enter_dead(s, SERVICE_FAILURE_RESOURCES, /* allow_restart= */ true);
}

static void service_enter_stop_by_notify(Service *s) {
        int r;

        assert(s);

        (void) unit_enqueue_rewatch_pids(UNIT(s));

        r = service_arm_timer(s, /* relative= */ true, s->timeout_stop_usec);
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to install timer: %m");
                service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_RESOURCES);
                return;
        }

        /* The service told us it's stopping, so it's as if we SIGTERM'd it. */
        service_set_state(s, SERVICE_STOP_SIGTERM);
}

static void service_enter_stop(Service *s, ServiceResult f) {
        int r;

        assert(s);

        if (s->result == SERVICE_SUCCESS)
                s->result = f;

        service_unwatch_control_pid(s);
        (void) unit_enqueue_rewatch_pids(UNIT(s));

        s->control_command = s->exec_command[SERVICE_EXEC_STOP];
        if (s->control_command) {
                s->control_command_id = SERVICE_EXEC_STOP;
                pidref_done(&s->control_pid);

                r = service_spawn(s,
                                  s->control_command,
                                  s->timeout_stop_usec,
                                  EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_IS_CONTROL|EXEC_SETENV_RESULT|EXEC_CONTROL_CGROUP,
                                  &s->control_pid);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to spawn 'stop' task: %m");
                        service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_RESOURCES);
                        return;
                }

                service_set_state(s, SERVICE_STOP);
        } else
                service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_SUCCESS);
}

static bool service_good(Service *s) {
        int main_pid_ok;
        assert(s);

        if (s->type == SERVICE_DBUS && !s->bus_name_good)
                return false;

        main_pid_ok = main_pid_good(s);
        if (main_pid_ok > 0) /* It's alive */
                return true;
        if (main_pid_ok == 0 && s->exit_type == SERVICE_EXIT_MAIN) /* It's dead */
                return false;

        /* OK, we don't know anything about the main PID, maybe
         * because there is none. Let's check the control group
         * instead. */

        return cgroup_good(s) != 0;
}

static void service_enter_running(Service *s, ServiceResult f) {
        int r;

        assert(s);

        if (s->result == SERVICE_SUCCESS)
                s->result = f;

        service_unwatch_control_pid(s);

        if (s->result != SERVICE_SUCCESS)
                service_enter_signal(s, SERVICE_STOP_SIGTERM, f);
        else if (service_good(s)) {

                /* If there are any queued up sd_notify() notifications, process them now */
                if (s->notify_state == NOTIFY_RELOADING)
                        service_enter_reload_by_notify(s);
                else if (s->notify_state == NOTIFY_STOPPING)
                        service_enter_stop_by_notify(s);
                else {
                        service_set_state(s, SERVICE_RUNNING);

                        r = service_arm_timer(s, /* relative= */ false, service_running_timeout(s));
                        if (r < 0) {
                                log_unit_warning_errno(UNIT(s), r, "Failed to install timer: %m");
                                service_enter_running(s, SERVICE_FAILURE_RESOURCES);
                                return;
                        }
                }

        } else if (s->remain_after_exit)
                service_set_state(s, SERVICE_EXITED);
        else
                service_enter_stop(s, SERVICE_SUCCESS);
}

static void service_enter_start_post(Service *s) {
        int r;
        assert(s);

        service_unwatch_control_pid(s);
        service_reset_watchdog(s);

        s->control_command = s->exec_command[SERVICE_EXEC_START_POST];
        if (s->control_command) {
                s->control_command_id = SERVICE_EXEC_START_POST;
                pidref_done(&s->control_pid);

                r = service_spawn(s,
                                  s->control_command,
                                  s->timeout_start_usec,
                                  EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_IS_CONTROL|EXEC_CONTROL_CGROUP,
                                  &s->control_pid);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to spawn 'start-post' task: %m");
                        service_enter_stop(s, SERVICE_FAILURE_RESOURCES);
                        return;
                }

                service_set_state(s, SERVICE_START_POST);
        } else
                service_enter_running(s, SERVICE_SUCCESS);
}

static void service_kill_control_process(Service *s) {
        int r;

        assert(s);

        if (!pidref_is_set(&s->control_pid))
                return;

        r = pidref_kill_and_sigcont(&s->control_pid, SIGKILL);
        if (r < 0) {
                _cleanup_free_ char *comm = NULL;

                (void) pidref_get_comm(&s->control_pid, &comm);

                log_unit_debug_errno(UNIT(s), r, "Failed to kill control process " PID_FMT " (%s), ignoring: %m",
                                     s->control_pid.pid, strna(comm));
        }
}

static int service_adverse_to_leftover_processes(Service *s) {
        assert(s);

        /* KillMode=mixed and control group are used to indicate that all process should be killed off.
         * SendSIGKILL= is used for services that require a clean shutdown. These are typically database
         * service where a SigKilled process would result in a lengthy recovery and who's shutdown or startup
         * time is quite variable (so Timeout settings aren't of use).
         *
         * Here we take these two factors and refuse to start a service if there are existing processes
         * within a control group. Databases, while generally having some protection against multiple
         * instances running, lets not stress the rigor of these. Also ExecStartPre= parts of the service
         * aren't as rigoriously written to protect aganst against multiple use. */

        if (unit_warn_leftover_processes(UNIT(s), unit_log_leftover_process_start) > 0 &&
            IN_SET(s->kill_context.kill_mode, KILL_MIXED, KILL_CONTROL_GROUP) &&
            !s->kill_context.send_sigkill)
               return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(EBUSY),
                                           "Will not start SendSIGKILL=no service of type KillMode=control-group or mixed while processes exist");

        return 0;
}

static void service_enter_start(Service *s) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        ExecCommand *c;
        usec_t timeout;
        int r;

        assert(s);

        service_unwatch_control_pid(s);
        service_unwatch_main_pid(s);

        r = service_adverse_to_leftover_processes(s);
        if (r < 0)
                goto fail;

        if (s->type == SERVICE_FORKING) {
                s->control_command_id = SERVICE_EXEC_START;
                c = s->control_command = s->exec_command[SERVICE_EXEC_START];

                s->main_command = NULL;
        } else {
                s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;
                s->control_command = NULL;

                c = s->main_command = s->exec_command[SERVICE_EXEC_START];
        }

        if (!c) {
                if (s->type != SERVICE_ONESHOT) {
                        /* There's no command line configured for the main command? Hmm, that is strange.
                         * This can only happen if the configuration changes at runtime. In this case,
                         * let's enter a failure state. */
                        r = log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENXIO), "There's no 'start' task anymore we could start.");
                        goto fail;
                }

                /* We force a fake state transition here. Otherwise, the unit would go directly from
                 * SERVICE_DEAD to SERVICE_DEAD without SERVICE_ACTIVATING or SERVICE_ACTIVE
                 * in between. This way we can later trigger actions that depend on the state
                 * transition, including SuccessAction=. */
                service_set_state(s, SERVICE_START);

                service_enter_start_post(s);
                return;
        }

        if (IN_SET(s->type, SERVICE_SIMPLE, SERVICE_IDLE))
                /* For simple + idle this is the main process. We don't apply any timeout here, but
                 * service_enter_running() will later apply the .runtime_max_usec timeout. */
                timeout = USEC_INFINITY;
        else
                timeout = s->timeout_start_usec;

        r = service_spawn(s,
                          c,
                          timeout,
                          EXEC_PASS_FDS|EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_APPLY_TTY_STDIN|EXEC_SET_WATCHDOG|EXEC_WRITE_CREDENTIALS|EXEC_SETENV_MONITOR_RESULT,
                          &pidref);
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to spawn 'start' task: %m");
                goto fail;
        }

        if (IN_SET(s->type, SERVICE_SIMPLE, SERVICE_IDLE)) {
                /* For simple services we immediately start
                 * the START_POST binaries. */

                (void) service_set_main_pidref(s, &pidref);
                service_enter_start_post(s);

        } else  if (s->type == SERVICE_FORKING) {

                /* For forking services we wait until the start
                 * process exited. */

                pidref_done(&s->control_pid);
                s->control_pid = TAKE_PIDREF(pidref);
                service_set_state(s, SERVICE_START);

        } else if (IN_SET(s->type, SERVICE_ONESHOT, SERVICE_DBUS, SERVICE_NOTIFY, SERVICE_NOTIFY_RELOAD, SERVICE_EXEC)) {

                /* For oneshot services we wait until the start process exited, too, but it is our main process. */

                /* For D-Bus services we know the main pid right away, but wait for the bus name to appear on the
                 * bus. 'notify' and 'exec' services are similar. */

                (void) service_set_main_pidref(s, &pidref);
                service_set_state(s, SERVICE_START);
        } else
                assert_not_reached();

        return;

fail:
        service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_RESOURCES);
}

static void service_enter_start_pre(Service *s) {
        int r;

        assert(s);

        service_unwatch_control_pid(s);

        s->control_command = s->exec_command[SERVICE_EXEC_START_PRE];
        if (s->control_command) {

                r = service_adverse_to_leftover_processes(s);
                if (r < 0)
                        goto fail;

                s->control_command_id = SERVICE_EXEC_START_PRE;

                r = service_spawn(s,
                                  s->control_command,
                                  s->timeout_start_usec,
                                  EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_IS_CONTROL|EXEC_APPLY_TTY_STDIN|EXEC_SETENV_MONITOR_RESULT|EXEC_WRITE_CREDENTIALS,
                                  &s->control_pid);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to spawn 'start-pre' task: %m");
                        goto fail;
                }

                service_set_state(s, SERVICE_START_PRE);
        } else
                service_enter_start(s);

        return;

fail:
        service_enter_dead(s, SERVICE_FAILURE_RESOURCES, /* allow_restart= */ true);
}

static void service_enter_condition(Service *s) {
        int r;

        assert(s);

        service_unwatch_control_pid(s);

        s->control_command = s->exec_command[SERVICE_EXEC_CONDITION];
        if (s->control_command) {

                r = service_adverse_to_leftover_processes(s);
                if (r < 0)
                        goto fail;

                s->control_command_id = SERVICE_EXEC_CONDITION;
                pidref_done(&s->control_pid);

                r = service_spawn(s,
                                  s->control_command,
                                  s->timeout_start_usec,
                                  EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_IS_CONTROL|EXEC_APPLY_TTY_STDIN,
                                  &s->control_pid);

                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to spawn 'exec-condition' task: %m");
                        goto fail;
                }

                service_set_state(s, SERVICE_CONDITION);
        } else
                service_enter_start_pre(s);

        return;

fail:
        service_enter_dead(s, SERVICE_FAILURE_RESOURCES, /* allow_restart= */ true);
}

static void service_enter_restart(Service *s) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(s);

        if (unit_has_job_type(UNIT(s), JOB_STOP)) {
                /* Don't restart things if we are going down anyway */
                log_unit_info(UNIT(s), "Stop job pending for unit, skipping automatic restart.");
                return;
        }

        /* Any units that are bound to this service must also be restarted. We use JOB_START for ourselves
         * but then set JOB_RESTART_DEPENDENCIES which will enqueue JOB_RESTART for those dependency jobs. */
        r = manager_add_job(UNIT(s)->manager, JOB_START, UNIT(s), JOB_RESTART_DEPENDENCIES, NULL, &error, NULL);
        if (r < 0) {
                log_unit_warning(UNIT(s), "Failed to schedule restart job: %s", bus_error_message(&error, r));
                service_enter_dead(s, SERVICE_FAILURE_RESOURCES, /* allow_restart= */ false);
                return;
        }

        /* Count the jobs we enqueue for restarting. This counter is maintained as long as the unit isn't
         * fully stopped, i.e. as long as it remains up or remains in auto-start states. The user can reset
         * the counter explicitly however via the usual "systemctl reset-failure" logic. */
        s->n_restarts ++;
        s->flush_n_restarts = false;

        s->notify_access_override = _NOTIFY_ACCESS_INVALID;

        log_unit_struct(UNIT(s), LOG_INFO,
                        "MESSAGE_ID=" SD_MESSAGE_UNIT_RESTART_SCHEDULED_STR,
                        LOG_UNIT_INVOCATION_ID(UNIT(s)),
                        LOG_UNIT_MESSAGE(UNIT(s),
                                         "Scheduled restart job, restart counter is at %u.", s->n_restarts),
                        "N_RESTARTS=%u", s->n_restarts);

        service_set_state(s, SERVICE_AUTO_RESTART_QUEUED);

        /* Notify clients about changed restart counter */
        unit_add_to_dbus_queue(UNIT(s));
}

static void service_enter_reload_by_notify(Service *s) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(s);

        r = service_arm_timer(s, /* relative= */ true, s->timeout_start_usec);
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to install timer: %m");
                s->reload_result = SERVICE_FAILURE_RESOURCES;
                service_enter_running(s, SERVICE_SUCCESS);
                return;
        }

        service_set_state(s, SERVICE_RELOAD_NOTIFY);

        /* service_enter_reload_by_notify is never called during a reload, thus no loops are possible. */
        r = manager_propagate_reload(UNIT(s)->manager, UNIT(s), JOB_FAIL, &error);
        if (r < 0)
                log_unit_warning(UNIT(s), "Failed to schedule propagation of reload, ignoring: %s", bus_error_message(&error, r));
}

static void service_enter_reload(Service *s) {
        bool killed = false;
        int r;

        assert(s);

        service_unwatch_control_pid(s);
        s->reload_result = SERVICE_SUCCESS;

        usec_t ts = now(CLOCK_MONOTONIC);

        if (s->type == SERVICE_NOTIFY_RELOAD && pidref_is_set(&s->main_pid)) {
                r = pidref_kill_and_sigcont(&s->main_pid, s->reload_signal);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to send reload signal: %m");
                        goto fail;
                }

                killed = true;
        }

        s->control_command = s->exec_command[SERVICE_EXEC_RELOAD];
        if (s->control_command) {
                s->control_command_id = SERVICE_EXEC_RELOAD;
                pidref_done(&s->control_pid);

                r = service_spawn(s,
                                  s->control_command,
                                  s->timeout_start_usec,
                                  EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_IS_CONTROL|EXEC_CONTROL_CGROUP,
                                  &s->control_pid);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to spawn 'reload' task: %m");
                        goto fail;
                }

                service_set_state(s, SERVICE_RELOAD);
        } else if (killed) {
                r = service_arm_timer(s, /* relative= */ true, s->timeout_start_usec);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to install timer: %m");
                        goto fail;
                }

                service_set_state(s, SERVICE_RELOAD_SIGNAL);
        } else {
                service_enter_running(s, SERVICE_SUCCESS);
                return;
        }

        /* Store the timestamp when we started reloading: when reloading via SIGHUP we won't leave the reload
         * state until we received both RELOADING=1 and READY=1 with MONOTONIC_USEC= set to a value above
         * this. Thus we know for sure the reload cycle was executed *after* we requested it, and is not one
         * that was already in progress before. */
        s->reload_begin_usec = ts;
        return;

fail:
        s->reload_result = SERVICE_FAILURE_RESOURCES;
        service_enter_running(s, SERVICE_SUCCESS);
}

static void service_run_next_control(Service *s) {
        usec_t timeout;
        int r;

        assert(s);
        assert(s->control_command);
        assert(s->control_command->command_next);

        assert(s->control_command_id != SERVICE_EXEC_START);

        s->control_command = s->control_command->command_next;
        service_unwatch_control_pid(s);

        if (IN_SET(s->state, SERVICE_CONDITION, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST, SERVICE_RUNNING, SERVICE_RELOAD))
                timeout = s->timeout_start_usec;
        else
                timeout = s->timeout_stop_usec;

        pidref_done(&s->control_pid);

        r = service_spawn(s,
                          s->control_command,
                          timeout,
                          EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_IS_CONTROL|
                          (IN_SET(s->state, SERVICE_CONDITION, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST, SERVICE_RUNNING, SERVICE_RELOAD) ? EXEC_WRITE_CREDENTIALS : 0)|
                          (IN_SET(s->control_command_id, SERVICE_EXEC_CONDITION, SERVICE_EXEC_START_PRE, SERVICE_EXEC_STOP_POST) ? EXEC_APPLY_TTY_STDIN : 0)|
                          (IN_SET(s->control_command_id, SERVICE_EXEC_STOP, SERVICE_EXEC_STOP_POST) ? EXEC_SETENV_RESULT : 0)|
                          (IN_SET(s->control_command_id, SERVICE_EXEC_START_PRE, SERVICE_EXEC_START) ? EXEC_SETENV_MONITOR_RESULT : 0)|
                          (IN_SET(s->control_command_id, SERVICE_EXEC_START_POST, SERVICE_EXEC_RELOAD, SERVICE_EXEC_STOP, SERVICE_EXEC_STOP_POST) ? EXEC_CONTROL_CGROUP : 0),
                          &s->control_pid);
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to spawn next control task: %m");

                if (IN_SET(s->state, SERVICE_CONDITION, SERVICE_START_PRE, SERVICE_START_POST, SERVICE_STOP))
                        service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_RESOURCES);
                else if (s->state == SERVICE_STOP_POST)
                        service_enter_dead(s, SERVICE_FAILURE_RESOURCES, /* allow_restart= */ true);
                else if (s->state == SERVICE_RELOAD) {
                        s->reload_result = SERVICE_FAILURE_RESOURCES;
                        service_enter_running(s, SERVICE_SUCCESS);
                } else
                        service_enter_stop(s, SERVICE_FAILURE_RESOURCES);
        }
}

static void service_run_next_main(Service *s) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        assert(s);
        assert(s->main_command);
        assert(s->main_command->command_next);
        assert(s->type == SERVICE_ONESHOT);

        s->main_command = s->main_command->command_next;
        service_unwatch_main_pid(s);

        r = service_spawn(s,
                          s->main_command,
                          s->timeout_start_usec,
                          EXEC_PASS_FDS|EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_APPLY_TTY_STDIN|EXEC_SET_WATCHDOG|EXEC_SETENV_MONITOR_RESULT|EXEC_WRITE_CREDENTIALS,
                          &pidref);
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to spawn next main task: %m");
                service_enter_stop(s, SERVICE_FAILURE_RESOURCES);
                return;
        }

        (void) service_set_main_pidref(s, &pidref);
}

static int service_start(Unit *u) {
        Service *s = SERVICE(u);
        int r;

        assert(s);

        /* We cannot fulfill this request right now, try again later
         * please! */
        if (IN_SET(s->state,
                   SERVICE_STOP, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                   SERVICE_FINAL_WATCHDOG, SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL, SERVICE_CLEANING))
                return -EAGAIN;

        /* Already on it! */
        if (IN_SET(s->state, SERVICE_CONDITION, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST))
                return 0;

        /* A service that will be restarted must be stopped first to trigger BindsTo and/or OnFailure
         * dependencies. If a user does not want to wait for the holdoff time to elapse, the service should
         * be manually restarted, not started. We simply return EAGAIN here, so that any start jobs stay
         * queued, and assume that the auto restart timer will eventually trigger the restart. */
        if (IN_SET(s->state, SERVICE_AUTO_RESTART, SERVICE_DEAD_BEFORE_AUTO_RESTART, SERVICE_FAILED_BEFORE_AUTO_RESTART))
                return -EAGAIN;

        assert(IN_SET(s->state, SERVICE_DEAD, SERVICE_FAILED, SERVICE_DEAD_RESOURCES_PINNED, SERVICE_AUTO_RESTART_QUEUED));

        r = unit_acquire_invocation_id(u);
        if (r < 0)
                return r;

        s->result = SERVICE_SUCCESS;
        s->reload_result = SERVICE_SUCCESS;
        s->main_pid_known = false;
        s->main_pid_alien = false;
        s->forbid_restart = false;

        s->status_text = mfree(s->status_text);
        s->status_errno = 0;

        s->notify_access_override = _NOTIFY_ACCESS_INVALID;
        s->notify_state = NOTIFY_UNKNOWN;

        s->watchdog_original_usec = s->watchdog_usec;
        s->watchdog_override_enable = false;
        s->watchdog_override_usec = USEC_INFINITY;

        exec_command_reset_status_list_array(s->exec_command, _SERVICE_EXEC_COMMAND_MAX);
        exec_status_reset(&s->main_exec_status);

        /* This is not an automatic restart? Flush the restart counter then */
        if (s->flush_n_restarts) {
                s->n_restarts = 0;
                s->flush_n_restarts = false;
        }

        u->reset_accounting = true;

        service_enter_condition(s);
        return 1;
}

static int service_stop(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        /* Don't create restart jobs from manual stops. */
        s->forbid_restart = true;

        switch (s->state) {

        case SERVICE_STOP:
        case SERVICE_STOP_SIGTERM:
        case SERVICE_STOP_SIGKILL:
        case SERVICE_STOP_POST:
        case SERVICE_FINAL_WATCHDOG:
        case SERVICE_FINAL_SIGTERM:
        case SERVICE_FINAL_SIGKILL:
                /* Already on it */
                return 0;

        case SERVICE_AUTO_RESTART:
        case SERVICE_AUTO_RESTART_QUEUED:
                /* Give up on the auto restart */
                service_set_state(s, service_determine_dead_state(s));
                return 0;

        case SERVICE_CONDITION:
        case SERVICE_START_PRE:
        case SERVICE_START:
        case SERVICE_START_POST:
        case SERVICE_RELOAD:
        case SERVICE_RELOAD_SIGNAL:
        case SERVICE_RELOAD_NOTIFY:
        case SERVICE_STOP_WATCHDOG:
                /* If there's already something running we go directly into kill mode. */
                service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_SUCCESS);
                return 0;

        case SERVICE_CLEANING:
                /* If we are currently cleaning, then abort it, brutally. */
                service_enter_signal(s, SERVICE_FINAL_SIGKILL, SERVICE_SUCCESS);
                return 0;

        case SERVICE_RUNNING:
        case SERVICE_EXITED:
                service_enter_stop(s, SERVICE_SUCCESS);
                return 1;

        case SERVICE_DEAD_BEFORE_AUTO_RESTART:
        case SERVICE_FAILED_BEFORE_AUTO_RESTART:
        case SERVICE_DEAD:
        case SERVICE_FAILED:
        case SERVICE_DEAD_RESOURCES_PINNED:
        default:
                /* Unknown state, or unit_stop() should already have handled these */
                assert_not_reached();
        }
}

static int service_reload(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        assert(IN_SET(s->state, SERVICE_RUNNING, SERVICE_EXITED));

        service_enter_reload(s);
        return 1;
}

static bool service_can_reload(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        return s->exec_command[SERVICE_EXEC_RELOAD] ||
                s->type == SERVICE_NOTIFY_RELOAD;
}

static unsigned service_exec_command_index(Unit *u, ServiceExecCommand id, const ExecCommand *current) {
        Service *s = SERVICE(u);
        unsigned idx = 0;

        assert(s);
        assert(id >= 0);
        assert(id < _SERVICE_EXEC_COMMAND_MAX);

        const ExecCommand *first = s->exec_command[id];

        /* Figure out where we are in the list by walking back to the beginning */
        for (const ExecCommand *c = current; c != first; c = c->command_prev)
                idx++;

        return idx;
}

static int service_serialize_exec_command(Unit *u, FILE *f, const ExecCommand *command) {
        _cleanup_free_ char *args = NULL, *p = NULL;
        Service *s = SERVICE(u);
        const char *type, *key;
        ServiceExecCommand id;
        size_t length = 0;
        unsigned idx;

        assert(s);
        assert(f);

        if (!command)
                return 0;

        if (command == s->control_command) {
                type = "control";
                id = s->control_command_id;
        } else {
                type = "main";
                id = SERVICE_EXEC_START;
        }

        idx = service_exec_command_index(u, id, command);

        STRV_FOREACH(arg, command->argv) {
                _cleanup_free_ char *e = NULL;
                size_t n;

                e = cescape(*arg);
                if (!e)
                        return log_oom();

                n = strlen(e);
                if (!GREEDY_REALLOC(args, length + 2 + n + 2))
                        return log_oom();

                if (length > 0)
                        args[length++] = ' ';

                args[length++] = '"';
                memcpy(args + length, e, n);
                length += n;
                args[length++] = '"';
        }

        if (!GREEDY_REALLOC(args, length + 1))
                return log_oom();

        args[length++] = 0;

        p = cescape(command->path);
        if (!p)
                return log_oom();

        key = strjoina(type, "-command");

        /* We use '+1234' instead of '1234' to mark the last command in a sequence.
         * This is used in service_deserialize_exec_command(). */
        (void) serialize_item_format(
                        f, key,
                        "%s %s%u %s %s",
                        service_exec_command_to_string(id),
                        command->command_next ? "" : "+",
                        idx,
                        p, args);

        return 0;
}

static int service_serialize(Unit *u, FILE *f, FDSet *fds) {
        Service *s = SERVICE(u);
        int r;

        assert(u);
        assert(f);
        assert(fds);

        (void) serialize_item(f, "state", service_state_to_string(s->state));
        (void) serialize_item(f, "result", service_result_to_string(s->result));
        (void) serialize_item(f, "reload-result", service_result_to_string(s->reload_result));

        (void) serialize_pidref(f, fds, "control-pid", &s->control_pid);
        if (s->main_pid_known)
                (void) serialize_pidref(f, fds, "main-pid", &s->main_pid);

        (void) serialize_bool(f, "main-pid-known", s->main_pid_known);
        (void) serialize_bool(f, "bus-name-good", s->bus_name_good);
        (void) serialize_bool(f, "bus-name-owner", s->bus_name_owner);

        (void) serialize_item_format(f, "n-restarts", "%u", s->n_restarts);
        (void) serialize_bool(f, "flush-n-restarts", s->flush_n_restarts);

        r = serialize_item_escaped(f, "status-text", s->status_text);
        if (r < 0)
                return r;

        service_serialize_exec_command(u, f, s->control_command);
        service_serialize_exec_command(u, f, s->main_command);

        r = serialize_fd(f, fds, "stdin-fd", s->stdin_fd);
        if (r < 0)
                return r;
        r = serialize_fd(f, fds, "stdout-fd", s->stdout_fd);
        if (r < 0)
                return r;
        r = serialize_fd(f, fds, "stderr-fd", s->stderr_fd);
        if (r < 0)
                return r;

        if (s->exec_fd_event_source) {
                r = serialize_fd(f, fds, "exec-fd", sd_event_source_get_io_fd(s->exec_fd_event_source));
                if (r < 0)
                        return r;

                (void) serialize_bool(f, "exec-fd-hot", s->exec_fd_hot);
        }

        if (UNIT_ISSET(s->accept_socket)) {
                r = serialize_item(f, "accept-socket", UNIT_DEREF(s->accept_socket)->id);
                if (r < 0)
                        return r;
        }

        r = serialize_fd(f, fds, "socket-fd", s->socket_fd);
        if (r < 0)
                return r;

        LIST_FOREACH(fd_store, fs, s->fd_store) {
                _cleanup_free_ char *c = NULL;
                int copy;

                copy = fdset_put_dup(fds, fs->fd);
                if (copy < 0)
                        return log_error_errno(copy, "Failed to copy file descriptor for serialization: %m");

                c = cescape(fs->fdname);
                if (!c)
                        return log_oom();

                (void) serialize_item_format(f, "fd-store-fd", "%i \"%s\" %i", copy, c, fs->do_poll);
        }

        if (s->main_exec_status.pid > 0) {
                (void) serialize_item_format(f, "main-exec-status-pid", PID_FMT, s->main_exec_status.pid);
                (void) serialize_dual_timestamp(f, "main-exec-status-start", &s->main_exec_status.start_timestamp);
                (void) serialize_dual_timestamp(f, "main-exec-status-exit", &s->main_exec_status.exit_timestamp);

                if (dual_timestamp_is_set(&s->main_exec_status.exit_timestamp)) {
                        (void) serialize_item_format(f, "main-exec-status-code", "%i", s->main_exec_status.code);
                        (void) serialize_item_format(f, "main-exec-status-status", "%i", s->main_exec_status.status);
                }
        }

        if (s->notify_access_override >= 0)
                (void) serialize_item(f, "notify-access-override", notify_access_to_string(s->notify_access_override));

        (void) serialize_dual_timestamp(f, "watchdog-timestamp", &s->watchdog_timestamp);
        (void) serialize_bool(f, "forbid-restart", s->forbid_restart);

        if (s->watchdog_override_enable)
                (void) serialize_item_format(f, "watchdog-override-usec", USEC_FMT, s->watchdog_override_usec);

        if (s->watchdog_original_usec != USEC_INFINITY)
                (void) serialize_item_format(f, "watchdog-original-usec", USEC_FMT, s->watchdog_original_usec);

        if (s->reload_begin_usec != USEC_INFINITY)
                (void) serialize_item_format(f, "reload-begin-usec", USEC_FMT, s->reload_begin_usec);

        return 0;
}

int service_deserialize_exec_command(
                Unit *u,
                const char *key,
                const char *value) {

        Service *s = SERVICE(u);
        int r;
        unsigned idx = 0, i;
        bool control, found = false, last = false;
        ServiceExecCommand id = _SERVICE_EXEC_COMMAND_INVALID;
        ExecCommand *command = NULL;
        _cleanup_free_ char *path = NULL;
        _cleanup_strv_free_ char **argv = NULL;

        enum ExecCommandState {
                STATE_EXEC_COMMAND_TYPE,
                STATE_EXEC_COMMAND_INDEX,
                STATE_EXEC_COMMAND_PATH,
                STATE_EXEC_COMMAND_ARGS,
                _STATE_EXEC_COMMAND_MAX,
                _STATE_EXEC_COMMAND_INVALID = -EINVAL,
        } state;

        assert(s);
        assert(key);
        assert(value);

        control = streq(key, "control-command");

        state = STATE_EXEC_COMMAND_TYPE;

        for (;;) {
                _cleanup_free_ char *arg = NULL;

                r = extract_first_word(&value, &arg, NULL, EXTRACT_CUNESCAPE | EXTRACT_UNQUOTE);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                switch (state) {
                case STATE_EXEC_COMMAND_TYPE:
                        id = service_exec_command_from_string(arg);
                        if (id < 0)
                                return id;

                        state = STATE_EXEC_COMMAND_INDEX;
                        break;
                case STATE_EXEC_COMMAND_INDEX:
                        /* PID 1234 is serialized as either '1234' or '+1234'. The second form is used to
                         * mark the last command in a sequence. We warn if the deserialized command doesn't
                         * match what we have loaded from the unit, but we don't need to warn if that is the
                         * last command. */

                        r = safe_atou(arg, &idx);
                        if (r < 0)
                                return r;
                        last = arg[0] == '+';

                        state = STATE_EXEC_COMMAND_PATH;
                        break;
                case STATE_EXEC_COMMAND_PATH:
                        path = TAKE_PTR(arg);
                        state = STATE_EXEC_COMMAND_ARGS;
                        break;
                case STATE_EXEC_COMMAND_ARGS:
                        r = strv_extend(&argv, arg);
                        if (r < 0)
                                return -ENOMEM;
                        break;
                default:
                        assert_not_reached();
                }
        }

        if (state != STATE_EXEC_COMMAND_ARGS)
                return -EINVAL;
        if (strv_isempty(argv))
                return -EINVAL; /* At least argv[0] must be always present. */

        /* Let's check whether exec command on given offset matches data that we just deserialized */
        for (command = s->exec_command[id], i = 0; command; command = command->command_next, i++) {
                if (i != idx)
                        continue;

                found = strv_equal(argv, command->argv) && streq(command->path, path);
                break;
        }

        if (!found) {
                /* Command at the index we serialized is different, let's look for command that exactly
                 * matches but is on different index. If there is no such command we will not resume execution. */
                for (command = s->exec_command[id]; command; command = command->command_next)
                        if (strv_equal(command->argv, argv) && streq(command->path, path))
                                break;
        }

        if (command && control) {
                s->control_command = command;
                s->control_command_id = id;
        } else if (command)
                s->main_command = command;
        else if (last)
                log_unit_debug(u, "Current command vanished from the unit file.");
        else
                log_unit_warning(u, "Current command vanished from the unit file, execution of the command list won't be resumed.");

        return 0;
}

static int service_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Service *s = SERVICE(u);
        int r;

        assert(u);
        assert(key);
        assert(value);
        assert(fds);

        if (streq(key, "state")) {
                ServiceState state;

                state = service_state_from_string(value);
                if (state < 0)
                        log_unit_debug(u, "Failed to parse state value: %s", value);
                else
                        s->deserialized_state = state;
        } else if (streq(key, "result")) {
                ServiceResult f;

                f = service_result_from_string(value);
                if (f < 0)
                        log_unit_debug(u, "Failed to parse result value: %s", value);
                else if (f != SERVICE_SUCCESS)
                        s->result = f;

        } else if (streq(key, "reload-result")) {
                ServiceResult f;

                f = service_result_from_string(value);
                if (f < 0)
                        log_unit_debug(u, "Failed to parse reload result value: %s", value);
                else if (f != SERVICE_SUCCESS)
                        s->reload_result = f;

        } else if (streq(key, "control-pid")) {
                pidref_done(&s->control_pid);

                (void) deserialize_pidref(fds, value, &s->control_pid);

        } else if (streq(key, "main-pid")) {
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

                if (deserialize_pidref(fds, value, &pidref) >= 0)
                        (void) service_set_main_pidref(s, &pidref);

        } else if (streq(key, "main-pid-known")) {
                int b;

                b = parse_boolean(value);
                if (b < 0)
                        log_unit_debug(u, "Failed to parse main-pid-known value: %s", value);
                else
                        s->main_pid_known = b;
        } else if (streq(key, "bus-name-good")) {
                int b;

                b = parse_boolean(value);
                if (b < 0)
                        log_unit_debug(u, "Failed to parse bus-name-good value: %s", value);
                else
                        s->bus_name_good = b;
        } else if (streq(key, "bus-name-owner")) {
                r = free_and_strdup(&s->bus_name_owner, value);
                if (r < 0)
                        log_unit_error_errno(u, r, "Unable to deserialize current bus owner %s: %m", value);
        } else if (streq(key, "status-text")) {
                char *t;
                ssize_t l;

                l = cunescape(value, 0, &t);
                if (l < 0)
                        log_unit_debug_errno(u, l, "Failed to unescape status text '%s': %m", value);
                else
                        free_and_replace(s->status_text, t);

        } else if (streq(key, "accept-socket")) {
                Unit *socket;

                if (u->type != UNIT_SOCKET) {
                        log_unit_debug(u, "Failed to deserialize accept-socket: unit is not a socket");
                        return 0;
                }

                r = manager_load_unit(u->manager, value, NULL, NULL, &socket);
                if (r < 0)
                        log_unit_debug_errno(u, r, "Failed to load accept-socket unit '%s': %m", value);
                else {
                        unit_ref_set(&s->accept_socket, u, socket);
                        SOCKET(socket)->n_connections++;
                }

        } else if (streq(key, "socket-fd")) {
                asynchronous_close(s->socket_fd);
                s->socket_fd = deserialize_fd(fds, value);

        } else if (streq(key, "fd-store-fd")) {
                _cleanup_free_ char *fdv = NULL, *fdn = NULL, *fdp = NULL;
                _cleanup_close_ int fd = -EBADF;
                int do_poll;

                r = extract_first_word(&value, &fdv, NULL, 0);
                if (r <= 0) {
                        log_unit_debug(u, "Failed to parse fd-store-fd value, ignoring: %s", value);
                        return 0;
                }

                fd = deserialize_fd(fds, fdv);
                if (fd < 0)
                        return 0;

                r = extract_first_word(&value, &fdn, NULL, EXTRACT_CUNESCAPE | EXTRACT_UNQUOTE);
                if (r <= 0) {
                        log_unit_debug(u, "Failed to parse fd-store-fd value, ignoring: %s", value);
                        return 0;
                }

                r = extract_first_word(&value, &fdp, NULL, 0);
                if (r == 0) {
                        /* If the value is not present, we assume the default */
                        do_poll = 1;
                } else if (r < 0 || (r = safe_atoi(fdp, &do_poll)) < 0) {
                        log_unit_debug_errno(u, r, "Failed to parse fd-store-fd value \"%s\", ignoring: %m", value);
                        return 0;
                }

                r = service_add_fd_store(s, fd, fdn, do_poll);
                if (r < 0) {
                        log_unit_debug_errno(u, r, "Failed to store deserialized fd %i, ignoring: %m", fd);
                        return 0;
                }

                TAKE_FD(fd);
        } else if (streq(key, "main-exec-status-pid")) {
                pid_t pid;

                if (parse_pid(value, &pid) < 0)
                        log_unit_debug(u, "Failed to parse main-exec-status-pid value: %s", value);
                else
                        s->main_exec_status.pid = pid;
        } else if (streq(key, "main-exec-status-code")) {
                int i;

                if (safe_atoi(value, &i) < 0)
                        log_unit_debug(u, "Failed to parse main-exec-status-code value: %s", value);
                else
                        s->main_exec_status.code = i;
        } else if (streq(key, "main-exec-status-status")) {
                int i;

                if (safe_atoi(value, &i) < 0)
                        log_unit_debug(u, "Failed to parse main-exec-status-status value: %s", value);
                else
                        s->main_exec_status.status = i;
        } else if (streq(key, "main-exec-status-start"))
                deserialize_dual_timestamp(value, &s->main_exec_status.start_timestamp);
        else if (streq(key, "main-exec-status-exit"))
                deserialize_dual_timestamp(value, &s->main_exec_status.exit_timestamp);
        else if (streq(key, "notify-access-override")) {
                NotifyAccess notify_access;

                notify_access = notify_access_from_string(value);
                if (notify_access < 0)
                        log_unit_debug(u, "Failed to parse notify-access-override value: %s", value);
                else
                        s->notify_access_override = notify_access;
        } else if (streq(key, "watchdog-timestamp"))
                deserialize_dual_timestamp(value, &s->watchdog_timestamp);
        else if (streq(key, "forbid-restart")) {
                int b;

                b = parse_boolean(value);
                if (b < 0)
                        log_unit_debug(u, "Failed to parse forbid-restart value: %s", value);
                else
                        s->forbid_restart = b;
        } else if (streq(key, "stdin-fd")) {

                asynchronous_close(s->stdin_fd);
                s->stdin_fd = deserialize_fd(fds, value);
                if (s->stdin_fd >= 0)
                        s->exec_context.stdio_as_fds = true;

        } else if (streq(key, "stdout-fd")) {

                asynchronous_close(s->stdout_fd);
                s->stdout_fd = deserialize_fd(fds, value);
                if (s->stdout_fd >= 0)
                        s->exec_context.stdio_as_fds = true;

        } else if (streq(key, "stderr-fd")) {

                asynchronous_close(s->stderr_fd);
                s->stderr_fd = deserialize_fd(fds, value);
                if (s->stderr_fd >= 0)
                        s->exec_context.stdio_as_fds = true;

        } else if (streq(key, "exec-fd")) {
                _cleanup_close_ int fd = -EBADF;

                fd = deserialize_fd(fds, value);
                if (fd >= 0) {
                        s->exec_fd_event_source = sd_event_source_disable_unref(s->exec_fd_event_source);

                        if (service_allocate_exec_fd_event_source(s, fd, &s->exec_fd_event_source) >= 0)
                                TAKE_FD(fd);
                }

        } else if (streq(key, "watchdog-override-usec")) {
                if (deserialize_usec(value, &s->watchdog_override_usec) < 0)
                        log_unit_debug(u, "Failed to parse watchdog_override_usec value: %s", value);
                else
                        s->watchdog_override_enable = true;

        } else if (streq(key, "watchdog-original-usec")) {
                if (deserialize_usec(value, &s->watchdog_original_usec) < 0)
                        log_unit_debug(u, "Failed to parse watchdog_original_usec value: %s", value);

        } else if (STR_IN_SET(key, "main-command", "control-command")) {
                r = service_deserialize_exec_command(u, key, value);
                if (r < 0)
                        log_unit_debug_errno(u, r, "Failed to parse serialized command \"%s\": %m", value);

        } else if (streq(key, "n-restarts")) {
                r = safe_atou(value, &s->n_restarts);
                if (r < 0)
                        log_unit_debug_errno(u, r, "Failed to parse serialized restart counter '%s': %m", value);

        } else if (streq(key, "flush-n-restarts")) {
                r = parse_boolean(value);
                if (r < 0)
                        log_unit_debug_errno(u, r, "Failed to parse serialized flush restart counter setting '%s': %m", value);
                else
                        s->flush_n_restarts = r;
        } else if (streq(key, "reload-begin-usec")) {
                r = deserialize_usec(value, &s->reload_begin_usec);
                if (r < 0)
                        log_unit_debug_errno(u, r, "Failed to parse serialized reload begin timestamp '%s', ignoring: %m", value);
        } else
                log_unit_debug(u, "Unknown serialization key: %s", key);

        return 0;
}

static UnitActiveState service_active_state(Unit *u) {
        const UnitActiveState *table;

        assert(u);

        table = SERVICE(u)->type == SERVICE_IDLE ? state_translation_table_idle : state_translation_table;

        return table[SERVICE(u)->state];
}

static const char *service_sub_state_to_string(Unit *u) {
        assert(u);

        return service_state_to_string(SERVICE(u)->state);
}

static bool service_may_gc(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        /* Never clean up services that still have a process around, even if the service is formally dead. Note that
         * unit_may_gc() already checked our cgroup for us, we just check our two additional PIDs, too, in case they
         * have moved outside of the cgroup. */

        if (main_pid_good(s) > 0 ||
            control_pid_good(s) > 0)
                return false;

        /* Only allow collection of actually dead services, i.e. not those that are in the transitionary
         * SERVICE_DEAD_BEFORE_AUTO_RESTART/SERVICE_FAILED_BEFORE_AUTO_RESTART states. */
        if (!IN_SET(s->state, SERVICE_DEAD, SERVICE_FAILED, SERVICE_DEAD_RESOURCES_PINNED))
                return false;

        return true;
}

static int service_retry_pid_file(Service *s) {
        int r;

        assert(s->pid_file);
        assert(IN_SET(s->state, SERVICE_START, SERVICE_START_POST));

        r = service_load_pid_file(s, false);
        if (r < 0)
                return r;

        service_unwatch_pid_file(s);

        service_enter_running(s, SERVICE_SUCCESS);
        return 0;
}

static int service_watch_pid_file(Service *s) {
        int r;

        log_unit_debug(UNIT(s), "Setting watch for PID file %s", s->pid_file_pathspec->path);

        r = path_spec_watch(s->pid_file_pathspec, service_dispatch_inotify_io);
        if (r < 0) {
                log_unit_error_errno(UNIT(s), r, "Failed to set a watch for PID file %s: %m", s->pid_file_pathspec->path);
                service_unwatch_pid_file(s);
                return r;
        }

        /* the pidfile might have appeared just before we set the watch */
        log_unit_debug(UNIT(s), "Trying to read PID file %s in case it changed", s->pid_file_pathspec->path);
        service_retry_pid_file(s);

        return 0;
}

static int service_demand_pid_file(Service *s) {
        _cleanup_free_ PathSpec *ps = NULL;

        assert(s->pid_file);
        assert(!s->pid_file_pathspec);

        ps = new(PathSpec, 1);
        if (!ps)
                return -ENOMEM;

        *ps = (PathSpec) {
                .unit = UNIT(s),
                .path = strdup(s->pid_file),
                /* PATH_CHANGED would not be enough. There are daemons (sendmail) that keep their PID file
                 * open all the time. */
                .type = PATH_MODIFIED,
                .inotify_fd = -EBADF,
        };

        if (!ps->path)
                return -ENOMEM;

        path_simplify(ps->path);

        s->pid_file_pathspec = TAKE_PTR(ps);

        return service_watch_pid_file(s);
}

static int service_dispatch_inotify_io(sd_event_source *source, int fd, uint32_t events, void *userdata) {
        PathSpec *p = ASSERT_PTR(userdata);
        Service *s;

        s = SERVICE(p->unit);

        assert(s);
        assert(fd >= 0);
        assert(IN_SET(s->state, SERVICE_START, SERVICE_START_POST));
        assert(s->pid_file_pathspec);
        assert(path_spec_owns_inotify_fd(s->pid_file_pathspec, fd));

        log_unit_debug(UNIT(s), "inotify event");

        if (path_spec_fd_event(p, events) < 0)
                goto fail;

        if (service_retry_pid_file(s) == 0)
                return 0;

        if (service_watch_pid_file(s) < 0)
                goto fail;

        return 0;

fail:
        service_unwatch_pid_file(s);
        service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_RESOURCES);
        return 0;
}

static int service_dispatch_exec_io(sd_event_source *source, int fd, uint32_t events, void *userdata) {
        Service *s = SERVICE(userdata);

        assert(s);

        log_unit_debug(UNIT(s), "got exec-fd event");

        /* If Type=exec is set, we'll consider a service started successfully the instant we invoked execve()
         * successfully for it. We implement this through a pipe() towards the child, which the kernel automatically
         * closes for us due to O_CLOEXEC on execve() in the child, which then triggers EOF on the pipe in the
         * parent. We need to be careful however, as there are other reasons that we might cause the child's side of
         * the pipe to be closed (for example, a simple exit()). To deal with that we'll ignore EOFs on the pipe unless
         * the child signalled us first that it is about to call the execve(). It does so by sending us a simple
         * non-zero byte via the pipe. We also provide the child with a way to inform us in case execve() failed: if it
         * sends a zero byte we'll ignore POLLHUP on the fd again. */

        for (;;) {
                uint8_t x;
                ssize_t n;

                n = read(fd, &x, sizeof(x));
                if (n < 0) {
                        if (errno == EAGAIN) /* O_NONBLOCK in effect → everything queued has now been processed. */
                                return 0;

                        return log_unit_error_errno(UNIT(s), errno, "Failed to read from exec_fd: %m");
                }
                if (n == 0) { /* EOF → the event we are waiting for */

                        s->exec_fd_event_source = sd_event_source_disable_unref(s->exec_fd_event_source);

                        if (s->exec_fd_hot) { /* Did the child tell us to expect EOF now? */
                                log_unit_debug(UNIT(s), "Got EOF on exec-fd");

                                s->exec_fd_hot = false;

                                /* Nice! This is what we have been waiting for. Transition to next state. */
                                if (s->type == SERVICE_EXEC && s->state == SERVICE_START)
                                        service_enter_start_post(s);
                        } else
                                log_unit_debug(UNIT(s), "Got EOF on exec-fd while it was disabled, ignoring.");

                        return 0;
                }

                /* A byte was read → this turns on/off the exec fd logic */
                assert(n == sizeof(x));
                s->exec_fd_hot = x;
        }

        return 0;
}

static void service_notify_cgroup_empty_event(Unit *u) {
        Service *s = SERVICE(u);

        assert(u);

        log_unit_debug(u, "Control group is empty.");

        switch (s->state) {

                /* Waiting for SIGCHLD is usually more interesting, because it includes return
                 * codes/signals. Which is why we ignore the cgroup events for most cases, except when we
                 * don't know pid which to expect the SIGCHLD for. */

        case SERVICE_START:
                if (IN_SET(s->type, SERVICE_NOTIFY, SERVICE_NOTIFY_RELOAD) &&
                    main_pid_good(s) == 0 &&
                    control_pid_good(s) == 0) {
                        /* No chance of getting a ready notification anymore */
                        service_enter_stop_post(s, SERVICE_FAILURE_PROTOCOL);
                        break;
                }

                if (s->exit_type == SERVICE_EXIT_CGROUP && main_pid_good(s) <= 0)
                        service_enter_start_post(s);

                _fallthrough_;
        case SERVICE_START_POST:
                if (s->pid_file_pathspec &&
                    main_pid_good(s) == 0 &&
                    control_pid_good(s) == 0) {

                        /* Give up hoping for the daemon to write its PID file */
                        log_unit_warning(u, "Daemon never wrote its PID file. Failing.");

                        service_unwatch_pid_file(s);
                        if (s->state == SERVICE_START)
                                service_enter_stop_post(s, SERVICE_FAILURE_PROTOCOL);
                        else
                                service_enter_stop(s, SERVICE_FAILURE_PROTOCOL);
                }
                break;

        case SERVICE_RUNNING:
                /* service_enter_running() will figure out what to do */
                service_enter_running(s, SERVICE_SUCCESS);
                break;

        case SERVICE_STOP_WATCHDOG:
        case SERVICE_STOP_SIGTERM:
        case SERVICE_STOP_SIGKILL:

                if (main_pid_good(s) <= 0 && control_pid_good(s) <= 0)
                        service_enter_stop_post(s, SERVICE_SUCCESS);

                break;

        case SERVICE_STOP_POST:
        case SERVICE_FINAL_WATCHDOG:
        case SERVICE_FINAL_SIGTERM:
        case SERVICE_FINAL_SIGKILL:
                if (main_pid_good(s) <= 0 && control_pid_good(s) <= 0)
                        service_enter_dead(s, SERVICE_SUCCESS, true);

                break;

        /* If the cgroup empty notification comes when the unit is not active, we must have failed to clean
         * up the cgroup earlier and should do it now. */
        case SERVICE_AUTO_RESTART:
        case SERVICE_AUTO_RESTART_QUEUED:
                unit_prune_cgroup(u);
                break;

        default:
                ;
        }
}

static void service_notify_cgroup_oom_event(Unit *u, bool managed_oom) {
        Service *s = SERVICE(u);

        if (managed_oom)
                log_unit_debug(u, "Process(es) of control group were killed by systemd-oomd.");
        else
                log_unit_debug(u, "Process of control group was killed by the OOM killer.");

        if (s->oom_policy == OOM_CONTINUE)
                return;

        switch (s->state) {

        case SERVICE_CONDITION:
        case SERVICE_START_PRE:
        case SERVICE_START:
        case SERVICE_START_POST:
        case SERVICE_STOP:
                if (s->oom_policy == OOM_STOP)
                        service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_OOM_KILL);
                else if (s->oom_policy == OOM_KILL)
                        service_enter_signal(s, SERVICE_STOP_SIGKILL, SERVICE_FAILURE_OOM_KILL);

                break;

        case SERVICE_EXITED:
        case SERVICE_RUNNING:
                if (s->oom_policy == OOM_STOP)
                        service_enter_stop(s, SERVICE_FAILURE_OOM_KILL);
                else if (s->oom_policy == OOM_KILL)
                        service_enter_signal(s, SERVICE_STOP_SIGKILL, SERVICE_FAILURE_OOM_KILL);

                break;

        case SERVICE_STOP_WATCHDOG:
        case SERVICE_STOP_SIGTERM:
                service_enter_signal(s, SERVICE_STOP_SIGKILL, SERVICE_FAILURE_OOM_KILL);
                break;

        case SERVICE_STOP_SIGKILL:
        case SERVICE_FINAL_SIGKILL:
                if (s->result == SERVICE_SUCCESS)
                        s->result = SERVICE_FAILURE_OOM_KILL;
                break;

        case SERVICE_STOP_POST:
        case SERVICE_FINAL_SIGTERM:
                service_enter_signal(s, SERVICE_FINAL_SIGKILL, SERVICE_FAILURE_OOM_KILL);
                break;

        default:
                ;
        }
}

static void service_sigchld_event(Unit *u, pid_t pid, int code, int status) {
        bool notify_dbus = true;
        Service *s = SERVICE(u);
        ServiceResult f;
        ExitClean clean_mode;

        assert(s);
        assert(pid >= 0);

        /* Oneshot services and non-SERVICE_EXEC_START commands should not be
         * considered daemons as they are typically not long running. */
        if (s->type == SERVICE_ONESHOT || (s->control_pid.pid == pid && s->control_command_id != SERVICE_EXEC_START))
                clean_mode = EXIT_CLEAN_COMMAND;
        else
                clean_mode = EXIT_CLEAN_DAEMON;

        if (is_clean_exit(code, status, clean_mode, &s->success_status))
                f = SERVICE_SUCCESS;
        else if (code == CLD_EXITED)
                f = SERVICE_FAILURE_EXIT_CODE;
        else if (code == CLD_KILLED)
                f = SERVICE_FAILURE_SIGNAL;
        else if (code == CLD_DUMPED)
                f = SERVICE_FAILURE_CORE_DUMP;
        else
                assert_not_reached();

        if (s->main_pid.pid == pid) {
                /* Clean up the exec_fd event source. We want to do this here, not later in
                 * service_set_state(), because service_enter_stop_post() calls service_spawn().
                 * The source owns its end of the pipe, so this will close that too. */
                s->exec_fd_event_source = sd_event_source_disable_unref(s->exec_fd_event_source);

                /* Forking services may occasionally move to a new PID.
                 * As long as they update the PID file before exiting the old
                 * PID, they're fine. */
                if (service_load_pid_file(s, false) > 0)
                        return;

                pidref_done(&s->main_pid);
                exec_status_exit(&s->main_exec_status, &s->exec_context, pid, code, status);

                if (s->main_command) {
                        /* If this is not a forking service than the
                         * main process got started and hence we copy
                         * the exit status so that it is recorded both
                         * as main and as control process exit
                         * status */

                        s->main_command->exec_status = s->main_exec_status;

                        if (s->main_command->flags & EXEC_COMMAND_IGNORE_FAILURE)
                                f = SERVICE_SUCCESS;
                } else if (s->exec_command[SERVICE_EXEC_START]) {

                        /* If this is a forked process, then we should
                         * ignore the return value if this was
                         * configured for the starter process */

                        if (s->exec_command[SERVICE_EXEC_START]->flags & EXEC_COMMAND_IGNORE_FAILURE)
                                f = SERVICE_SUCCESS;
                }

                unit_log_process_exit(
                                u,
                                "Main process",
                                service_exec_command_to_string(SERVICE_EXEC_START),
                                f == SERVICE_SUCCESS,
                                code, status);

                if (s->result == SERVICE_SUCCESS)
                        s->result = f;

                if (s->main_command &&
                    s->main_command->command_next &&
                    s->type == SERVICE_ONESHOT &&
                    f == SERVICE_SUCCESS) {

                        /* There is another command to execute, so let's do that. */

                        log_unit_debug(u, "Running next main command for state %s.", service_state_to_string(s->state));
                        service_run_next_main(s);

                } else {
                        s->main_command = NULL;

                        /* Services with ExitType=cgroup do not act on main PID exiting, unless the cgroup is
                         * already empty */
                        if (s->exit_type == SERVICE_EXIT_MAIN || cgroup_good(s) <= 0) {
                                /* The service exited, so the service is officially gone. */
                                switch (s->state) {

                                case SERVICE_START_POST:
                                case SERVICE_RELOAD:
                                case SERVICE_RELOAD_SIGNAL:
                                case SERVICE_RELOAD_NOTIFY:
                                        /* If neither main nor control processes are running then the current
                                         * state can never exit cleanly, hence immediately terminate the
                                         * service. */
                                        if (control_pid_good(s) <= 0)
                                                service_enter_stop(s, f);

                                        /* Otherwise need to wait until the operation is done. */
                                        break;

                                case SERVICE_STOP:
                                        /* Need to wait until the operation is done. */
                                        break;

                                case SERVICE_START:
                                        if (s->type == SERVICE_ONESHOT) {
                                                /* This was our main goal, so let's go on */
                                                if (f == SERVICE_SUCCESS)
                                                        service_enter_start_post(s);
                                                else
                                                        service_enter_signal(s, SERVICE_STOP_SIGTERM, f);
                                                break;
                                        } else if (IN_SET(s->type, SERVICE_NOTIFY, SERVICE_NOTIFY_RELOAD)) {
                                                /* Only enter running through a notification, so that the
                                                 * SERVICE_START state signifies that no ready notification
                                                 * has been received */
                                                if (f != SERVICE_SUCCESS)
                                                        service_enter_signal(s, SERVICE_STOP_SIGTERM, f);
                                                else if (!s->remain_after_exit || service_get_notify_access(s) == NOTIFY_MAIN)
                                                        /* The service has never been and will never be active */
                                                        service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_PROTOCOL);
                                                break;
                                        }

                                        _fallthrough_;
                                case SERVICE_RUNNING:
                                        service_enter_running(s, f);
                                        break;

                                case SERVICE_STOP_WATCHDOG:
                                case SERVICE_STOP_SIGTERM:
                                case SERVICE_STOP_SIGKILL:

                                        if (control_pid_good(s) <= 0)
                                                service_enter_stop_post(s, f);

                                        /* If there is still a control process, wait for that first */
                                        break;

                                case SERVICE_STOP_POST:

                                        if (control_pid_good(s) <= 0)
                                                service_enter_signal(s, SERVICE_FINAL_SIGTERM, f);

                                        break;

                                case SERVICE_FINAL_WATCHDOG:
                                case SERVICE_FINAL_SIGTERM:
                                case SERVICE_FINAL_SIGKILL:

                                        if (control_pid_good(s) <= 0)
                                                service_enter_dead(s, f, true);
                                        break;

                                default:
                                        assert_not_reached();
                                }
                        } else if (s->exit_type == SERVICE_EXIT_CGROUP && s->state == SERVICE_START)
                                /* If a main process exits very quickly, this function might be executed
                                 * before service_dispatch_exec_io(). Since this function disabled IO events
                                 * to monitor the main process above, we need to update the state here too.
                                 * Let's consider the process is successfully launched and exited. */
                                service_enter_start_post(s);
                }

        } else if (s->control_pid.pid == pid) {
                const char *kind;
                bool success;

                pidref_done(&s->control_pid);

                if (s->control_command) {
                        exec_status_exit(&s->control_command->exec_status, &s->exec_context, pid, code, status);

                        if (s->control_command->flags & EXEC_COMMAND_IGNORE_FAILURE)
                                f = SERVICE_SUCCESS;
                }

                /* ExecCondition= calls that exit with (0, 254] should invoke skip-like behavior instead of failing */
                if (s->state == SERVICE_CONDITION) {
                        if (f == SERVICE_FAILURE_EXIT_CODE && status < 255) {
                                UNIT(s)->condition_result = false;
                                f = SERVICE_SKIP_CONDITION;
                                success = true;
                        } else if (f == SERVICE_SUCCESS) {
                                UNIT(s)->condition_result = true;
                                success = true;
                        } else
                                success = false;

                        kind = "Condition check process";
                } else {
                        kind = "Control process";
                        success = f == SERVICE_SUCCESS;
                }

                unit_log_process_exit(
                                u,
                                kind,
                                service_exec_command_to_string(s->control_command_id),
                                success,
                                code, status);

                if (s->state != SERVICE_RELOAD && s->result == SERVICE_SUCCESS)
                        s->result = f;

                if (s->control_command &&
                    s->control_command->command_next &&
                    f == SERVICE_SUCCESS) {

                        /* There is another command to * execute, so let's do that. */

                        log_unit_debug(u, "Running next control command for state %s.", service_state_to_string(s->state));
                        service_run_next_control(s);

                } else {
                        /* No further commands for this step, so let's figure out what to do next */

                        s->control_command = NULL;
                        s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;

                        log_unit_debug(u, "Got final SIGCHLD for state %s.", service_state_to_string(s->state));

                        switch (s->state) {

                        case SERVICE_CONDITION:
                                if (f == SERVICE_SUCCESS)
                                        service_enter_start_pre(s);
                                else
                                        service_enter_signal(s, SERVICE_STOP_SIGTERM, f);
                                break;

                        case SERVICE_START_PRE:
                                if (f == SERVICE_SUCCESS)
                                        service_enter_start(s);
                                else
                                        service_enter_signal(s, SERVICE_STOP_SIGTERM, f);
                                break;

                        case SERVICE_START:
                                if (s->type != SERVICE_FORKING)
                                        /* Maybe spurious event due to a reload that changed the type? */
                                        break;

                                if (f != SERVICE_SUCCESS) {
                                        service_enter_signal(s, SERVICE_STOP_SIGTERM, f);
                                        break;
                                }

                                if (s->pid_file) {
                                        bool has_start_post;
                                        int r;

                                        /* Let's try to load the pid file here if we can.
                                         * The PID file might actually be created by a START_POST
                                         * script. In that case don't worry if the loading fails. */

                                        has_start_post = s->exec_command[SERVICE_EXEC_START_POST];
                                        r = service_load_pid_file(s, !has_start_post);
                                        if (!has_start_post && r < 0) {
                                                r = service_demand_pid_file(s);
                                                if (r < 0 || cgroup_good(s) == 0)
                                                        service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_PROTOCOL);
                                                break;
                                        }
                                } else
                                        service_search_main_pid(s);

                                service_enter_start_post(s);
                                break;

                        case SERVICE_START_POST:
                                if (f != SERVICE_SUCCESS) {
                                        service_enter_signal(s, SERVICE_STOP_SIGTERM, f);
                                        break;
                                }

                                if (s->pid_file) {
                                        int r;

                                        r = service_load_pid_file(s, true);
                                        if (r < 0) {
                                                r = service_demand_pid_file(s);
                                                if (r < 0 || cgroup_good(s) == 0)
                                                        service_enter_stop(s, SERVICE_FAILURE_PROTOCOL);
                                                break;
                                        }
                                } else
                                        service_search_main_pid(s);

                                service_enter_running(s, SERVICE_SUCCESS);
                                break;

                        case SERVICE_RELOAD:
                        case SERVICE_RELOAD_SIGNAL:
                        case SERVICE_RELOAD_NOTIFY:
                                if (f == SERVICE_SUCCESS)
                                        if (service_load_pid_file(s, true) < 0)
                                                service_search_main_pid(s);

                                s->reload_result = f;

                                /* If the last notification we received from the service process indicates
                                 * we are still reloading, then don't leave reloading state just yet, just
                                 * transition into SERVICE_RELOAD_NOTIFY, to wait for the READY=1 coming,
                                 * too. */
                                if (s->notify_state == NOTIFY_RELOADING)
                                        service_set_state(s, SERVICE_RELOAD_NOTIFY);
                                else
                                        service_enter_running(s, SERVICE_SUCCESS);
                                break;

                        case SERVICE_STOP:
                                service_enter_signal(s, SERVICE_STOP_SIGTERM, f);
                                break;

                        case SERVICE_STOP_WATCHDOG:
                        case SERVICE_STOP_SIGTERM:
                        case SERVICE_STOP_SIGKILL:
                                if (main_pid_good(s) <= 0)
                                        service_enter_stop_post(s, f);

                                /* If there is still a service process around, wait until
                                 * that one quit, too */
                                break;

                        case SERVICE_STOP_POST:
                                if (main_pid_good(s) <= 0)
                                        service_enter_signal(s, SERVICE_FINAL_SIGTERM, f);
                                break;

                        case SERVICE_FINAL_WATCHDOG:
                        case SERVICE_FINAL_SIGTERM:
                        case SERVICE_FINAL_SIGKILL:
                                if (main_pid_good(s) <= 0)
                                        service_enter_dead(s, f, true);
                                break;

                        case SERVICE_CLEANING:

                                if (s->clean_result == SERVICE_SUCCESS)
                                        s->clean_result = f;

                                service_enter_dead(s, SERVICE_SUCCESS, false);
                                break;

                        default:
                                assert_not_reached();
                        }
                }
        } else /* Neither control nor main PID? If so, don't notify about anything */
                notify_dbus = false;

        /* Notify clients about changed exit status */
        if (notify_dbus)
                unit_add_to_dbus_queue(u);

        /* We watch the main/control process otherwise we can't retrieve the unit they
         * belong to with cgroupv1. But if they are not our direct child, we won't get a
         * SIGCHLD for them. Therefore we need to look for others to watch so we can
         * detect when the cgroup becomes empty. Note that the control process is always
         * our child so it's pointless to watch all other processes. */
        if (!control_pid_good(s))
                if (!s->main_pid_known || s->main_pid_alien)
                        (void) unit_enqueue_rewatch_pids(u);
}

static int service_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata) {
        Service *s = SERVICE(userdata);

        assert(s);
        assert(source == s->timer_event_source);

        switch (s->state) {

        case SERVICE_CONDITION:
        case SERVICE_START_PRE:
        case SERVICE_START:
        case SERVICE_START_POST:
                switch (s->timeout_start_failure_mode) {

                case SERVICE_TIMEOUT_TERMINATE:
                        log_unit_warning(UNIT(s), "%s operation timed out. Terminating.", service_state_to_string(s->state));
                        service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_TIMEOUT);
                        break;

                case SERVICE_TIMEOUT_ABORT:
                        log_unit_warning(UNIT(s), "%s operation timed out. Aborting.", service_state_to_string(s->state));
                        service_enter_signal(s, SERVICE_STOP_WATCHDOG, SERVICE_FAILURE_TIMEOUT);
                        break;

                case SERVICE_TIMEOUT_KILL:
                        if (s->kill_context.send_sigkill) {
                                log_unit_warning(UNIT(s), "%s operation timed out. Killing.", service_state_to_string(s->state));
                                service_enter_signal(s, SERVICE_STOP_SIGKILL, SERVICE_FAILURE_TIMEOUT);
                        } else {
                                log_unit_warning(UNIT(s), "%s operation timed out. Skipping SIGKILL.", service_state_to_string(s->state));
                                service_enter_stop_post(s, SERVICE_FAILURE_TIMEOUT);
                        }
                        break;

                default:
                        assert_not_reached();
                }
                break;

        case SERVICE_RUNNING:
                log_unit_warning(UNIT(s), "Service reached runtime time limit. Stopping.");
                service_enter_stop(s, SERVICE_FAILURE_TIMEOUT);
                break;

        case SERVICE_RELOAD:
        case SERVICE_RELOAD_SIGNAL:
        case SERVICE_RELOAD_NOTIFY:
                log_unit_warning(UNIT(s), "Reload operation timed out. Killing reload process.");
                service_kill_control_process(s);
                s->reload_result = SERVICE_FAILURE_TIMEOUT;
                service_enter_running(s, SERVICE_SUCCESS);
                break;

        case SERVICE_STOP:
                switch (s->timeout_stop_failure_mode) {

                case SERVICE_TIMEOUT_TERMINATE:
                        log_unit_warning(UNIT(s), "Stopping timed out. Terminating.");
                        service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_TIMEOUT);
                        break;

                case SERVICE_TIMEOUT_ABORT:
                        log_unit_warning(UNIT(s), "Stopping timed out. Aborting.");
                        service_enter_signal(s, SERVICE_STOP_WATCHDOG, SERVICE_FAILURE_TIMEOUT);
                        break;

                case SERVICE_TIMEOUT_KILL:
                        if (s->kill_context.send_sigkill) {
                                log_unit_warning(UNIT(s), "Stopping timed out. Killing.");
                                service_enter_signal(s, SERVICE_STOP_SIGKILL, SERVICE_FAILURE_TIMEOUT);
                        } else {
                                log_unit_warning(UNIT(s), "Stopping timed out. Skipping SIGKILL.");
                                service_enter_stop_post(s, SERVICE_FAILURE_TIMEOUT);
                        }
                        break;

                default:
                        assert_not_reached();
                }
                break;

        case SERVICE_STOP_WATCHDOG:
                if (s->kill_context.send_sigkill) {
                        log_unit_warning(UNIT(s), "State 'stop-watchdog' timed out. Killing.");
                        service_enter_signal(s, SERVICE_STOP_SIGKILL, SERVICE_FAILURE_TIMEOUT);
                } else {
                        log_unit_warning(UNIT(s), "State 'stop-watchdog' timed out. Skipping SIGKILL.");
                        service_enter_stop_post(s, SERVICE_FAILURE_TIMEOUT);
                }
                break;

        case SERVICE_STOP_SIGTERM:
                if (s->timeout_stop_failure_mode == SERVICE_TIMEOUT_ABORT) {
                        log_unit_warning(UNIT(s), "State 'stop-sigterm' timed out. Aborting.");
                        service_enter_signal(s, SERVICE_STOP_WATCHDOG, SERVICE_FAILURE_TIMEOUT);
                } else if (s->kill_context.send_sigkill) {
                        log_unit_warning(UNIT(s), "State 'stop-sigterm' timed out. Killing.");
                        service_enter_signal(s, SERVICE_STOP_SIGKILL, SERVICE_FAILURE_TIMEOUT);
                } else {
                        log_unit_warning(UNIT(s), "State 'stop-sigterm' timed out. Skipping SIGKILL.");
                        service_enter_stop_post(s, SERVICE_FAILURE_TIMEOUT);
                }

                break;

        case SERVICE_STOP_SIGKILL:
                /* Uh, we sent a SIGKILL and it is still not gone?
                 * Must be something we cannot kill, so let's just be
                 * weirded out and continue */

                log_unit_warning(UNIT(s), "Processes still around after SIGKILL. Ignoring.");
                service_enter_stop_post(s, SERVICE_FAILURE_TIMEOUT);
                break;

        case SERVICE_STOP_POST:
                switch (s->timeout_stop_failure_mode) {

                case SERVICE_TIMEOUT_TERMINATE:
                        log_unit_warning(UNIT(s), "State 'stop-post' timed out. Terminating.");
                        service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_FAILURE_TIMEOUT);
                        break;

                case SERVICE_TIMEOUT_ABORT:
                        log_unit_warning(UNIT(s), "State 'stop-post' timed out. Aborting.");
                        service_enter_signal(s, SERVICE_FINAL_WATCHDOG, SERVICE_FAILURE_TIMEOUT);
                        break;

                case SERVICE_TIMEOUT_KILL:
                        if (s->kill_context.send_sigkill) {
                                log_unit_warning(UNIT(s), "State 'stop-post' timed out. Killing.");
                                service_enter_signal(s, SERVICE_FINAL_SIGKILL, SERVICE_FAILURE_TIMEOUT);
                        } else {
                                log_unit_warning(UNIT(s), "State 'stop-post' timed out. Skipping SIGKILL. Entering failed mode.");
                                service_enter_dead(s, SERVICE_FAILURE_TIMEOUT, false);
                        }
                        break;

                default:
                        assert_not_reached();
                }
                break;

        case SERVICE_FINAL_WATCHDOG:
                if (s->kill_context.send_sigkill) {
                        log_unit_warning(UNIT(s), "State 'final-watchdog' timed out. Killing.");
                        service_enter_signal(s, SERVICE_FINAL_SIGKILL, SERVICE_FAILURE_TIMEOUT);
                } else {
                        log_unit_warning(UNIT(s), "State 'final-watchdog' timed out. Skipping SIGKILL. Entering failed mode.");
                        service_enter_dead(s, SERVICE_FAILURE_TIMEOUT, false);
                }
                break;

        case SERVICE_FINAL_SIGTERM:
                if (s->timeout_stop_failure_mode == SERVICE_TIMEOUT_ABORT) {
                        log_unit_warning(UNIT(s), "State 'final-sigterm' timed out. Aborting.");
                        service_enter_signal(s, SERVICE_FINAL_WATCHDOG, SERVICE_FAILURE_TIMEOUT);
                } else if (s->kill_context.send_sigkill) {
                        log_unit_warning(UNIT(s), "State 'final-sigterm' timed out. Killing.");
                        service_enter_signal(s, SERVICE_FINAL_SIGKILL, SERVICE_FAILURE_TIMEOUT);
                } else {
                        log_unit_warning(UNIT(s), "State 'final-sigterm' timed out. Skipping SIGKILL. Entering failed mode.");
                        service_enter_dead(s, SERVICE_FAILURE_TIMEOUT, false);
                }

                break;

        case SERVICE_FINAL_SIGKILL:
                log_unit_warning(UNIT(s), "Processes still around after final SIGKILL. Entering failed mode.");
                service_enter_dead(s, SERVICE_FAILURE_TIMEOUT, true);
                break;

        case SERVICE_AUTO_RESTART:
                if (s->restart_usec > 0)
                        log_unit_debug(UNIT(s),
                                       "Service restart interval %s expired, scheduling restart.",
                                       FORMAT_TIMESPAN(service_restart_usec_next(s), USEC_PER_SEC));
                else
                        log_unit_debug(UNIT(s),
                                       "Service has no hold-off time (RestartSec=0), scheduling restart.");

                service_enter_restart(s);
                break;

        case SERVICE_CLEANING:
                log_unit_warning(UNIT(s), "Cleaning timed out. killing.");

                if (s->clean_result == SERVICE_SUCCESS)
                        s->clean_result = SERVICE_FAILURE_TIMEOUT;

                service_enter_signal(s, SERVICE_FINAL_SIGKILL, 0);
                break;

        default:
                assert_not_reached();
        }

        return 0;
}

static int service_dispatch_watchdog(sd_event_source *source, usec_t usec, void *userdata) {
        Service *s = SERVICE(userdata);
        usec_t watchdog_usec;

        assert(s);
        assert(source == s->watchdog_event_source);

        watchdog_usec = service_get_watchdog_usec(s);

        if (UNIT(s)->manager->service_watchdogs) {
                log_unit_error(UNIT(s), "Watchdog timeout (limit %s)!",
                               FORMAT_TIMESPAN(watchdog_usec, 1));

                service_enter_signal(s, SERVICE_STOP_WATCHDOG, SERVICE_FAILURE_WATCHDOG);
        } else
                log_unit_warning(UNIT(s), "Watchdog disabled! Ignoring watchdog timeout (limit %s)!",
                                 FORMAT_TIMESPAN(watchdog_usec, 1));

        return 0;
}

static bool service_notify_message_authorized(Service *s, pid_t pid, FDSet *fds) {
        assert(s);

        NotifyAccess notify_access = service_get_notify_access(s);

        if (notify_access == NOTIFY_NONE) {
                log_unit_warning(UNIT(s), "Got notification message from PID "PID_FMT", but reception is disabled.", pid);
                return false;
        }

        if (notify_access == NOTIFY_MAIN && pid != s->main_pid.pid) {
                if (pidref_is_set(&s->main_pid))
                        log_unit_warning(UNIT(s), "Got notification message from PID "PID_FMT", but reception only permitted for main PID "PID_FMT, pid, s->main_pid.pid);
                else
                        log_unit_warning(UNIT(s), "Got notification message from PID "PID_FMT", but reception only permitted for main PID which is currently not known", pid);

                return false;
        }

        if (notify_access == NOTIFY_EXEC && pid != s->main_pid.pid && pid != s->control_pid.pid) {
                if (pidref_is_set(&s->main_pid) && pidref_is_set(&s->control_pid))
                        log_unit_warning(UNIT(s), "Got notification message from PID "PID_FMT", but reception only permitted for main PID "PID_FMT" and control PID "PID_FMT,
                                         pid, s->main_pid.pid, s->control_pid.pid);
                else if (pidref_is_set(&s->main_pid))
                        log_unit_warning(UNIT(s), "Got notification message from PID "PID_FMT", but reception only permitted for main PID "PID_FMT, pid, s->main_pid.pid);
                else if (pidref_is_set(&s->control_pid))
                        log_unit_warning(UNIT(s), "Got notification message from PID "PID_FMT", but reception only permitted for control PID "PID_FMT, pid, s->control_pid.pid);
                else
                        log_unit_warning(UNIT(s), "Got notification message from PID "PID_FMT", but reception only permitted for main PID and control PID which are currently not known", pid);

                return false;
        }

        return true;
}

static void service_force_watchdog(Service *s) {
        if (!UNIT(s)->manager->service_watchdogs)
                return;

        log_unit_error(UNIT(s), "Watchdog request (last status: %s)!",
                       s->status_text ?: "<unset>");

        service_enter_signal(s, SERVICE_STOP_WATCHDOG, SERVICE_FAILURE_WATCHDOG);
}

static void service_notify_message(
                Unit *u,
                const struct ucred *ucred,
                char * const *tags,
                FDSet *fds) {

        Service *s = SERVICE(u);
        bool notify_dbus = false;
        usec_t monotonic_usec = USEC_INFINITY;
        const char *e;
        int r;

        assert(u);
        assert(ucred);

        if (!service_notify_message_authorized(s, ucred->pid, fds))
                return;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *cc = NULL;

                cc = strv_join(tags, ", ");
                log_unit_debug(u, "Got notification message from PID "PID_FMT" (%s)", ucred->pid, empty_to_na(cc));
        }

        /* Interpret MAINPID= */
        e = strv_find_startswith(tags, "MAINPID=");
        if (e && IN_SET(s->state, SERVICE_START, SERVICE_START_POST, SERVICE_RUNNING, SERVICE_RELOAD, SERVICE_RELOAD_SIGNAL, SERVICE_RELOAD_NOTIFY)) {
                _cleanup_(pidref_done) PidRef new_main_pid = PIDREF_NULL;

                r = pidref_set_pidstr(&new_main_pid, e);
                if (r < 0)
                        log_unit_warning_errno(u, r, "Failed to parse MAINPID=%s field in notification message, ignoring: %m", e);
                else if (!s->main_pid_known || !pidref_equal(&new_main_pid, &s->main_pid)) {

                        r = service_is_suitable_main_pid(s, &new_main_pid, LOG_WARNING);
                        if (r == 0) {
                                /* The new main PID is a bit suspicious, which is OK if the sender is privileged. */

                                if (ucred->uid == 0) {
                                        log_unit_debug(u, "New main PID "PID_FMT" does not belong to service, but we'll accept it as the request to change it came from a privileged process.", new_main_pid.pid);
                                        r = 1;
                                } else
                                        log_unit_debug(u, "New main PID "PID_FMT" does not belong to service, refusing.", new_main_pid.pid);
                        }
                        if (r > 0) {
                                (void) service_set_main_pidref(s, &new_main_pid);

                                r = unit_watch_pidref(UNIT(s), &s->main_pid, /* exclusive= */ false);
                                if (r < 0)
                                        log_unit_warning_errno(UNIT(s), r, "Failed to watch new main PID "PID_FMT" for service: %m", s->main_pid.pid);

                                notify_dbus = true;
                        }
                }
        }

        /* Parse MONOTONIC_USEC= */
        e = strv_find_startswith(tags, "MONOTONIC_USEC=");
        if (e) {
                r = safe_atou64(e, &monotonic_usec);
                if (r < 0)
                        log_unit_warning_errno(u, r, "Failed to parse MONOTONIC_USEC= field in notification message, ignoring: %s", e);
        }

        /* Interpret READY=/STOPPING=/RELOADING=. STOPPING= wins over the others, and READY= over RELOADING= */
        if (strv_contains(tags, "STOPPING=1")) {
                s->notify_state = NOTIFY_STOPPING;

                if (IN_SET(s->state, SERVICE_RUNNING, SERVICE_RELOAD_SIGNAL, SERVICE_RELOAD_NOTIFY))
                        service_enter_stop_by_notify(s);

                notify_dbus = true;

        } else if (strv_contains(tags, "READY=1")) {

                s->notify_state = NOTIFY_READY;

                /* Type=notify services inform us about completed initialization with READY=1 */
                if (IN_SET(s->type, SERVICE_NOTIFY, SERVICE_NOTIFY_RELOAD) &&
                    s->state == SERVICE_START)
                        service_enter_start_post(s);

                /* Sending READY=1 while we are reloading informs us that the reloading is complete. */
                if (s->state == SERVICE_RELOAD_NOTIFY)
                        service_enter_running(s, SERVICE_SUCCESS);

                /* Combined RELOADING=1 and READY=1? Then this is indication that the service started and
                 * immediately finished reloading. */
                if (s->state == SERVICE_RELOAD_SIGNAL &&
                    strv_contains(tags, "RELOADING=1") &&
                    monotonic_usec != USEC_INFINITY &&
                    monotonic_usec >= s->reload_begin_usec) {
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                        /* Propagate a reload explicitly */
                        r = manager_propagate_reload(UNIT(s)->manager, UNIT(s), JOB_FAIL, &error);
                        if (r < 0)
                                log_unit_warning(UNIT(s), "Failed to schedule propagation of reload, ignoring: %s", bus_error_message(&error, r));

                        service_enter_running(s, SERVICE_SUCCESS);
                }

                notify_dbus = true;

        } else if (strv_contains(tags, "RELOADING=1")) {

                s->notify_state = NOTIFY_RELOADING;

                /* Sending RELOADING=1 after we send SIGHUP to request a reload will transition
                 * things to "reload-notify" state, where we'll wait for READY=1 to let us know the
                 * reload is done. Note that we insist on a timestamp being sent along here, so that
                 * we know for sure this is a reload cycle initiated *after* we sent the signal */
                if (s->state == SERVICE_RELOAD_SIGNAL &&
                    monotonic_usec != USEC_INFINITY &&
                    monotonic_usec >= s->reload_begin_usec)
                        /* Note, we don't call service_enter_reload_by_notify() here, because we
                         * don't need reload propagation nor do we want to restart the time-out. */
                        service_set_state(s, SERVICE_RELOAD_NOTIFY);

                if (s->state == SERVICE_RUNNING)
                        service_enter_reload_by_notify(s);

                notify_dbus = true;
        }

        /* Interpret STATUS= */
        e = strv_find_startswith(tags, "STATUS=");
        if (e) {
                _cleanup_free_ char *t = NULL;

                if (!isempty(e)) {
                        /* Note that this size limit check is mostly paranoia: since the datagram size we are willing
                         * to process is already limited to NOTIFY_BUFFER_MAX, this limit here should never be hit. */
                        if (strlen(e) > STATUS_TEXT_MAX)
                                log_unit_warning(u, "Status message overly long (%zu > %u), ignoring.", strlen(e), STATUS_TEXT_MAX);
                        else if (!utf8_is_valid(e))
                                log_unit_warning(u, "Status message in notification message is not UTF-8 clean, ignoring.");
                        else {
                                t = strdup(e);
                                if (!t)
                                        log_oom();
                        }
                }

                if (!streq_ptr(s->status_text, t)) {
                        free_and_replace(s->status_text, t);
                        notify_dbus = true;
                }
        }

        /* Interpret NOTIFYACCESS= */
        e = strv_find_startswith(tags, "NOTIFYACCESS=");
        if (e) {
                NotifyAccess notify_access;

                notify_access = notify_access_from_string(e);
                if (notify_access < 0)
                        log_unit_warning_errno(u, notify_access,
                                               "Failed to parse NOTIFYACCESS= field value '%s' in notification message, ignoring: %m", e);

                /* We don't need to check whether the new access mode is more strict than what is
                 * already in use, since only the privileged process is allowed to change it
                 * in the first place. */
                if (service_get_notify_access(s) != notify_access) {
                        service_override_notify_access(s, notify_access);
                        notify_dbus = true;
                }
        }

        /* Interpret ERRNO= */
        e = strv_find_startswith(tags, "ERRNO=");
        if (e) {
                int status_errno;

                status_errno = parse_errno(e);
                if (status_errno < 0)
                        log_unit_warning_errno(u, status_errno,
                                               "Failed to parse ERRNO= field value '%s' in notification message: %m", e);
                else if (s->status_errno != status_errno) {
                        s->status_errno = status_errno;
                        notify_dbus = true;
                }
        }

        /* Interpret EXTEND_TIMEOUT= */
        e = strv_find_startswith(tags, "EXTEND_TIMEOUT_USEC=");
        if (e) {
                usec_t extend_timeout_usec;
                if (safe_atou64(e, &extend_timeout_usec) < 0)
                        log_unit_warning(u, "Failed to parse EXTEND_TIMEOUT_USEC=%s", e);
                else
                        service_extend_timeout(s, extend_timeout_usec);
        }

        /* Interpret WATCHDOG= */
        e = strv_find_startswith(tags, "WATCHDOG=");
        if (e) {
                if (streq(e, "1"))
                        service_reset_watchdog(s);
                else if (streq(e, "trigger"))
                        service_force_watchdog(s);
                else
                        log_unit_warning(u, "Passed WATCHDOG= field is invalid, ignoring.");
        }

        e = strv_find_startswith(tags, "WATCHDOG_USEC=");
        if (e) {
                usec_t watchdog_override_usec;
                if (safe_atou64(e, &watchdog_override_usec) < 0)
                        log_unit_warning(u, "Failed to parse WATCHDOG_USEC=%s", e);
                else
                        service_override_watchdog_timeout(s, watchdog_override_usec);
        }

        /* Process FD store messages. Either FDSTOREREMOVE=1 for removal, or FDSTORE=1 for addition. In both cases,
         * process FDNAME= for picking the file descriptor name to use. Note that FDNAME= is required when removing
         * fds, but optional when pushing in new fds, for compatibility reasons. */
        if (strv_contains(tags, "FDSTOREREMOVE=1")) {
                const char *name;

                name = strv_find_startswith(tags, "FDNAME=");
                if (!name || !fdname_is_valid(name))
                        log_unit_warning(u, "FDSTOREREMOVE=1 requested, but no valid file descriptor name passed, ignoring.");
                else
                        service_remove_fd_store(s, name);

        } else if (strv_contains(tags, "FDSTORE=1")) {
                const char *name;

                name = strv_find_startswith(tags, "FDNAME=");
                if (name && !fdname_is_valid(name)) {
                        log_unit_warning(u, "Passed FDNAME= name is invalid, ignoring.");
                        name = NULL;
                }

                (void) service_add_fd_store_set(s, fds, name, !strv_contains(tags, "FDPOLL=0"));
        }

        /* Notify clients about changed status or main pid */
        if (notify_dbus)
                unit_add_to_dbus_queue(u);
}

static int service_get_timeout(Unit *u, usec_t *timeout) {
        Service *s = SERVICE(u);
        uint64_t t;
        int r;

        if (!s->timer_event_source)
                return 0;

        r = sd_event_source_get_time(s->timer_event_source, &t);
        if (r < 0)
                return r;
        if (t == USEC_INFINITY)
                return 0;

        *timeout = t;
        return 1;
}

static usec_t service_get_timeout_start_usec(Unit *u) {
        Service *s = SERVICE(ASSERT_PTR(u));
        return s->timeout_start_usec;
}

static bool pick_up_pid_from_bus_name(Service *s) {
        assert(s);

        /* If the service is running but we have no main PID yet, get it from the owner of the D-Bus name */

        return !pidref_is_set(&s->main_pid) &&
                IN_SET(s->state,
                       SERVICE_START,
                       SERVICE_START_POST,
                       SERVICE_RUNNING,
                       SERVICE_RELOAD,
                       SERVICE_RELOAD_SIGNAL,
                       SERVICE_RELOAD_NOTIFY);
}

static int bus_name_pid_lookup_callback(sd_bus_message *reply, void *userdata, sd_bus_error *ret_error) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        const sd_bus_error *e;
        Unit *u = ASSERT_PTR(userdata);
        uint32_t pid;
        Service *s;
        int r;

        assert(reply);

        s = SERVICE(u);
        s->bus_name_pid_lookup_slot = sd_bus_slot_unref(s->bus_name_pid_lookup_slot);

        if (!s->bus_name || !pick_up_pid_from_bus_name(s))
                return 1;

        e = sd_bus_message_get_error(reply);
        if (e) {
                r = sd_bus_error_get_errno(e);
                log_warning_errno(r, "GetConnectionUnixProcessID() failed: %s", bus_error_message(e, r));
                return 1;
        }

        r = sd_bus_message_read(reply, "u", &pid);
        if (r < 0) {
                bus_log_parse_error(r);
                return 1;
        }

        r = pidref_set_pid(&pidref, pid);
        if (r < 0) {
                log_debug_errno(r, "GetConnectionUnixProcessID() returned invalid PID: %m");
                return 1;
        }

        log_unit_debug(u, "D-Bus name %s is now owned by process " PID_FMT, s->bus_name, pidref.pid);

        (void) service_set_main_pidref(s, &pidref);
        (void) unit_watch_pidref(UNIT(s), &s->main_pid, /* exclusive= */ false);
        return 1;
}

static void service_bus_name_owner_change(Unit *u, const char *new_owner) {

        Service *s = SERVICE(u);
        int r;

        assert(s);

        if (new_owner)
                log_unit_debug(u, "D-Bus name %s now owned by %s", s->bus_name, new_owner);
        else
                log_unit_debug(u, "D-Bus name %s now not owned by anyone.", s->bus_name);

        s->bus_name_good = new_owner;

        /* Track the current owner, so we can reconstruct changes after a daemon reload */
        r = free_and_strdup(&s->bus_name_owner, new_owner);
        if (r < 0) {
                log_unit_error_errno(u, r, "Unable to set new bus name owner %s: %m", new_owner);
                return;
        }

        if (s->type == SERVICE_DBUS) {

                /* service_enter_running() will figure out what to
                 * do */
                if (s->state == SERVICE_RUNNING)
                        service_enter_running(s, SERVICE_SUCCESS);
                else if (s->state == SERVICE_START && new_owner)
                        service_enter_start_post(s);

        } else if (new_owner && pick_up_pid_from_bus_name(s)) {

                /* Try to acquire PID from bus service */

                s->bus_name_pid_lookup_slot = sd_bus_slot_unref(s->bus_name_pid_lookup_slot);

                r = sd_bus_call_method_async(
                                u->manager->api_bus,
                                &s->bus_name_pid_lookup_slot,
                                "org.freedesktop.DBus",
                                "/org/freedesktop/DBus",
                                "org.freedesktop.DBus",
                                "GetConnectionUnixProcessID",
                                bus_name_pid_lookup_callback,
                                s,
                                "s",
                                s->bus_name);
                if (r < 0)
                        log_debug_errno(r, "Failed to request owner PID of service name, ignoring: %m");
        }
}

int service_set_socket_fd(
                Service *s,
                int fd,
                Socket *sock,
                SocketPeer *peer,
                bool selinux_context_net) {

        _cleanup_free_ char *peer_text = NULL;
        int r;

        assert(s);
        assert(fd >= 0);

        /* This is called by the socket code when instantiating a new service for a stream socket and the socket needs
         * to be configured. We take ownership of the passed fd on success. */

        if (UNIT(s)->load_state != UNIT_LOADED)
                return -EINVAL;

        if (s->socket_fd >= 0)
                return -EBUSY;

        assert(!s->socket_peer);

        if (!IN_SET(s->state, SERVICE_DEAD, SERVICE_DEAD_RESOURCES_PINNED))
                return -EAGAIN;

        if (getpeername_pretty(fd, true, &peer_text) >= 0) {

                if (UNIT(s)->description) {
                        _cleanup_free_ char *a = NULL;

                        a = strjoin(UNIT(s)->description, " (", peer_text, ")");
                        if (!a)
                                return -ENOMEM;

                        r = unit_set_description(UNIT(s), a);
                }  else
                        r = unit_set_description(UNIT(s), peer_text);
                if (r < 0)
                        return r;
        }

        r = unit_add_two_dependencies(UNIT(sock), UNIT_BEFORE, UNIT_TRIGGERS, UNIT(s), false, UNIT_DEPENDENCY_IMPLICIT);
        if (r < 0)
                return r;

        s->socket_fd = fd;
        s->socket_peer = socket_peer_ref(peer);
        s->socket_fd_selinux_context_net = selinux_context_net;

        unit_ref_set(&s->accept_socket, UNIT(s), UNIT(sock));
        return 0;
}

static void service_reset_failed(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        if (s->state == SERVICE_FAILED)
                service_set_state(s, service_determine_dead_state(s));

        s->result = SERVICE_SUCCESS;
        s->reload_result = SERVICE_SUCCESS;
        s->clean_result = SERVICE_SUCCESS;
        s->n_restarts = 0;
        s->flush_n_restarts = false;
}

static PidRef* service_main_pid(Unit *u) {
        return &ASSERT_PTR(SERVICE(u))->main_pid;
}

static PidRef* service_control_pid(Unit *u) {
        return &ASSERT_PTR(SERVICE(u))->control_pid;
}

static bool service_needs_console(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        /* We provide our own implementation of this here, instead of relying of the generic implementation
         * unit_needs_console() provides, since we want to return false if we are in SERVICE_EXITED state. */

        if (!exec_context_may_touch_console(&s->exec_context))
                return false;

        return IN_SET(s->state,
                      SERVICE_CONDITION,
                      SERVICE_START_PRE,
                      SERVICE_START,
                      SERVICE_START_POST,
                      SERVICE_RUNNING,
                      SERVICE_RELOAD,
                      SERVICE_RELOAD_SIGNAL,
                      SERVICE_RELOAD_NOTIFY,
                      SERVICE_STOP,
                      SERVICE_STOP_WATCHDOG,
                      SERVICE_STOP_SIGTERM,
                      SERVICE_STOP_SIGKILL,
                      SERVICE_STOP_POST,
                      SERVICE_FINAL_WATCHDOG,
                      SERVICE_FINAL_SIGTERM,
                      SERVICE_FINAL_SIGKILL);
}

static int service_exit_status(Unit *u) {
        Service *s = SERVICE(u);

        assert(u);

        if (s->main_exec_status.pid <= 0 ||
            !dual_timestamp_is_set(&s->main_exec_status.exit_timestamp))
                return -ENODATA;

        if (s->main_exec_status.code != CLD_EXITED)
                return -EBADE;

        return s->main_exec_status.status;
}

static const char* service_status_text(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        return s->status_text;
}

static int service_clean(Unit *u, ExecCleanMask mask) {
        _cleanup_strv_free_ char **l = NULL;
        bool may_clean_fdstore = false;
        Service *s = SERVICE(u);
        int r;

        assert(s);
        assert(mask != 0);

        if (!IN_SET(s->state, SERVICE_DEAD, SERVICE_DEAD_RESOURCES_PINNED))
                return -EBUSY;

        /* Determine if there's anything we could potentially clean */
        r = exec_context_get_clean_directories(&s->exec_context, u->manager->prefix, mask, &l);
        if (r < 0)
                return r;

        if (mask & EXEC_CLEAN_FDSTORE)
                may_clean_fdstore = s->n_fd_store > 0 || s->n_fd_store_max > 0;

        if (strv_isempty(l) && !may_clean_fdstore)
                return -EUNATCH; /* Nothing to potentially clean */

        /* Let's clean the stuff we can clean quickly */
        if (may_clean_fdstore)
                service_release_fd_store(s);

        /* If we are done, leave quickly */
        if (strv_isempty(l)) {
                if (s->state == SERVICE_DEAD_RESOURCES_PINNED && !s->fd_store)
                        service_set_state(s, SERVICE_DEAD);
                return 0;
        }

        /* We need to clean disk stuff. This is slow, hence do it out of process, and change state */
        service_unwatch_control_pid(s);
        s->clean_result = SERVICE_SUCCESS;
        s->control_command = NULL;
        s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;

        r = service_arm_timer(s, /* relative= */ true, s->exec_context.timeout_clean_usec);
        if (r < 0) {
                log_unit_warning_errno(u, r, "Failed to install timer: %m");
                goto fail;
        }

        r = unit_fork_and_watch_rm_rf(u, l, &s->control_pid);
        if (r < 0) {
                log_unit_warning_errno(u, r, "Failed to spawn cleaning task: %m");
                goto fail;
        }

        service_set_state(s, SERVICE_CLEANING);
        return 0;

fail:
        s->clean_result = SERVICE_FAILURE_RESOURCES;
        s->timer_event_source = sd_event_source_disable_unref(s->timer_event_source);
        return r;
}

static int service_can_clean(Unit *u, ExecCleanMask *ret) {
        Service *s = SERVICE(u);
        ExecCleanMask mask = 0;
        int r;

        assert(s);
        assert(ret);

        r = exec_context_get_clean_mask(&s->exec_context, &mask);
        if (r < 0)
                return r;

        if (s->n_fd_store_max > 0)
                mask |= EXEC_CLEAN_FDSTORE;

        *ret = mask;
        return 0;
}

static const char *service_finished_job(Unit *u, JobType t, JobResult result) {
        if (t == JOB_START &&
            result == JOB_DONE &&
            SERVICE(u)->type == SERVICE_ONESHOT)
                return "Finished %s.";

        /* Fall back to generic */
        return NULL;
}

static int service_can_start(Unit *u) {
        Service *s = SERVICE(u);
        int r;

        assert(s);

        /* Make sure we don't enter a busy loop of some kind. */
        r = unit_test_start_limit(u);
        if (r < 0) {
                service_enter_dead(s, SERVICE_FAILURE_START_LIMIT_HIT, false);
                return r;
        }

        return 1;
}

static void service_release_resources(Unit *u) {
        Service *s = SERVICE(ASSERT_PTR(u));

        /* Invoked by the unit state engine, whenever it realizes that unit is dead and there's no job
         * anymore for it, and it hence is a good idea to release resources */

        /* Don't release resources if this is a transitionary failed/dead state
         * (i.e. SERVICE_DEAD_BEFORE_AUTO_RESTART/SERVICE_FAILED_BEFORE_AUTO_RESTART), insist on a permanent
         * failure state. */
        if (!IN_SET(s->state, SERVICE_DEAD, SERVICE_FAILED, SERVICE_DEAD_RESOURCES_PINNED))
                return;

        log_unit_debug(u, "Releasing resources...");

        service_release_socket_fd(s);
        service_release_stdio_fd(s);

        if (s->fd_store_preserve_mode != EXEC_PRESERVE_YES)
                service_release_fd_store(s);

        if (s->state == SERVICE_DEAD_RESOURCES_PINNED && !s->fd_store)
                service_set_state(s, SERVICE_DEAD);
}

int service_determine_exec_selinux_label(Service *s, char **ret) {
        int r;

        assert(s);
        assert(ret);

        if (!mac_selinux_use())
                return -ENODATA;

        /* Returns the SELinux label used for execution of the main service binary */

        if (s->exec_context.selinux_context) { /* Prefer the explicitly configured label if there is one */
                char *con = strdup(s->exec_context.selinux_context);
                if (!con)
                        return -ENOMEM;

                *ret = con;
                return 0;
        }

        if (s->exec_context.root_image ||
            s->exec_context.n_extension_images > 0 ||
            !strv_isempty(s->exec_context.extension_directories)) /* We cannot chase paths through images */
                return log_unit_debug_errno(UNIT(s), SYNTHETIC_ERRNO(ENODATA), "Service with RootImage=, ExtensionImages= or ExtensionDirectories= set, cannot determine socket SELinux label before activation, ignoring.");

        ExecCommand *c = s->exec_command[SERVICE_EXEC_START];
        if (!c)
                return -ENODATA;

        _cleanup_free_ char *path = NULL;
        r = chase(c->path, s->exec_context.root_directory, CHASE_PREFIX_ROOT, &path, NULL);
        if (r < 0) {
                log_unit_debug_errno(UNIT(s), r, "Failed to resolve service binary '%s', ignoring.", c->path);
                return -ENODATA;
        }

        r = mac_selinux_get_create_label_from_exe(path, ret);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r)) {
                log_unit_debug_errno(UNIT(s), r, "Reading SELinux label off binary '%s' is not supported, ignoring.", path);
                return -ENODATA;
        }
        if (ERRNO_IS_NEG_PRIVILEGE(r)) {
                log_unit_debug_errno(UNIT(s), r, "Can't read SELinux label off binary '%s', due to privileges, ignoring.", path);
                return -ENODATA;
        }
        if (r < 0)
                return log_unit_debug_errno(UNIT(s), r, "Failed to read SELinux label off binary '%s': %m", path);

        return 0;
}

static const char* const service_restart_table[_SERVICE_RESTART_MAX] = {
        [SERVICE_RESTART_NO]          = "no",
        [SERVICE_RESTART_ON_SUCCESS]  = "on-success",
        [SERVICE_RESTART_ON_FAILURE]  = "on-failure",
        [SERVICE_RESTART_ON_ABNORMAL] = "on-abnormal",
        [SERVICE_RESTART_ON_WATCHDOG] = "on-watchdog",
        [SERVICE_RESTART_ON_ABORT]    = "on-abort",
        [SERVICE_RESTART_ALWAYS]      = "always",
};

DEFINE_STRING_TABLE_LOOKUP(service_restart, ServiceRestart);

static const char* const service_restart_mode_table[_SERVICE_RESTART_MODE_MAX] = {
        [SERVICE_RESTART_MODE_NORMAL] = "normal",
        [SERVICE_RESTART_MODE_DIRECT]  = "direct",
};

DEFINE_STRING_TABLE_LOOKUP(service_restart_mode, ServiceRestartMode);

static const char* const service_type_table[_SERVICE_TYPE_MAX] = {
        [SERVICE_SIMPLE]        = "simple",
        [SERVICE_FORKING]       = "forking",
        [SERVICE_ONESHOT]       = "oneshot",
        [SERVICE_DBUS]          = "dbus",
        [SERVICE_NOTIFY]        = "notify",
        [SERVICE_NOTIFY_RELOAD] = "notify-reload",
        [SERVICE_IDLE]          = "idle",
        [SERVICE_EXEC]          = "exec",
};

DEFINE_STRING_TABLE_LOOKUP(service_type, ServiceType);

static const char* const service_exit_type_table[_SERVICE_EXIT_TYPE_MAX] = {
        [SERVICE_EXIT_MAIN]   = "main",
        [SERVICE_EXIT_CGROUP] = "cgroup",
};

DEFINE_STRING_TABLE_LOOKUP(service_exit_type, ServiceExitType);

static const char* const service_exec_command_table[_SERVICE_EXEC_COMMAND_MAX] = {
        [SERVICE_EXEC_CONDITION]  = "ExecCondition",
        [SERVICE_EXEC_START_PRE]  = "ExecStartPre",
        [SERVICE_EXEC_START]      = "ExecStart",
        [SERVICE_EXEC_START_POST] = "ExecStartPost",
        [SERVICE_EXEC_RELOAD]     = "ExecReload",
        [SERVICE_EXEC_STOP]       = "ExecStop",
        [SERVICE_EXEC_STOP_POST]  = "ExecStopPost",
};

DEFINE_STRING_TABLE_LOOKUP(service_exec_command, ServiceExecCommand);

static const char* const service_exec_ex_command_table[_SERVICE_EXEC_COMMAND_MAX] = {
        [SERVICE_EXEC_CONDITION]  = "ExecConditionEx",
        [SERVICE_EXEC_START_PRE]  = "ExecStartPreEx",
        [SERVICE_EXEC_START]      = "ExecStartEx",
        [SERVICE_EXEC_START_POST] = "ExecStartPostEx",
        [SERVICE_EXEC_RELOAD]     = "ExecReloadEx",
        [SERVICE_EXEC_STOP]       = "ExecStopEx",
        [SERVICE_EXEC_STOP_POST]  = "ExecStopPostEx",
};

DEFINE_STRING_TABLE_LOOKUP(service_exec_ex_command, ServiceExecCommand);

static const char* const notify_state_table[_NOTIFY_STATE_MAX] = {
        [NOTIFY_UNKNOWN]   = "unknown",
        [NOTIFY_READY]     = "ready",
        [NOTIFY_RELOADING] = "reloading",
        [NOTIFY_STOPPING]  = "stopping",
};

DEFINE_STRING_TABLE_LOOKUP(notify_state, NotifyState);

static const char* const service_result_table[_SERVICE_RESULT_MAX] = {
        [SERVICE_SUCCESS]                 = "success",
        [SERVICE_FAILURE_RESOURCES]       = "resources",
        [SERVICE_FAILURE_PROTOCOL]        = "protocol",
        [SERVICE_FAILURE_TIMEOUT]         = "timeout",
        [SERVICE_FAILURE_EXIT_CODE]       = "exit-code",
        [SERVICE_FAILURE_SIGNAL]          = "signal",
        [SERVICE_FAILURE_CORE_DUMP]       = "core-dump",
        [SERVICE_FAILURE_WATCHDOG]        = "watchdog",
        [SERVICE_FAILURE_START_LIMIT_HIT] = "start-limit-hit",
        [SERVICE_FAILURE_OOM_KILL]        = "oom-kill",
        [SERVICE_SKIP_CONDITION]          = "exec-condition",
};

DEFINE_STRING_TABLE_LOOKUP(service_result, ServiceResult);

static const char* const service_timeout_failure_mode_table[_SERVICE_TIMEOUT_FAILURE_MODE_MAX] = {
        [SERVICE_TIMEOUT_TERMINATE] = "terminate",
        [SERVICE_TIMEOUT_ABORT]     = "abort",
        [SERVICE_TIMEOUT_KILL]      = "kill",
};

DEFINE_STRING_TABLE_LOOKUP(service_timeout_failure_mode, ServiceTimeoutFailureMode);

const UnitVTable service_vtable = {
        .object_size = sizeof(Service),
        .exec_context_offset = offsetof(Service, exec_context),
        .cgroup_context_offset = offsetof(Service, cgroup_context),
        .kill_context_offset = offsetof(Service, kill_context),
        .exec_runtime_offset = offsetof(Service, exec_runtime),

        .sections =
                "Unit\0"
                "Service\0"
                "Install\0",
        .private_section = "Service",

        .can_transient = true,
        .can_delegate = true,
        .can_fail = true,
        .can_set_managed_oom = true,

        .init = service_init,
        .done = service_done,
        .load = service_load,
        .release_resources = service_release_resources,

        .coldplug = service_coldplug,

        .dump = service_dump,

        .start = service_start,
        .stop = service_stop,
        .reload = service_reload,

        .can_reload = service_can_reload,

        .clean = service_clean,
        .can_clean = service_can_clean,

        .freeze = unit_freeze_vtable_common,
        .thaw = unit_thaw_vtable_common,

        .serialize = service_serialize,
        .deserialize_item = service_deserialize_item,

        .active_state = service_active_state,
        .sub_state_to_string = service_sub_state_to_string,

        .will_restart = service_will_restart,

        .may_gc = service_may_gc,

        .sigchld_event = service_sigchld_event,

        .reset_failed = service_reset_failed,

        .notify_cgroup_empty = service_notify_cgroup_empty_event,
        .notify_cgroup_oom = service_notify_cgroup_oom_event,
        .notify_message = service_notify_message,

        .main_pid = service_main_pid,
        .control_pid = service_control_pid,

        .bus_name_owner_change = service_bus_name_owner_change,

        .bus_set_property = bus_service_set_property,
        .bus_commit_properties = bus_service_commit_properties,

        .get_timeout = service_get_timeout,
        .get_timeout_start_usec = service_get_timeout_start_usec,
        .needs_console = service_needs_console,
        .exit_status = service_exit_status,
        .status_text = service_status_text,

        .status_message_formats = {
                .finished_start_job = {
                        [JOB_FAILED]     = "Failed to start %s.",
                },
                .finished_stop_job = {
                        [JOB_DONE]       = "Stopped %s.",
                        [JOB_FAILED]     = "Stopped (with error) %s.",
                },
                .finished_job = service_finished_job,
        },

        .can_start = service_can_start,

        .notify_plymouth = true,

        .audit_start_message_type = AUDIT_SERVICE_START,
        .audit_stop_message_type = AUDIT_SERVICE_STOP,
};
