/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "async.h"
#include "bus-error.h"
#include "bus-kernel.h"
#include "bus-util.h"
#include "dbus-service.h"
#include "dbus-unit.h"
#include "def.h"
#include "env-util.h"
#include "escape.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "load-dropin.h"
#include "load-fragment.h"
#include "log.h"
#include "manager.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
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
#include "util.h"

static const UnitActiveState state_translation_table[_SERVICE_STATE_MAX] = {
        [SERVICE_DEAD] = UNIT_INACTIVE,
        [SERVICE_CONDITION] = UNIT_ACTIVATING,
        [SERVICE_START_PRE] = UNIT_ACTIVATING,
        [SERVICE_START] = UNIT_ACTIVATING,
        [SERVICE_START_POST] = UNIT_ACTIVATING,
        [SERVICE_RUNNING] = UNIT_ACTIVE,
        [SERVICE_EXITED] = UNIT_ACTIVE,
        [SERVICE_RELOAD] = UNIT_RELOADING,
        [SERVICE_STOP] = UNIT_DEACTIVATING,
        [SERVICE_STOP_WATCHDOG] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_STOP_POST] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_FAILED] = UNIT_FAILED,
        [SERVICE_AUTO_RESTART] = UNIT_ACTIVATING,
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
        [SERVICE_STOP] = UNIT_DEACTIVATING,
        [SERVICE_STOP_WATCHDOG] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_STOP_POST] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_FAILED] = UNIT_FAILED,
        [SERVICE_AUTO_RESTART] = UNIT_ACTIVATING,
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

        s->timeout_start_usec = u->manager->default_timeout_start_usec;
        s->timeout_stop_usec = u->manager->default_timeout_stop_usec;
        s->timeout_abort_usec = u->manager->default_timeout_abort_usec;
        s->timeout_abort_set = u->manager->default_timeout_abort_set;
        s->restart_usec = u->manager->default_restart_usec;
        s->runtime_max_usec = USEC_INFINITY;
        s->type = _SERVICE_TYPE_INVALID;
        s->socket_fd = -1;
        s->stdin_fd = s->stdout_fd = s->stderr_fd = -1;
        s->guess_main_pid = true;

        s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;

        s->exec_context.keyring_mode = MANAGER_IS_SYSTEM(u->manager) ?
                EXEC_KEYRING_PRIVATE : EXEC_KEYRING_INHERIT;

        s->watchdog_original_usec = USEC_INFINITY;

        s->oom_policy = _OOM_POLICY_INVALID;
}

static void service_unwatch_control_pid(Service *s) {
        assert(s);

        if (s->control_pid <= 0)
                return;

        unit_unwatch_pid(UNIT(s), s->control_pid);
        s->control_pid = 0;
}

static void service_unwatch_main_pid(Service *s) {
        assert(s);

        if (s->main_pid <= 0)
                return;

        unit_unwatch_pid(UNIT(s), s->main_pid);
        s->main_pid = 0;
}

static void service_unwatch_pid_file(Service *s) {
        if (!s->pid_file_pathspec)
                return;

        log_unit_debug(UNIT(s), "Stopping watch for PID file %s", s->pid_file_pathspec->path);
        path_spec_unwatch(s->pid_file_pathspec);
        path_spec_done(s->pid_file_pathspec);
        s->pid_file_pathspec = mfree(s->pid_file_pathspec);
}

static int service_set_main_pid(Service *s, pid_t pid) {
        assert(s);

        if (pid <= 1)
                return -EINVAL;

        if (pid == getpid_cached())
                return -EINVAL;

        if (s->main_pid == pid && s->main_pid_known)
                return 0;

        if (s->main_pid != pid) {
                service_unwatch_main_pid(s);
                exec_status_start(&s->main_exec_status, pid);
        }

        s->main_pid = pid;
        s->main_pid_known = true;
        s->main_pid_alien = pid_is_my_child(pid) == 0;

        if (s->main_pid_alien)
                log_unit_warning(UNIT(s), "Supervising process "PID_FMT" which is not our child. We'll most likely not notice when it exits.", pid);

        return 0;
}

void service_close_socket_fd(Service *s) {
        assert(s);

        /* Undo the effect of service_set_socket_fd(). */

        s->socket_fd = asynchronous_close(s->socket_fd);

        if (UNIT_ISSET(s->accept_socket)) {
                socket_connection_unref(SOCKET(UNIT_DEREF(s->accept_socket)));
                unit_ref_unset(&s->accept_socket);
        }
}

static void service_stop_watchdog(Service *s) {
        assert(s);

        s->watchdog_event_source = sd_event_source_unref(s->watchdog_event_source);
        s->watchdog_timestamp = DUAL_TIMESTAMP_NULL;
}

static usec_t service_get_watchdog_usec(Service *s) {
        assert(s);

        if (s->watchdog_override_enable)
                return s->watchdog_override_usec;

        return s->watchdog_original_usec;
}

static void service_start_watchdog(Service *s) {
        usec_t watchdog_usec;
        int r;

        assert(s);

        watchdog_usec = service_get_watchdog_usec(s);
        if (IN_SET(watchdog_usec, 0, USEC_INFINITY)) {
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
                log_unit_warning_errno(UNIT(s), r, "Failed to set timeout time for even source '%s', ignoring %m", strna(desc));
        }
}

static void service_extend_timeout(Service *s, usec_t extend_timeout_usec) {
        usec_t extended;

        assert(s);

        if (IN_SET(extend_timeout_usec, 0, USEC_INFINITY))
                return;

        extended = usec_add(now(CLOCK_MONOTONIC), extend_timeout_usec);

        service_extend_event_source_timeout(s, s->timer_event_source, extended);
        service_extend_event_source_timeout(s, s->watchdog_event_source, extended);
}

static void service_reset_watchdog(Service *s) {
        assert(s);

        dual_timestamp_get(&s->watchdog_timestamp);
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

static void service_fd_store_unlink(ServiceFDStore *fs) {

        if (!fs)
                return;

        if (fs->service) {
                assert(fs->service->n_fd_store > 0);
                LIST_REMOVE(fd_store, fs->service->fd_store, fs);
                fs->service->n_fd_store--;
        }

        sd_event_source_disable_unref(fs->event_source);

        free(fs->fdname);
        safe_close(fs->fd);
        free(fs);
}

static void service_release_fd_store(Service *s) {
        assert(s);

        if (s->n_keep_fd_store > 0)
                return;

        log_unit_debug(UNIT(s), "Releasing all stored fds");
        while (s->fd_store)
                service_fd_store_unlink(s->fd_store);

        assert(s->n_fd_store == 0);
}

static void service_release_resources(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        if (!s->fd_store && s->stdin_fd < 0 && s->stdout_fd < 0 && s->stderr_fd < 0)
                return;

        log_unit_debug(u, "Releasing resources.");

        s->stdin_fd = safe_close(s->stdin_fd);
        s->stdout_fd = safe_close(s->stdout_fd);
        s->stderr_fd = safe_close(s->stderr_fd);

        service_release_fd_store(s);
}

static void service_done(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        s->pid_file = mfree(s->pid_file);
        s->status_text = mfree(s->status_text);

        s->exec_runtime = exec_runtime_unref(s->exec_runtime, false);
        exec_command_free_array(s->exec_command, _SERVICE_EXEC_COMMAND_MAX);
        s->control_command = NULL;
        s->main_command = NULL;

        dynamic_creds_unref(&s->dynamic_creds);

        exit_status_set_free(&s->restart_prevent_status);
        exit_status_set_free(&s->restart_force_status);
        exit_status_set_free(&s->success_status);

        /* This will leak a process, but at least no memory or any of
         * our resources */
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

        service_close_socket_fd(s);
        s->peer = socket_peer_unref(s->peer);

        unit_ref_unset(&s->accept_socket);

        service_stop_watchdog(s);

        s->timer_event_source = sd_event_source_unref(s->timer_event_source);
        s->exec_fd_event_source = sd_event_source_unref(s->exec_fd_event_source);

        service_release_resources(u);
}

static int on_fd_store_io(sd_event_source *e, int fd, uint32_t revents, void *userdata) {
        ServiceFDStore *fs = userdata;

        assert(e);
        assert(fs);

        /* If we get either EPOLLHUP or EPOLLERR, it's time to remove this entry from the fd store */
        log_unit_debug(UNIT(fs->service),
                       "Received %s on stored fd %d (%s), closing.",
                       revents & EPOLLERR ? "EPOLLERR" : "EPOLLHUP",
                       fs->fd, strna(fs->fdname));
        service_fd_store_unlink(fs);
        return 0;
}

static int service_add_fd_store(Service *s, int fd, const char *name) {
        ServiceFDStore *fs;
        int r;

        /* fd is always consumed if we return >= 0 */

        assert(s);
        assert(fd >= 0);

        if (s->n_fd_store >= s->n_fd_store_max)
                return -EXFULL; /* Our store is full.
                                 * Use this errno rather than E[NM]FILE to distinguish from
                                 * the case where systemd itself hits the file limit. */

        LIST_FOREACH(fd_store, fs, s->fd_store) {
                r = same_fd(fs->fd, fd);
                if (r < 0)
                        return r;
                if (r > 0) {
                        safe_close(fd);
                        return 0; /* fd already included */
                }
        }

        fs = new0(ServiceFDStore, 1);
        if (!fs)
                return -ENOMEM;

        fs->fd = fd;
        fs->service = s;
        fs->fdname = strdup(name ?: "stored");
        if (!fs->fdname) {
                free(fs);
                return -ENOMEM;
        }

        r = sd_event_add_io(UNIT(s)->manager->event, &fs->event_source, fd, 0, on_fd_store_io, fs);
        if (r < 0 && r != -EPERM) { /* EPERM indicates fds that aren't pollable, which is OK */
                free(fs->fdname);
                free(fs);
                return r;
        } else if (r >= 0)
                (void) sd_event_source_set_description(fs->event_source, "service-fd-store");

        LIST_PREPEND(fd_store, s->fd_store, fs);
        s->n_fd_store++;

        return 1; /* fd newly stored */
}

static int service_add_fd_store_set(Service *s, FDSet *fds, const char *name) {
        int r;

        assert(s);

        while (fdset_size(fds) > 0) {
                _cleanup_close_ int fd = -1;

                fd = fdset_steal_first(fds);
                if (fd < 0)
                        break;

                r = service_add_fd_store(s, fd, name);
                if (r == -EXFULL)
                        return log_unit_warning_errno(UNIT(s), r,
                                                      "Cannot store more fds than FileDescriptorStoreMax=%u, closing remaining.",
                                                      s->n_fd_store_max);
                if (r < 0)
                        return log_unit_error_errno(UNIT(s), r, "Failed to add fd to store: %m");
                if (r > 0)
                        log_unit_debug(UNIT(s), "Added fd %u (%s) to fd store.", fd, strna(name));
                fd = -1;
        }

        return 0;
}

static void service_remove_fd_store(Service *s, const char *name) {
        ServiceFDStore *fs, *n;

        assert(s);
        assert(name);

        LIST_FOREACH_SAFE(fd_store, fs, n, s->fd_store) {
                if (!streq(fs->fdname, name))
                        continue;

                log_unit_debug(UNIT(s), "Got explicit request to remove fd %i (%s), closing.", fs->fd, name);
                service_fd_store_unlink(fs);
        }
}

static int service_arm_timer(Service *s, usec_t usec) {
        int r;

        assert(s);

        if (s->timer_event_source) {
                r = sd_event_source_set_time(s->timer_event_source, usec);
                if (r < 0)
                        return r;

                return sd_event_source_set_enabled(s->timer_event_source, SD_EVENT_ONESHOT);
        }

        if (usec == USEC_INFINITY)
                return 0;

        r = sd_event_add_time(
                        UNIT(s)->manager->event,
                        &s->timer_event_source,
                        CLOCK_MONOTONIC,
                        usec, 0,
                        service_dispatch_timer, s);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(s->timer_event_source, "service-timer");

        return 0;
}

static int service_verify(Service *s) {
        assert(s);

        if (UNIT(s)->load_state != UNIT_LOADED)
                return 0;

        if (!s->exec_command[SERVICE_EXEC_START] && !s->exec_command[SERVICE_EXEC_STOP]
            && UNIT(s)->success_action == EMERGENCY_ACTION_NONE) {
                /* FailureAction= only makes sense if one of the start or stop commands is specified.
                 * SuccessAction= will be executed unconditionally if no commands are specified. Hence,
                 * either a command or SuccessAction= are required. */

                log_unit_error(UNIT(s), "Service has no ExecStart=, ExecStop=, or SuccessAction=. Refusing.");
                return -ENOEXEC;
        }

        if (s->type != SERVICE_ONESHOT && !s->exec_command[SERVICE_EXEC_START]) {
                log_unit_error(UNIT(s), "Service has no ExecStart= setting, which is only allowed for Type=oneshot services. Refusing.");
                return -ENOEXEC;
        }

        if (!s->remain_after_exit && !s->exec_command[SERVICE_EXEC_START] && UNIT(s)->success_action == EMERGENCY_ACTION_NONE) {
                log_unit_error(UNIT(s), "Service has no ExecStart= and no SuccessAction= settings and does not have RemainAfterExit=yes set. Refusing.");
                return -ENOEXEC;
        }

        if (s->type != SERVICE_ONESHOT && s->exec_command[SERVICE_EXEC_START]->command_next) {
                log_unit_error(UNIT(s), "Service has more than one ExecStart= setting, which is only allowed for Type=oneshot services. Refusing.");
                return -ENOEXEC;
        }

        if (s->type == SERVICE_ONESHOT && s->restart != SERVICE_RESTART_NO) {
                log_unit_error(UNIT(s), "Service has Restart= setting other than no, which isn't allowed for Type=oneshot services. Refusing.");
                return -ENOEXEC;
        }

        if (s->type == SERVICE_ONESHOT && !exit_status_set_is_empty(&s->restart_force_status)) {
                log_unit_error(UNIT(s), "Service has RestartForceStatus= set, which isn't allowed for Type=oneshot services. Refusing.");
                return -ENOEXEC;
        }

        if (s->type == SERVICE_DBUS && !s->bus_name) {
                log_unit_error(UNIT(s), "Service is of type D-Bus but no D-Bus service name has been specified. Refusing.");
                return -ENOEXEC;
        }

        if (s->bus_name && s->type != SERVICE_DBUS)
                log_unit_warning(UNIT(s), "Service has a D-Bus service name specified, but is not of type dbus. Ignoring.");

        if (s->exec_context.pam_name && !IN_SET(s->kill_context.kill_mode, KILL_CONTROL_GROUP, KILL_MIXED)) {
                log_unit_error(UNIT(s), "Service has PAM enabled. Kill mode must be set to 'control-group' or 'mixed'. Refusing.");
                return -ENOEXEC;
        }

        if (s->usb_function_descriptors && !s->usb_function_strings)
                log_unit_warning(UNIT(s), "Service has USBFunctionDescriptors= setting, but no USBFunctionStrings=. Ignoring.");

        if (!s->usb_function_descriptors && s->usb_function_strings)
                log_unit_warning(UNIT(s), "Service has USBFunctionStrings= setting, but no USBFunctionDescriptors=. Ignoring.");

        if (s->runtime_max_usec != USEC_INFINITY && s->type == SERVICE_ONESHOT)
                log_unit_warning(UNIT(s), "RuntimeMaxSec= has no effect in combination with Type=oneshot. Ignoring.");

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

static void service_fix_output(Service *s) {
        assert(s);

        /* If nothing has been explicitly configured, patch default output in. If input is socket/tty we avoid this
         * however, since in that case we want output to default to the same place as we read input from. */

        if (s->exec_context.std_error == EXEC_OUTPUT_INHERIT &&
            s->exec_context.std_output == EXEC_OUTPUT_INHERIT &&
            s->exec_context.std_input == EXEC_INPUT_NULL)
                s->exec_context.std_error = UNIT(s)->manager->default_std_error;

        if (s->exec_context.std_output == EXEC_OUTPUT_INHERIT &&
            s->exec_context.std_input == EXEC_INPUT_NULL)
                s->exec_context.std_output = UNIT(s)->manager->default_std_output;

        if (s->exec_context.std_input == EXEC_INPUT_NULL &&
            s->exec_context.stdin_data_size > 0)
                s->exec_context.std_input = EXEC_INPUT_DATA;
}

static int service_setup_bus_name(Service *s) {
        int r;

        assert(s);

        if (!s->bus_name)
                return 0;

        r = unit_add_dependency_by_name(UNIT(s), UNIT_REQUIRES, SPECIAL_DBUS_SOCKET, true, UNIT_DEPENDENCY_FILE);
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r, "Failed to add dependency on " SPECIAL_DBUS_SOCKET ": %m");

        /* We always want to be ordered against dbus.socket if both are in the transaction. */
        r = unit_add_dependency_by_name(UNIT(s), UNIT_AFTER, SPECIAL_DBUS_SOCKET, true, UNIT_DEPENDENCY_FILE);
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r, "Failed to add dependency on " SPECIAL_DBUS_SOCKET ": %m");

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

        service_fix_output(s);

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
            (s->type == SERVICE_NOTIFY || s->watchdog_usec > 0 || s->n_fd_store_max > 0))
                s->notify_access = NOTIFY_MAIN;

        /* If no OOM policy was explicitly set, then default to the configure default OOM policy. Except when
         * delegation is on, in that case it we assume the payload knows better what to do and can process
         * things in a more focused way. */
        if (s->oom_policy < 0)
                s->oom_policy = s->cgroup_context.delegate ? OOM_CONTINUE : UNIT(s)->manager->default_oom_policy;

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

        assert(s);

        /* Load a .service file */
        r = unit_load_fragment(u);
        if (r < 0)
                return r;

        /* Still nothing found? Then let's give up */
        if (u->load_state == UNIT_STUB)
                return -ENOENT;

        /* This is a new unit? Then let's add in some extras */
        if (u->load_state == UNIT_LOADED) {

                /* We were able to load something, then let's add in
                 * the dropin directories. */
                r = unit_load_dropin(u);
                if (r < 0)
                        return r;

                /* This is a new unit? Then let's add in some
                 * extras */
                r = service_add_extras(s);
                if (r < 0)
                        return r;
        }

        return service_verify(s);
}

static void service_dump(Unit *u, FILE *f, const char *prefix) {
        char buf_restart[FORMAT_TIMESPAN_MAX], buf_start[FORMAT_TIMESPAN_MAX], buf_stop[FORMAT_TIMESPAN_MAX],
                buf_runtime[FORMAT_TIMESPAN_MAX], buf_watchdog[FORMAT_TIMESPAN_MAX], buf_abort[FORMAT_TIMESPAN_MAX];
        ServiceExecCommand c;
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
                "%sOOMPolicy: %s\n",
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
                prefix, notify_access_to_string(s->notify_access),
                prefix, notify_state_to_string(s->notify_state),
                prefix, oom_policy_to_string(s->oom_policy));

        if (s->control_pid > 0)
                fprintf(f,
                        "%sControl PID: "PID_FMT"\n",
                        prefix, s->control_pid);

        if (s->main_pid > 0)
                fprintf(f,
                        "%sMain PID: "PID_FMT"\n"
                        "%sMain PID Known: %s\n"
                        "%sMain PID Alien: %s\n",
                        prefix, s->main_pid,
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
                "%sTimeoutStartSec: %s\n"
                "%sTimeoutStopSec: %s\n",
                prefix, format_timespan(buf_restart, sizeof(buf_restart), s->restart_usec, USEC_PER_SEC),
                prefix, format_timespan(buf_start, sizeof(buf_start), s->timeout_start_usec, USEC_PER_SEC),
                prefix, format_timespan(buf_stop, sizeof(buf_stop), s->timeout_stop_usec, USEC_PER_SEC));

        if (s->timeout_abort_set)
                fprintf(f,
                        "%sTimeoutAbortSec: %s\n",
                        prefix, format_timespan(buf_abort, sizeof(buf_abort), s->timeout_abort_usec, USEC_PER_SEC));

        fprintf(f,
                "%sRuntimeMaxSec: %s\n"
                "%sWatchdogSec: %s\n",
                prefix, format_timespan(buf_runtime, sizeof(buf_runtime), s->runtime_max_usec, USEC_PER_SEC),
                prefix, format_timespan(buf_watchdog, sizeof(buf_watchdog), s->watchdog_usec, USEC_PER_SEC));

        kill_context_dump(&s->kill_context, f, prefix);
        exec_context_dump(&s->exec_context, f, prefix);

        for (c = 0; c < _SERVICE_EXEC_COMMAND_MAX; c++) {

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
                        "%sFile Descriptor Store Current: %zu\n",
                        prefix, s->n_fd_store_max,
                        prefix, s->n_fd_store);

        cgroup_context_dump(&s->cgroup_context, f, prefix);
}

static int service_is_suitable_main_pid(Service *s, pid_t pid, int prio) {
        Unit *owner;

        assert(s);
        assert(pid_is_valid(pid));

        /* Checks whether the specified PID is suitable as main PID for this service. returns negative if not, 0 if the
         * PID is questionnable but should be accepted if the source of configuration is trusted. > 0 if the PID is
         * good */

        if (pid == getpid_cached() || pid == 1) {
                log_unit_full(UNIT(s), prio, 0, "New main PID "PID_FMT" is the manager, refusing.", pid);
                return -EPERM;
        }

        if (pid == s->control_pid) {
                log_unit_full(UNIT(s), prio, 0, "New main PID "PID_FMT" is the control process, refusing.", pid);
                return -EPERM;
        }

        if (!pid_is_alive(pid)) {
                log_unit_full(UNIT(s), prio, 0, "New main PID "PID_FMT" does not exist or is a zombie.", pid);
                return -ESRCH;
        }

        owner = manager_get_unit_by_pid(UNIT(s)->manager, pid);
        if (owner == UNIT(s)) {
                log_unit_debug(UNIT(s), "New main PID "PID_FMT" belongs to service, we are happy.", pid);
                return 1; /* Yay, it's definitely a good PID */
        }

        return 0; /* Hmm it's a suspicious PID, let's accept it if configuration source is trusted */
}

static int service_load_pid_file(Service *s, bool may_warn) {
        char procfs[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int)];
        bool questionable_pid_file = false;
        _cleanup_free_ char *k = NULL;
        _cleanup_close_ int fd = -1;
        int r, prio;
        pid_t pid;

        assert(s);

        if (!s->pid_file)
                return -ENOENT;

        prio = may_warn ? LOG_INFO : LOG_DEBUG;

        fd = chase_symlinks(s->pid_file, NULL, CHASE_OPEN|CHASE_SAFE, NULL);
        if (fd == -ENOLINK) {
                log_unit_full(UNIT(s), LOG_DEBUG, fd, "Potentially unsafe symlink chain, will now retry with relaxed checks: %s", s->pid_file);

                questionable_pid_file = true;

                fd = chase_symlinks(s->pid_file, NULL, CHASE_OPEN, NULL);
        }
        if (fd < 0)
                return log_unit_full(UNIT(s), prio, fd, "Can't open PID file %s (yet?) after %s: %m", s->pid_file, service_state_to_string(s->state));

        /* Let's read the PID file now that we chased it down. But we need to convert the O_PATH fd chase_symlinks() returned us into a proper fd first. */
        xsprintf(procfs, "/proc/self/fd/%i", fd);
        r = read_one_line_file(procfs, &k);
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r, "Can't convert PID files %s O_PATH file descriptor to proper file descriptor: %m", s->pid_file);

        r = parse_pid(k, &pid);
        if (r < 0)
                return log_unit_full(UNIT(s), prio, r, "Failed to parse PID from file %s: %m", s->pid_file);

        if (s->main_pid_known && pid == s->main_pid)
                return 0;

        r = service_is_suitable_main_pid(s, pid, prio);
        if (r < 0)
                return r;
        if (r == 0) {
                struct stat st;

                if (questionable_pid_file) {
                        log_unit_error(UNIT(s), "Refusing to accept PID outside of service control group, acquired through unsafe symlink chain: %s", s->pid_file);
                        return -EPERM;
                }

                /* Hmm, it's not clear if the new main PID is safe. Let's allow this if the PID file is owned by root */

                if (fstat(fd, &st) < 0)
                        return log_unit_error_errno(UNIT(s), errno, "Failed to fstat() PID file O_PATH fd: %m");

                if (st.st_uid != 0) {
                        log_unit_error(UNIT(s), "New main PID "PID_FMT" does not belong to service, and PID file is not owned by root. Refusing.", pid);
                        return -EPERM;
                }

                log_unit_debug(UNIT(s), "New main PID "PID_FMT" does not belong to service, but we'll accept it since PID file is owned by root.", pid);
        }

        if (s->main_pid_known) {
                log_unit_debug(UNIT(s), "Main PID changing: "PID_FMT" -> "PID_FMT, s->main_pid, pid);

                service_unwatch_main_pid(s);
                s->main_pid_known = false;
        } else
                log_unit_debug(UNIT(s), "Main PID loaded: "PID_FMT, pid);

        r = service_set_main_pid(s, pid);
        if (r < 0)
                return r;

        r = unit_watch_pid(UNIT(s), pid, false);
        if (r < 0) /* FIXME: we need to do something here */
                return log_unit_warning_errno(UNIT(s), r, "Failed to watch PID "PID_FMT" for service: %m", pid);

        return 1;
}

static void service_search_main_pid(Service *s) {
        pid_t pid = 0;
        int r;

        assert(s);

        /* If we know it anyway, don't ever fallback to unreliable
         * heuristics */
        if (s->main_pid_known)
                return;

        if (!s->guess_main_pid)
                return;

        assert(s->main_pid <= 0);

        if (unit_search_main_pid(UNIT(s), &pid) < 0)
                return;

        log_unit_debug(UNIT(s), "Main PID guessed: "PID_FMT, pid);
        if (service_set_main_pid(s, pid) < 0)
                return;

        r = unit_watch_pid(UNIT(s), pid, false);
        if (r < 0)
                /* FIXME: we need to do something here */
                log_unit_warning_errno(UNIT(s), r, "Failed to watch PID "PID_FMT" from: %m", pid);
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
                    SERVICE_RELOAD,
                    SERVICE_STOP, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                    SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL,
                    SERVICE_AUTO_RESTART,
                    SERVICE_CLEANING))
                s->timer_event_source = sd_event_source_unref(s->timer_event_source);

        if (!IN_SET(state,
                    SERVICE_START, SERVICE_START_POST,
                    SERVICE_RUNNING, SERVICE_RELOAD,
                    SERVICE_STOP, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                    SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL)) {
                service_unwatch_main_pid(s);
                s->main_command = NULL;
        }

        if (!IN_SET(state,
                    SERVICE_CONDITION, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST,
                    SERVICE_RELOAD,
                    SERVICE_STOP, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                    SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL,
                    SERVICE_CLEANING)) {
                service_unwatch_control_pid(s);
                s->control_command = NULL;
                s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;
        }

        if (IN_SET(state, SERVICE_DEAD, SERVICE_FAILED, SERVICE_AUTO_RESTART)) {
                unit_unwatch_all_pids(UNIT(s));
                unit_dequeue_rewatch_pids(UNIT(s));
        }

        if (!IN_SET(state,
                    SERVICE_CONDITION, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST,
                    SERVICE_RUNNING, SERVICE_RELOAD,
                    SERVICE_STOP, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                    SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL) &&
            !(state == SERVICE_DEAD && UNIT(s)->job))
                service_close_socket_fd(s);

        if (state != SERVICE_START)
                s->exec_fd_event_source = sd_event_source_unref(s->exec_fd_event_source);

        if (!IN_SET(state, SERVICE_START_POST, SERVICE_RUNNING, SERVICE_RELOAD))
                service_stop_watchdog(s);

        /* For the inactive states unit_notify() will trim the cgroup,
         * but for exit we have to do that ourselves... */
        if (state == SERVICE_EXITED && !MANAGER_IS_RELOADING(UNIT(s)->manager))
                unit_prune_cgroup(UNIT(s));

        if (old_state != state)
                log_unit_debug(UNIT(s), "Changed %s -> %s", service_state_to_string(old_state), service_state_to_string(state));

        unit_notify(UNIT(s), table[old_state], table[state],
                    (s->reload_result == SERVICE_SUCCESS ? 0 : UNIT_NOTIFY_RELOAD_FAILURE) |
                    (s->will_auto_restart ? UNIT_NOTIFY_WILL_AUTO_RESTART : 0) |
                    (s->result == SERVICE_SKIP_CONDITION ? UNIT_NOTIFY_SKIP_CONDITION : 0));
}

static usec_t service_coldplug_timeout(Service *s) {
        assert(s);

        switch (s->deserialized_state) {

        case SERVICE_CONDITION:
        case SERVICE_START_PRE:
        case SERVICE_START:
        case SERVICE_START_POST:
        case SERVICE_RELOAD:
                return usec_add(UNIT(s)->state_change_timestamp.monotonic, s->timeout_start_usec);

        case SERVICE_RUNNING:
                return usec_add(UNIT(s)->active_enter_timestamp.monotonic, s->runtime_max_usec);

        case SERVICE_STOP:
        case SERVICE_STOP_SIGTERM:
        case SERVICE_STOP_SIGKILL:
        case SERVICE_STOP_POST:
        case SERVICE_FINAL_SIGTERM:
        case SERVICE_FINAL_SIGKILL:
                return usec_add(UNIT(s)->state_change_timestamp.monotonic, s->timeout_stop_usec);

        case SERVICE_STOP_WATCHDOG:
                return usec_add(UNIT(s)->state_change_timestamp.monotonic, service_timeout_abort_usec(s));

        case SERVICE_AUTO_RESTART:
                return usec_add(UNIT(s)->inactive_enter_timestamp.monotonic, s->restart_usec);

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

        r = service_arm_timer(s, service_coldplug_timeout(s));
        if (r < 0)
                return r;

        if (s->main_pid > 0 &&
            pid_is_unwaited(s->main_pid) &&
            (IN_SET(s->deserialized_state,
                    SERVICE_START, SERVICE_START_POST,
                    SERVICE_RUNNING, SERVICE_RELOAD,
                    SERVICE_STOP, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                    SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL))) {
                r = unit_watch_pid(UNIT(s), s->main_pid, false);
                if (r < 0)
                        return r;
        }

        if (s->control_pid > 0 &&
            pid_is_unwaited(s->control_pid) &&
            IN_SET(s->deserialized_state,
                   SERVICE_CONDITION, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST,
                   SERVICE_RELOAD,
                   SERVICE_STOP, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                   SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL,
                   SERVICE_CLEANING)) {
                r = unit_watch_pid(UNIT(s), s->control_pid, false);
                if (r < 0)
                        return r;
        }

        if (!IN_SET(s->deserialized_state, SERVICE_DEAD, SERVICE_FAILED, SERVICE_AUTO_RESTART, SERVICE_CLEANING)) {
                (void) unit_enqueue_rewatch_pids(u);
                (void) unit_setup_dynamic_creds(u);
                (void) unit_setup_exec_runtime(u);
        }

        if (IN_SET(s->deserialized_state, SERVICE_START_POST, SERVICE_RUNNING, SERVICE_RELOAD))
                service_start_watchdog(s);

        if (UNIT_ISSET(s->accept_socket)) {
                Socket* socket = SOCKET(UNIT_DEREF(s->accept_socket));

                if (socket->max_connections_per_source > 0) {
                        SocketPeer *peer;

                        /* Make a best-effort attempt at bumping the connection count */
                        if (socket_acquire_peer(socket, s->socket_fd, &peer) > 0) {
                                socket_peer_unref(s->peer);
                                s->peer = peer;
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

                rfds = new(int, 1);
                if (!rfds)
                        return -ENOMEM;
                rfds[0] = s->socket_fd;

                rfd_names = strv_new("connection");
                if (!rfd_names)
                        return -ENOMEM;

                rn_socket_fds = 1;
        } else {
                Iterator i;
                void *v;
                Unit *u;

                /* Pass all our configured sockets for singleton services */

                HASHMAP_FOREACH_KEY(v, u, UNIT(s)->dependencies[UNIT_TRIGGERED_BY], i) {
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
                ServiceFDStore *fs;
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

        (void) sd_event_source_set_description(source, "service event_fd");

        r = sd_event_source_set_io_fd_own(source, true);
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r, "Failed to pass ownership of fd to event source: %m");

        *ret_event_source = TAKE_PTR(source);
        return 0;
}

static int service_allocate_exec_fd(
                Service *s,
                sd_event_source **ret_event_source,
                int* ret_exec_fd) {

        _cleanup_close_pair_ int p[2] = { -1, -1 };
        int r;

        assert(s);
        assert(ret_event_source);
        assert(ret_exec_fd);

        if (pipe2(p, O_CLOEXEC|O_NONBLOCK) < 0)
                return log_unit_error_errno(UNIT(s), errno, "Failed to allocate exec_fd pipe: %m");

        r = service_allocate_exec_fd_event_source(s, p[0], ret_event_source);
        if (r < 0)
                return r;

        p[0] = -1;
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
                return IN_SET(s->notify_access, NOTIFY_EXEC, NOTIFY_ALL);

        /* We only spawn main processes and control processes, so any
         * process that is not a control process is a main process */
        return s->notify_access != NOTIFY_NONE;
}

static int service_spawn(
                Service *s,
                ExecCommand *c,
                usec_t timeout,
                ExecFlags flags,
                pid_t *_pid) {

        _cleanup_(exec_params_clear) ExecParameters exec_params = {
                .flags      = flags,
                .stdin_fd   = -1,
                .stdout_fd  = -1,
                .stderr_fd  = -1,
                .exec_fd    = -1,
        };
        _cleanup_strv_free_ char **final_env = NULL, **our_env = NULL, **fd_names = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *exec_fd_source = NULL;
        size_t n_socket_fds = 0, n_storage_fds = 0, n_env = 0;
        _cleanup_close_ int exec_fd = -1;
        _cleanup_free_ int *fds = NULL;
        pid_t pid;
        int r;

        assert(s);
        assert(c);
        assert(_pid);

        r = unit_prepare_exec(UNIT(s)); /* This realizes the cgroup, among other things */
        if (r < 0)
                return r;

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

                r = service_collect_fds(s, &fds, &fd_names, &n_socket_fds, &n_storage_fds);
                if (r < 0)
                        return r;

                log_unit_debug(UNIT(s), "Passing %zu fds to service", n_socket_fds + n_storage_fds);
        }

        if (!FLAGS_SET(flags, EXEC_IS_CONTROL) && s->type == SERVICE_EXEC) {
                assert(!s->exec_fd_event_source);

                r = service_allocate_exec_fd(s, &exec_fd_source, &exec_fd);
                if (r < 0)
                        return r;
        }

        r = service_arm_timer(s, usec_add(now(CLOCK_MONOTONIC), timeout));
        if (r < 0)
                return r;

        our_env = new0(char*, 10);
        if (!our_env)
                return -ENOMEM;

        if (service_exec_needs_notify_socket(s, flags))
                if (asprintf(our_env + n_env++, "NOTIFY_SOCKET=%s", UNIT(s)->manager->notify_socket) < 0)
                        return -ENOMEM;

        if (s->main_pid > 0)
                if (asprintf(our_env + n_env++, "MAINPID="PID_FMT, s->main_pid) < 0)
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

        if (flags & EXEC_SETENV_RESULT) {
                if (asprintf(our_env + n_env++, "SERVICE_RESULT=%s", service_result_to_string(s->result)) < 0)
                        return -ENOMEM;

                if (s->main_exec_status.pid > 0 &&
                    dual_timestamp_is_set(&s->main_exec_status.exit_timestamp)) {
                        if (asprintf(our_env + n_env++, "EXIT_CODE=%s", sigchld_code_to_string(s->main_exec_status.code)) < 0)
                                return -ENOMEM;

                        if (s->main_exec_status.code == CLD_EXITED)
                                r = asprintf(our_env + n_env++, "EXIT_STATUS=%i", s->main_exec_status.status);
                        else
                                r = asprintf(our_env + n_env++, "EXIT_STATUS=%s", signal_to_string(s->main_exec_status.status));
                        if (r < 0)
                                return -ENOMEM;
                }
        }

        r = unit_set_exec_params(UNIT(s), &exec_params);
        if (r < 0)
                return r;

        final_env = strv_env_merge(2, exec_params.environment, our_env, NULL);
        if (!final_env)
                return -ENOMEM;

        /* System D-Bus needs nss-systemd disabled, so that we don't deadlock */
        SET_FLAG(exec_params.flags, EXEC_NSS_BYPASS_BUS,
                 MANAGER_IS_SYSTEM(UNIT(s)->manager) && unit_has_name(UNIT(s), SPECIAL_DBUS_SERVICE));

        strv_free_and_replace(exec_params.environment, final_env);
        exec_params.fds = fds;
        exec_params.fd_names = fd_names;
        exec_params.n_socket_fds = n_socket_fds;
        exec_params.n_storage_fds = n_storage_fds;
        exec_params.watchdog_usec = service_get_watchdog_usec(s);
        exec_params.selinux_context_net = s->socket_fd_selinux_context_net;
        if (s->type == SERVICE_IDLE)
                exec_params.idle_pipe = UNIT(s)->manager->idle_pipe;
        exec_params.stdin_fd = s->stdin_fd;
        exec_params.stdout_fd = s->stdout_fd;
        exec_params.stderr_fd = s->stderr_fd;
        exec_params.exec_fd = exec_fd;

        r = exec_spawn(UNIT(s),
                       c,
                       &s->exec_context,
                       &exec_params,
                       s->exec_runtime,
                       &s->dynamic_creds,
                       &pid);
        if (r < 0)
                return r;

        s->exec_fd_event_source = TAKE_PTR(exec_fd_source);
        s->exec_fd_hot = false;

        r = unit_watch_pid(UNIT(s), pid, true);
        if (r < 0)
                return r;

        *_pid = pid;

        return 0;
}

static int main_pid_good(Service *s) {
        assert(s);

        /* Returns 0 if the pid is dead, > 0 if it is good, < 0 if we don't know */

        /* If we know the pid file, then let's just check if it is
         * still valid */
        if (s->main_pid_known) {

                /* If it's an alien child let's check if it is still
                 * alive ... */
                if (s->main_pid_alien && s->main_pid > 0)
                        return pid_is_alive(s->main_pid);

                /* .. otherwise assume we'll get a SIGCHLD for it,
                 * which we really should wait for to collect exit
                 * status and code */
                return s->main_pid > 0;
        }

        /* We don't know the pid */
        return -EAGAIN;
}

static int control_pid_good(Service *s) {
        assert(s);

        /* Returns 0 if the control PID is dead, > 0 if it is good. We never actually return < 0 here, but in order to
         * make this function as similar as possible to main_pid_good() and cgroup_good(), we pretend that < 0 also
         * means: we can't figure it out. */

        return s->control_pid > 0;
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

static bool service_shall_restart(Service *s) {
        assert(s);

        /* Don't restart after manual stops */
        if (s->forbid_restart)
                return false;

        /* Never restart if this is configured as special exception */
        if (exit_status_set_test(&s->restart_prevent_status, s->main_exec_status.code, s->main_exec_status.status))
                return false;

        /* Restart if the exit code/status are configured as restart triggers */
        if (exit_status_set_test(&s->restart_force_status,  s->main_exec_status.code, s->main_exec_status.status))
                return true;

        switch (s->restart) {

        case SERVICE_RESTART_NO:
                return false;

        case SERVICE_RESTART_ALWAYS:
                return true;

        case SERVICE_RESTART_ON_SUCCESS:
                return s->result == SERVICE_SUCCESS;

        case SERVICE_RESTART_ON_FAILURE:
                return s->result != SERVICE_SUCCESS;

        case SERVICE_RESTART_ON_ABNORMAL:
                return !IN_SET(s->result, SERVICE_SUCCESS, SERVICE_FAILURE_EXIT_CODE);

        case SERVICE_RESTART_ON_WATCHDOG:
                return s->result == SERVICE_FAILURE_WATCHDOG;

        case SERVICE_RESTART_ON_ABORT:
                return IN_SET(s->result, SERVICE_FAILURE_SIGNAL, SERVICE_FAILURE_CORE_DUMP);

        default:
                assert_not_reached("unknown restart setting");
        }
}

static bool service_will_restart(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        if (s->will_auto_restart)
                return true;
        if (s->state == SERVICE_AUTO_RESTART)
                return true;

        return unit_will_restart_default(u);
}

static void service_enter_dead(Service *s, ServiceResult f, bool allow_restart) {
        ServiceState end_state;
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
                end_state = SERVICE_DEAD;
        } else if (s->result == SERVICE_SKIP_CONDITION) {
                unit_log_skip(UNIT(s), service_result_to_string(s->result));
                end_state = SERVICE_DEAD;
        } else {
                unit_log_failure(UNIT(s), service_result_to_string(s->result));
                end_state = SERVICE_FAILED;
        }

        if (allow_restart && service_shall_restart(s))
                s->will_auto_restart = true;

        /* Make sure service_release_resources() doesn't destroy our FD store, while we are changing through
         * SERVICE_FAILED/SERVICE_DEAD before entering into SERVICE_AUTO_RESTART. */
        s->n_keep_fd_store ++;

        service_set_state(s, end_state);

        if (s->will_auto_restart) {
                s->will_auto_restart = false;

                r = service_arm_timer(s, usec_add(now(CLOCK_MONOTONIC), s->restart_usec));
                if (r < 0) {
                        s->n_keep_fd_store--;
                        goto fail;
                }

                service_set_state(s, SERVICE_AUTO_RESTART);
        } else
                /* If we shan't restart, then flush out the restart counter. But don't do that immediately, so that the
                 * user can still introspect the counter. Do so on the next start. */
                s->flush_n_restarts = true;

        /* The new state is in effect, let's decrease the fd store ref counter again. Let's also re-add us to the GC
         * queue, so that the fd store is possibly gc'ed again */
        s->n_keep_fd_store--;
        unit_add_to_gc_queue(UNIT(s));

        /* The next restart might not be a manual stop, hence reset the flag indicating manual stops */
        s->forbid_restart = false;

        /* We want fresh tmpdirs in case service is started again immediately */
        s->exec_runtime = exec_runtime_unref(s->exec_runtime, true);

        /* Also, remove the runtime directory */
        unit_destroy_runtime_directory(UNIT(s), &s->exec_context);

        /* Get rid of the IPC bits of the user */
        unit_unref_uid_gid(UNIT(s), true);

        /* Release the user, and destroy it if we are the only remaining owner */
        dynamic_creds_destroy(&s->dynamic_creds);

        /* Try to delete the pid file. At this point it will be
         * out-of-date, and some software might be confused by it, so
         * let's remove it. */
        if (s->pid_file)
                (void) unlink(s->pid_file);

        /* Reset TTY ownership if necessary */
        exec_context_revert_tty(&s->exec_context);

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to run install restart timer: %m");
        service_enter_dead(s, SERVICE_FAILURE_RESOURCES, false);
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

                r = service_spawn(s,
                                  s->control_command,
                                  s->timeout_stop_usec,
                                  EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_APPLY_TTY_STDIN|EXEC_IS_CONTROL|EXEC_SETENV_RESULT|EXEC_CONTROL_CGROUP,
                                  &s->control_pid);
                if (r < 0)
                        goto fail;

                service_set_state(s, SERVICE_STOP_POST);
        } else
                service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_SUCCESS);

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to run 'stop-post' task: %m");
        service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_FAILURE_RESOURCES);
}

static int state_to_kill_operation(ServiceState state) {
        switch (state) {

        case SERVICE_STOP_WATCHDOG:
                return KILL_WATCHDOG;

        case SERVICE_STOP_SIGTERM:
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
        int r;

        assert(s);

        if (s->result == SERVICE_SUCCESS)
                s->result = f;

        /* Before sending any signal, make sure we track all members of this cgroup */
        (void) unit_watch_all_pids(UNIT(s));

        /* Also, enqueue a job that we recheck all our PIDs a bit later, given that it's likely some processes have
         * died now */
        (void) unit_enqueue_rewatch_pids(UNIT(s));

        r = unit_kill_context(
                        UNIT(s),
                        &s->kill_context,
                        state_to_kill_operation(state),
                        s->main_pid,
                        s->control_pid,
                        s->main_pid_alien);
        if (r < 0)
                goto fail;

        if (r > 0) {
                r = service_arm_timer(s, usec_add(now(CLOCK_MONOTONIC),
                                      state == SERVICE_STOP_WATCHDOG ? service_timeout_abort_usec(s) : s->timeout_stop_usec));
                if (r < 0)
                        goto fail;

                service_set_state(s, state);
        } else if (IN_SET(state, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM) && s->kill_context.send_sigkill)
                service_enter_signal(s, SERVICE_STOP_SIGKILL, SERVICE_SUCCESS);
        else if (IN_SET(state, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL))
                service_enter_stop_post(s, SERVICE_SUCCESS);
        else if (state == SERVICE_FINAL_SIGTERM && s->kill_context.send_sigkill)
                service_enter_signal(s, SERVICE_FINAL_SIGKILL, SERVICE_SUCCESS);
        else
                service_enter_dead(s, SERVICE_SUCCESS, true);

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to kill processes: %m");

        if (IN_SET(state, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL))
                service_enter_stop_post(s, SERVICE_FAILURE_RESOURCES);
        else
                service_enter_dead(s, SERVICE_FAILURE_RESOURCES, true);
}

static void service_enter_stop_by_notify(Service *s) {
        assert(s);

        (void) unit_enqueue_rewatch_pids(UNIT(s));

        service_arm_timer(s, usec_add(now(CLOCK_MONOTONIC), s->timeout_stop_usec));

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

                r = service_spawn(s,
                                  s->control_command,
                                  s->timeout_stop_usec,
                                  EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_IS_CONTROL|EXEC_SETENV_RESULT|EXEC_CONTROL_CGROUP,
                                  &s->control_pid);
                if (r < 0)
                        goto fail;

                service_set_state(s, SERVICE_STOP);
        } else
                service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_SUCCESS);

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to run 'stop' task: %m");
        service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_RESOURCES);
}

static bool service_good(Service *s) {
        int main_pid_ok;
        assert(s);

        if (s->type == SERVICE_DBUS && !s->bus_name_good)
                return false;

        main_pid_ok = main_pid_good(s);
        if (main_pid_ok > 0) /* It's alive */
                return true;
        if (main_pid_ok == 0) /* It's dead */
                return false;

        /* OK, we don't know anything about the main PID, maybe
         * because there is none. Let's check the control group
         * instead. */

        return cgroup_good(s) != 0;
}

static void service_enter_running(Service *s, ServiceResult f) {
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
                        service_arm_timer(s, usec_add(UNIT(s)->active_enter_timestamp.monotonic, s->runtime_max_usec));
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

                r = service_spawn(s,
                                  s->control_command,
                                  s->timeout_start_usec,
                                  EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_IS_CONTROL|EXEC_CONTROL_CGROUP,
                                  &s->control_pid);
                if (r < 0)
                        goto fail;

                service_set_state(s, SERVICE_START_POST);
        } else
                service_enter_running(s, SERVICE_SUCCESS);

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to run 'start-post' task: %m");
        service_enter_stop(s, SERVICE_FAILURE_RESOURCES);
}

static void service_kill_control_process(Service *s) {
        int r;

        assert(s);

        if (s->control_pid <= 0)
                return;

        r = kill_and_sigcont(s->control_pid, SIGKILL);
        if (r < 0) {
                _cleanup_free_ char *comm = NULL;

                (void) get_process_comm(s->control_pid, &comm);

                log_unit_debug_errno(UNIT(s), r, "Failed to kill control process " PID_FMT " (%s), ignoring: %m",
                                     s->control_pid, strna(comm));
        }
}

static int service_adverse_to_leftover_processes(Service *s) {
        assert(s);

        /* KillMode=mixed and control group are used to indicate that all process should be killed off.
         * SendSIGKILL is used for services that require a clean shutdown. These are typically database
         * service where a SigKilled process would result in a lengthy recovery and who's shutdown or
         * startup time is quite variable (so Timeout settings aren't of use).
         *
         * Here we take these two factors and refuse to start a service if there are existing processes
         * within a control group. Databases, while generally having some protection against multiple
         * instances running, lets not stress the rigor of these. Also ExecStartPre parts of the service
         * aren't as rigoriously written to protect aganst against multiple use. */
        if (unit_warn_leftover_processes(UNIT(s)) &&
            IN_SET(s->kill_context.kill_mode, KILL_MIXED, KILL_CONTROL_GROUP) &&
            !s->kill_context.send_sigkill)
               return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(EBUSY),
                                           "Will not start SendSIGKILL=no service of type KillMode=control-group or mixed while processes exist");

        return 0;
}

static void service_enter_start(Service *s) {
        ExecCommand *c;
        usec_t timeout;
        pid_t pid;
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
                        /* There's no command line configured for the main command? Hmm, that is strange. This can only
                         * happen if the configuration changes at runtime. In this case, let's enter a failure
                         * state. */
                        log_unit_error(UNIT(s), "There's no 'start' task anymore we could start.");
                        r = -ENXIO;
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
                          EXEC_PASS_FDS|EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_APPLY_TTY_STDIN|EXEC_SET_WATCHDOG,
                          &pid);
        if (r < 0)
                goto fail;

        if (IN_SET(s->type, SERVICE_SIMPLE, SERVICE_IDLE)) {
                /* For simple services we immediately start
                 * the START_POST binaries. */

                service_set_main_pid(s, pid);
                service_enter_start_post(s);

        } else  if (s->type == SERVICE_FORKING) {

                /* For forking services we wait until the start
                 * process exited. */

                s->control_pid = pid;
                service_set_state(s, SERVICE_START);

        } else if (IN_SET(s->type, SERVICE_ONESHOT, SERVICE_DBUS, SERVICE_NOTIFY, SERVICE_EXEC)) {

                /* For oneshot services we wait until the start process exited, too, but it is our main process. */

                /* For D-Bus services we know the main pid right away, but wait for the bus name to appear on the
                 * bus. 'notify' and 'exec' services are similar. */

                service_set_main_pid(s, pid);
                service_set_state(s, SERVICE_START);
        } else
                assert_not_reached("Unknown service type");

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to run 'start' task: %m");
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
                                  EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_IS_CONTROL|EXEC_APPLY_TTY_STDIN,
                                  &s->control_pid);
                if (r < 0)
                        goto fail;

                service_set_state(s, SERVICE_START_PRE);
        } else
                service_enter_start(s);

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to run 'start-pre' task: %m");
        service_enter_dead(s, SERVICE_FAILURE_RESOURCES, true);
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

                r = service_spawn(s,
                                  s->control_command,
                                  s->timeout_start_usec,
                                  EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_IS_CONTROL|EXEC_APPLY_TTY_STDIN,
                                  &s->control_pid);

                if (r < 0)
                        goto fail;

                service_set_state(s, SERVICE_CONDITION);
        } else
                service_enter_start_pre(s);

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to run 'exec-condition' task: %m");
        service_enter_dead(s, SERVICE_FAILURE_RESOURCES, true);
}

static void service_enter_restart(Service *s) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(s);

        if (UNIT(s)->job && UNIT(s)->job->type == JOB_STOP) {
                /* Don't restart things if we are going down anyway */
                log_unit_info(UNIT(s), "Stop job pending for unit, delaying automatic restart.");

                r = service_arm_timer(s, usec_add(now(CLOCK_MONOTONIC), s->restart_usec));
                if (r < 0)
                        goto fail;

                return;
        }

        /* Any units that are bound to this service must also be
         * restarted. We use JOB_RESTART (instead of the more obvious
         * JOB_START) here so that those dependency jobs will be added
         * as well. */
        r = manager_add_job(UNIT(s)->manager, JOB_RESTART, UNIT(s), JOB_REPLACE, NULL, &error, NULL);
        if (r < 0)
                goto fail;

        /* Count the jobs we enqueue for restarting. This counter is maintained as long as the unit isn't fully
         * stopped, i.e. as long as it remains up or remains in auto-start states. The use can reset the counter
         * explicitly however via the usual "systemctl reset-failure" logic. */
        s->n_restarts ++;
        s->flush_n_restarts = false;

        log_struct(LOG_INFO,
                   "MESSAGE_ID=" SD_MESSAGE_UNIT_RESTART_SCHEDULED_STR,
                   LOG_UNIT_ID(UNIT(s)),
                   LOG_UNIT_INVOCATION_ID(UNIT(s)),
                   LOG_UNIT_MESSAGE(UNIT(s), "Scheduled restart job, restart counter is at %u.", s->n_restarts),
                   "N_RESTARTS=%u", s->n_restarts);

        /* Notify clients about changed restart counter */
        unit_add_to_dbus_queue(UNIT(s));

        /* Note that we stay in the SERVICE_AUTO_RESTART state here,
         * it will be canceled as part of the service_stop() call that
         * is executed as part of JOB_RESTART. */

        return;

fail:
        log_unit_warning(UNIT(s), "Failed to schedule restart job: %s", bus_error_message(&error, -r));
        service_enter_dead(s, SERVICE_FAILURE_RESOURCES, false);
}

static void service_enter_reload_by_notify(Service *s) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(s);

        service_arm_timer(s, usec_add(now(CLOCK_MONOTONIC), s->timeout_start_usec));
        service_set_state(s, SERVICE_RELOAD);

        /* service_enter_reload_by_notify is never called during a reload, thus no loops are possible. */
        r = manager_propagate_reload(UNIT(s)->manager, UNIT(s), JOB_FAIL, &error);
        if (r < 0)
                log_unit_warning(UNIT(s), "Failed to schedule propagation of reload: %s", bus_error_message(&error, -r));
}

static void service_enter_reload(Service *s) {
        int r;

        assert(s);

        service_unwatch_control_pid(s);
        s->reload_result = SERVICE_SUCCESS;

        s->control_command = s->exec_command[SERVICE_EXEC_RELOAD];
        if (s->control_command) {
                s->control_command_id = SERVICE_EXEC_RELOAD;

                r = service_spawn(s,
                                  s->control_command,
                                  s->timeout_start_usec,
                                  EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_IS_CONTROL|EXEC_CONTROL_CGROUP,
                                  &s->control_pid);
                if (r < 0)
                        goto fail;

                service_set_state(s, SERVICE_RELOAD);
        } else
                service_enter_running(s, SERVICE_SUCCESS);

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to run 'reload' task: %m");
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

        r = service_spawn(s,
                          s->control_command,
                          timeout,
                          EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_IS_CONTROL|
                          (IN_SET(s->control_command_id, SERVICE_EXEC_CONDITION, SERVICE_EXEC_START_PRE, SERVICE_EXEC_STOP_POST) ? EXEC_APPLY_TTY_STDIN : 0)|
                          (IN_SET(s->control_command_id, SERVICE_EXEC_STOP, SERVICE_EXEC_STOP_POST) ? EXEC_SETENV_RESULT : 0)|
                          (IN_SET(s->control_command_id, SERVICE_EXEC_START_POST, SERVICE_EXEC_RELOAD, SERVICE_EXEC_STOP, SERVICE_EXEC_STOP_POST) ? EXEC_CONTROL_CGROUP : 0),
                          &s->control_pid);
        if (r < 0)
                goto fail;

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to run next control task: %m");

        if (IN_SET(s->state, SERVICE_CONDITION, SERVICE_START_PRE, SERVICE_START_POST, SERVICE_STOP))
                service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_RESOURCES);
        else if (s->state == SERVICE_STOP_POST)
                service_enter_dead(s, SERVICE_FAILURE_RESOURCES, true);
        else if (s->state == SERVICE_RELOAD) {
                s->reload_result = SERVICE_FAILURE_RESOURCES;
                service_enter_running(s, SERVICE_SUCCESS);
        } else
                service_enter_stop(s, SERVICE_FAILURE_RESOURCES);
}

static void service_run_next_main(Service *s) {
        pid_t pid;
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
                          EXEC_PASS_FDS|EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_APPLY_TTY_STDIN|EXEC_SET_WATCHDOG,
                          &pid);
        if (r < 0)
                goto fail;

        service_set_main_pid(s, pid);

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to run next main task: %m");
        service_enter_stop(s, SERVICE_FAILURE_RESOURCES);
}

static int service_start(Unit *u) {
        Service *s = SERVICE(u);
        int r;

        assert(s);

        /* We cannot fulfill this request right now, try again later
         * please! */
        if (IN_SET(s->state,
                   SERVICE_STOP, SERVICE_STOP_WATCHDOG, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                   SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL, SERVICE_CLEANING))
                return -EAGAIN;

        /* Already on it! */
        if (IN_SET(s->state, SERVICE_CONDITION, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST))
                return 0;

        /* A service that will be restarted must be stopped first to
         * trigger BindsTo and/or OnFailure dependencies. If a user
         * does not want to wait for the holdoff time to elapse, the
         * service should be manually restarted, not started. We
         * simply return EAGAIN here, so that any start jobs stay
         * queued, and assume that the auto restart timer will
         * eventually trigger the restart. */
        if (s->state == SERVICE_AUTO_RESTART)
                return -EAGAIN;

        assert(IN_SET(s->state, SERVICE_DEAD, SERVICE_FAILED));

        /* Make sure we don't enter a busy loop of some kind. */
        r = unit_test_start_limit(u);
        if (r < 0) {
                service_enter_dead(s, SERVICE_FAILURE_START_LIMIT_HIT, false);
                return r;
        }

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

        /* Already on it */
        if (IN_SET(s->state,
                   SERVICE_STOP, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                   SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL))
                return 0;

        /* A restart will be scheduled or is in progress. */
        if (s->state == SERVICE_AUTO_RESTART) {
                service_set_state(s, SERVICE_DEAD);
                return 0;
        }

        /* If there's already something running we go directly into
         * kill mode. */
        if (IN_SET(s->state, SERVICE_CONDITION, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST, SERVICE_RELOAD, SERVICE_STOP_WATCHDOG)) {
                service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_SUCCESS);
                return 0;
        }

        /* If we are currently cleaning, then abort it, brutally. */
        if (s->state == SERVICE_CLEANING) {
                service_enter_signal(s, SERVICE_FINAL_SIGKILL, SERVICE_SUCCESS);
                return 0;
        }

        assert(IN_SET(s->state, SERVICE_RUNNING, SERVICE_EXITED));

        service_enter_stop(s, SERVICE_SUCCESS);
        return 1;
}

static int service_reload(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        assert(IN_SET(s->state, SERVICE_RUNNING, SERVICE_EXITED));

        service_enter_reload(s);
        return 1;
}

_pure_ static bool service_can_reload(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        return !!s->exec_command[SERVICE_EXEC_RELOAD];
}

static unsigned service_exec_command_index(Unit *u, ServiceExecCommand id, ExecCommand *current) {
        Service *s = SERVICE(u);
        unsigned idx = 0;
        ExecCommand *first, *c;

        assert(s);

        first = s->exec_command[id];

        /* Figure out where we are in the list by walking back to the beginning */
        for (c = current; c != first; c = c->command_prev)
                idx++;

        return idx;
}

static int service_serialize_exec_command(Unit *u, FILE *f, ExecCommand *command) {
        _cleanup_free_ char *args = NULL, *p = NULL;
        size_t allocated = 0, length = 0;
        Service *s = SERVICE(u);
        const char *type, *key;
        ServiceExecCommand id;
        unsigned idx;
        char **arg;

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
                if (!GREEDY_REALLOC(args, allocated, length + 2 + n + 2))
                        return log_oom();

                if (length > 0)
                        args[length++] = ' ';

                args[length++] = '"';
                memcpy(args + length, e, n);
                length += n;
                args[length++] = '"';
        }

        if (!GREEDY_REALLOC(args, allocated, length + 1))
                return log_oom();

        args[length++] = 0;

        p = cescape(command->path);
        if (!p)
                return -ENOMEM;

        key = strjoina(type, "-command");
        return serialize_item_format(f, key, "%s %u %s %s", service_exec_command_to_string(id), idx, p, args);
}

static int service_serialize(Unit *u, FILE *f, FDSet *fds) {
        Service *s = SERVICE(u);
        ServiceFDStore *fs;
        int r;

        assert(u);
        assert(f);
        assert(fds);

        (void) serialize_item(f, "state", service_state_to_string(s->state));
        (void) serialize_item(f, "result", service_result_to_string(s->result));
        (void) serialize_item(f, "reload-result", service_result_to_string(s->reload_result));

        if (s->control_pid > 0)
                (void) serialize_item_format(f, "control-pid", PID_FMT, s->control_pid);

        if (s->main_pid_known && s->main_pid > 0)
                (void) serialize_item_format(f, "main-pid", PID_FMT, s->main_pid);

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

                (void) serialize_item_format(f, "fd-store-fd", "%i %s", copy, c);
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

        (void) serialize_dual_timestamp(f, "watchdog-timestamp", &s->watchdog_timestamp);
        (void) serialize_bool(f, "forbid-restart", s->forbid_restart);

        if (s->watchdog_override_enable)
                (void) serialize_item_format(f, "watchdog-override-usec", USEC_FMT, s->watchdog_override_usec);

        if (s->watchdog_original_usec != USEC_INFINITY)
                (void) serialize_item_format(f, "watchdog-original-usec", USEC_FMT, s->watchdog_original_usec);

        return 0;
}

static int service_deserialize_exec_command(Unit *u, const char *key, const char *value) {
        Service *s = SERVICE(u);
        int r;
        unsigned idx = 0, i;
        bool control, found = false;
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
                _STATE_EXEC_COMMAND_INVALID = -1,
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
                                return -EINVAL;

                        state = STATE_EXEC_COMMAND_INDEX;
                        break;
                case STATE_EXEC_COMMAND_INDEX:
                        r = safe_atou(arg, &idx);
                        if (r < 0)
                                return -EINVAL;

                        state = STATE_EXEC_COMMAND_PATH;
                        break;
                case STATE_EXEC_COMMAND_PATH:
                        path = TAKE_PTR(arg);
                        state = STATE_EXEC_COMMAND_ARGS;

                        if (!path_is_absolute(path))
                                return -EINVAL;
                        break;
                case STATE_EXEC_COMMAND_ARGS:
                        r = strv_extend(&argv, arg);
                        if (r < 0)
                                return -ENOMEM;
                        break;
                default:
                        assert_not_reached("Unknown error at deserialization of exec command");
                        break;
                }
        }

        if (state != STATE_EXEC_COMMAND_ARGS)
                return -EINVAL;

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

        if (command && control)
                s->control_command = command;
        else if (command)
                s->main_command = command;
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
                pid_t pid;

                if (parse_pid(value, &pid) < 0)
                        log_unit_debug(u, "Failed to parse control-pid value: %s", value);
                else
                        s->control_pid = pid;
        } else if (streq(key, "main-pid")) {
                pid_t pid;

                if (parse_pid(value, &pid) < 0)
                        log_unit_debug(u, "Failed to parse main-pid value: %s", value);
                else
                        (void) service_set_main_pid(s, pid);
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

                r = cunescape(value, 0, &t);
                if (r < 0)
                        log_unit_debug_errno(u, r, "Failed to unescape status text '%s': %m", value);
                else
                        free_and_replace(s->status_text, t);

        } else if (streq(key, "accept-socket")) {
                Unit *socket;

                r = manager_load_unit(u->manager, value, NULL, NULL, &socket);
                if (r < 0)
                        log_unit_debug_errno(u, r, "Failed to load accept-socket unit '%s': %m", value);
                else {
                        unit_ref_set(&s->accept_socket, u, socket);
                        SOCKET(socket)->n_connections++;
                }

        } else if (streq(key, "socket-fd")) {
                int fd;

                if (safe_atoi(value, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse socket-fd value: %s", value);
                else {
                        asynchronous_close(s->socket_fd);
                        s->socket_fd = fdset_remove(fds, fd);
                }
        } else if (streq(key, "fd-store-fd")) {
                const char *fdv;
                size_t pf;
                int fd;

                pf = strcspn(value, WHITESPACE);
                fdv = strndupa(value, pf);

                if (safe_atoi(fdv, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse fd-store-fd value: %s", value);
                else {
                        _cleanup_free_ char *t = NULL;
                        const char *fdn;

                        fdn = value + pf;
                        fdn += strspn(fdn, WHITESPACE);
                        (void) cunescape(fdn, 0, &t);

                        r = service_add_fd_store(s, fd, t);
                        if (r < 0)
                                log_unit_error_errno(u, r, "Failed to add fd to store: %m");
                        else
                                fdset_remove(fds, fd);
                }

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
        else if (streq(key, "watchdog-timestamp"))
                deserialize_dual_timestamp(value, &s->watchdog_timestamp);
        else if (streq(key, "forbid-restart")) {
                int b;

                b = parse_boolean(value);
                if (b < 0)
                        log_unit_debug(u, "Failed to parse forbid-restart value: %s", value);
                else
                        s->forbid_restart = b;
        } else if (streq(key, "stdin-fd")) {
                int fd;

                if (safe_atoi(value, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse stdin-fd value: %s", value);
                else {
                        asynchronous_close(s->stdin_fd);
                        s->stdin_fd = fdset_remove(fds, fd);
                        s->exec_context.stdio_as_fds = true;
                }
        } else if (streq(key, "stdout-fd")) {
                int fd;

                if (safe_atoi(value, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse stdout-fd value: %s", value);
                else {
                        asynchronous_close(s->stdout_fd);
                        s->stdout_fd = fdset_remove(fds, fd);
                        s->exec_context.stdio_as_fds = true;
                }
        } else if (streq(key, "stderr-fd")) {
                int fd;

                if (safe_atoi(value, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse stderr-fd value: %s", value);
                else {
                        asynchronous_close(s->stderr_fd);
                        s->stderr_fd = fdset_remove(fds, fd);
                        s->exec_context.stdio_as_fds = true;
                }
        } else if (streq(key, "exec-fd")) {
                int fd;

                if (safe_atoi(value, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse exec-fd value: %s", value);
                else {
                        s->exec_fd_event_source = sd_event_source_unref(s->exec_fd_event_source);

                        fd = fdset_remove(fds, fd);
                        if (service_allocate_exec_fd_event_source(s, fd, &s->exec_fd_event_source) < 0)
                                safe_close(fd);
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
        } else
                log_unit_debug(u, "Unknown serialization key: %s", key);

        return 0;
}

_pure_ static UnitActiveState service_active_state(Unit *u) {
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
        if (r < 0)
                goto fail;

        /* the pidfile might have appeared just before we set the watch */
        log_unit_debug(UNIT(s), "Trying to read PID file %s in case it changed", s->pid_file_pathspec->path);
        service_retry_pid_file(s);

        return 0;
fail:
        log_unit_error_errno(UNIT(s), r, "Failed to set a watch for PID file %s: %m", s->pid_file_pathspec->path);
        service_unwatch_pid_file(s);
        return r;
}

static int service_demand_pid_file(Service *s) {
        PathSpec *ps;

        assert(s->pid_file);
        assert(!s->pid_file_pathspec);

        ps = new0(PathSpec, 1);
        if (!ps)
                return -ENOMEM;

        ps->unit = UNIT(s);
        ps->path = strdup(s->pid_file);
        if (!ps->path) {
                free(ps);
                return -ENOMEM;
        }

        path_simplify(ps->path, false);

        /* PATH_CHANGED would not be enough. There are daemons (sendmail) that
         * keep their PID file open all the time. */
        ps->type = PATH_MODIFIED;
        ps->inotify_fd = -1;

        s->pid_file_pathspec = ps;

        return service_watch_pid_file(s);
}

static int service_dispatch_inotify_io(sd_event_source *source, int fd, uint32_t events, void *userdata) {
        PathSpec *p = userdata;
        Service *s;

        assert(p);

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

                        s->exec_fd_event_source = sd_event_source_unref(s->exec_fd_event_source);

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

                /* Waiting for SIGCHLD is usually more interesting,
                 * because it includes return codes/signals. Which is
                 * why we ignore the cgroup events for most cases,
                 * except when we don't know pid which to expect the
                 * SIGCHLD for. */

        case SERVICE_START:
                if (s->type == SERVICE_NOTIFY &&
                    main_pid_good(s) == 0 &&
                    control_pid_good(s) == 0) {
                        /* No chance of getting a ready notification anymore */
                        service_enter_stop_post(s, SERVICE_FAILURE_PROTOCOL);
                        break;
                }

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
        case SERVICE_FINAL_SIGTERM:
        case SERVICE_FINAL_SIGKILL:
                if (main_pid_good(s) <= 0 && control_pid_good(s) <= 0)
                        service_enter_dead(s, SERVICE_SUCCESS, true);

                break;

        default:
                ;
        }
}

static void service_notify_cgroup_oom_event(Unit *u) {
        Service *s = SERVICE(u);

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
        if (s->type == SERVICE_ONESHOT || (s->control_pid == pid && s->control_command_id != SERVICE_EXEC_START))
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
                assert_not_reached("Unknown code");

        if (s->main_pid == pid) {
                /* Forking services may occasionally move to a new PID.
                 * As long as they update the PID file before exiting the old
                 * PID, they're fine. */
                if (service_load_pid_file(s, false) > 0)
                        return;

                s->main_pid = 0;
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

                        /* There is another command to *
                         * execute, so let's do that. */

                        log_unit_debug(u, "Running next main command for state %s.", service_state_to_string(s->state));
                        service_run_next_main(s);

                } else {

                        /* The service exited, so the service is officially
                         * gone. */
                        s->main_command = NULL;

                        switch (s->state) {

                        case SERVICE_START_POST:
                        case SERVICE_RELOAD:
                        case SERVICE_STOP:
                                /* Need to wait until the operation is
                                 * done */
                                break;

                        case SERVICE_START:
                                if (s->type == SERVICE_ONESHOT) {
                                        /* This was our main goal, so let's go on */
                                        if (f == SERVICE_SUCCESS)
                                                service_enter_start_post(s);
                                        else
                                                service_enter_signal(s, SERVICE_STOP_SIGTERM, f);
                                        break;
                                } else if (s->type == SERVICE_NOTIFY) {
                                        /* Only enter running through a notification, so that the
                                         * SERVICE_START state signifies that no ready notification
                                         * has been received */
                                        if (f != SERVICE_SUCCESS)
                                                service_enter_signal(s, SERVICE_STOP_SIGTERM, f);
                                        else if (!s->remain_after_exit || s->notify_access == NOTIFY_MAIN)
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
                        case SERVICE_FINAL_SIGTERM:
                        case SERVICE_FINAL_SIGKILL:

                                if (control_pid_good(s) <= 0)
                                        service_enter_dead(s, f, true);
                                break;

                        default:
                                assert_not_reached("Uh, main process died at wrong time.");
                        }
                }

        } else if (s->control_pid == pid) {
                s->control_pid = 0;

                /* ExecCondition= calls that exit with (0, 254] should invoke skip-like behavior instead of failing */
                if (f == SERVICE_FAILURE_EXIT_CODE && s->state == SERVICE_CONDITION && status < 255)
                        f = SERVICE_SKIP_CONDITION;

                if (s->control_command) {
                        exec_status_exit(&s->control_command->exec_status, &s->exec_context, pid, code, status);

                        if (s->control_command->flags & EXEC_COMMAND_IGNORE_FAILURE)
                                f = SERVICE_SUCCESS;
                }

                unit_log_process_exit(
                                u,
                                "Control process",
                                service_exec_command_to_string(s->control_command_id),
                                f == SERVICE_SUCCESS,
                                code, status);

                if (s->state != SERVICE_RELOAD && s->result == SERVICE_SUCCESS)
                        s->result = f;

                if (s->control_command &&
                    s->control_command->command_next &&
                    f == SERVICE_SUCCESS) {

                        /* There is another command to *
                         * execute, so let's do that. */

                        log_unit_debug(u, "Running next control command for state %s.", service_state_to_string(s->state));
                        service_run_next_control(s);

                } else {
                        /* No further commands for this step, so let's
                         * figure out what to do next */

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
                                if (f == SERVICE_SUCCESS)
                                        if (service_load_pid_file(s, true) < 0)
                                                service_search_main_pid(s);

                                s->reload_result = f;
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
                                assert_not_reached("Uh, control process died at wrong time.");
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
                log_unit_warning(UNIT(s), "%s operation timed out. Terminating.", service_state_to_string(s->state));
                service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_TIMEOUT);
                break;

        case SERVICE_START_POST:
                log_unit_warning(UNIT(s), "Start-post operation timed out. Stopping.");
                service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_TIMEOUT);
                break;

        case SERVICE_RUNNING:
                log_unit_warning(UNIT(s), "Service reached runtime time limit. Stopping.");
                service_enter_stop(s, SERVICE_FAILURE_TIMEOUT);
                break;

        case SERVICE_RELOAD:
                log_unit_warning(UNIT(s), "Reload operation timed out. Killing reload process.");
                service_kill_control_process(s);
                s->reload_result = SERVICE_FAILURE_TIMEOUT;
                service_enter_running(s, SERVICE_SUCCESS);
                break;

        case SERVICE_STOP:
                log_unit_warning(UNIT(s), "Stopping timed out. Terminating.");
                service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_TIMEOUT);
                break;

        case SERVICE_STOP_WATCHDOG:
                log_unit_warning(UNIT(s), "State 'stop-watchdog' timed out. Terminating.");
                service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_TIMEOUT);
                break;

        case SERVICE_STOP_SIGTERM:
                if (s->kill_context.send_sigkill) {
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
                log_unit_warning(UNIT(s), "State 'stop-post' timed out. Terminating.");
                service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_FAILURE_TIMEOUT);
                break;

        case SERVICE_FINAL_SIGTERM:
                if (s->kill_context.send_sigkill) {
                        log_unit_warning(UNIT(s), "State 'stop-final-sigterm' timed out. Killing.");
                        service_enter_signal(s, SERVICE_FINAL_SIGKILL, SERVICE_FAILURE_TIMEOUT);
                } else {
                        log_unit_warning(UNIT(s), "State 'stop-final-sigterm' timed out. Skipping SIGKILL. Entering failed mode.");
                        service_enter_dead(s, SERVICE_FAILURE_TIMEOUT, false);
                }

                break;

        case SERVICE_FINAL_SIGKILL:
                log_unit_warning(UNIT(s), "Processes still around after final SIGKILL. Entering failed mode.");
                service_enter_dead(s, SERVICE_FAILURE_TIMEOUT, true);
                break;

        case SERVICE_AUTO_RESTART:
                if (s->restart_usec > 0) {
                        char buf_restart[FORMAT_TIMESPAN_MAX];
                        log_unit_info(UNIT(s),
                                      "Service RestartSec=%s expired, scheduling restart.",
                                      format_timespan(buf_restart, sizeof buf_restart, s->restart_usec, USEC_PER_SEC));
                } else
                        log_unit_info(UNIT(s),
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
                assert_not_reached("Timeout at wrong time.");
        }

        return 0;
}

static int service_dispatch_watchdog(sd_event_source *source, usec_t usec, void *userdata) {
        Service *s = SERVICE(userdata);
        char t[FORMAT_TIMESPAN_MAX];
        usec_t watchdog_usec;

        assert(s);
        assert(source == s->watchdog_event_source);

        watchdog_usec = service_get_watchdog_usec(s);

        if (UNIT(s)->manager->service_watchdogs) {
                log_unit_error(UNIT(s), "Watchdog timeout (limit %s)!",
                               format_timespan(t, sizeof(t), watchdog_usec, 1));

                service_enter_signal(s, SERVICE_STOP_WATCHDOG, SERVICE_FAILURE_WATCHDOG);
        } else
                log_unit_warning(UNIT(s), "Watchdog disabled! Ignoring watchdog timeout (limit %s)!",
                                 format_timespan(t, sizeof(t), watchdog_usec, 1));

        return 0;
}

static bool service_notify_message_authorized(Service *s, pid_t pid, char **tags, FDSet *fds) {
        assert(s);

        if (s->notify_access == NOTIFY_NONE) {
                log_unit_warning(UNIT(s), "Got notification message from PID "PID_FMT", but reception is disabled.", pid);
                return false;
        }

        if (s->notify_access == NOTIFY_MAIN && pid != s->main_pid) {
                if (s->main_pid != 0)
                        log_unit_warning(UNIT(s), "Got notification message from PID "PID_FMT", but reception only permitted for main PID "PID_FMT, pid, s->main_pid);
                else
                        log_unit_warning(UNIT(s), "Got notification message from PID "PID_FMT", but reception only permitted for main PID which is currently not known", pid);

                return false;
        }

        if (s->notify_access == NOTIFY_EXEC && pid != s->main_pid && pid != s->control_pid) {
                if (s->main_pid != 0 && s->control_pid != 0)
                        log_unit_warning(UNIT(s), "Got notification message from PID "PID_FMT", but reception only permitted for main PID "PID_FMT" and control PID "PID_FMT,
                                         pid, s->main_pid, s->control_pid);
                else if (s->main_pid != 0)
                        log_unit_warning(UNIT(s), "Got notification message from PID "PID_FMT", but reception only permitted for main PID "PID_FMT, pid, s->main_pid);
                else if (s->control_pid != 0)
                        log_unit_warning(UNIT(s), "Got notification message from PID "PID_FMT", but reception only permitted for control PID "PID_FMT, pid, s->control_pid);
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
                       s->status_text ? s->status_text : "<unset>");

        service_enter_signal(s, SERVICE_STOP_WATCHDOG, SERVICE_FAILURE_WATCHDOG);
}

static void service_notify_message(
                Unit *u,
                const struct ucred *ucred,
                char **tags,
                FDSet *fds) {

        Service *s = SERVICE(u);
        bool notify_dbus = false;
        const char *e;
        char **i;
        int r;

        assert(u);
        assert(ucred);

        if (!service_notify_message_authorized(SERVICE(u), ucred->pid, tags, fds))
                return;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *cc = NULL;

                cc = strv_join(tags, ", ");
                log_unit_debug(u, "Got notification message from PID "PID_FMT" (%s)", ucred->pid, isempty(cc) ? "n/a" : cc);
        }

        /* Interpret MAINPID= */
        e = strv_find_startswith(tags, "MAINPID=");
        if (e && IN_SET(s->state, SERVICE_START, SERVICE_START_POST, SERVICE_RUNNING, SERVICE_RELOAD)) {
                pid_t new_main_pid;

                if (parse_pid(e, &new_main_pid) < 0)
                        log_unit_warning(u, "Failed to parse MAINPID= field in notification message, ignoring: %s", e);
                else if (!s->main_pid_known || new_main_pid != s->main_pid) {

                        r = service_is_suitable_main_pid(s, new_main_pid, LOG_WARNING);
                        if (r == 0) {
                                /* The new main PID is a bit suspicious, which is OK if the sender is privileged. */

                                if (ucred->uid == 0) {
                                        log_unit_debug(u, "New main PID "PID_FMT" does not belong to service, but we'll accept it as the request to change it came from a privileged process.", new_main_pid);
                                        r = 1;
                                } else
                                        log_unit_debug(u, "New main PID "PID_FMT" does not belong to service, refusing.", new_main_pid);
                        }
                        if (r > 0) {
                                service_set_main_pid(s, new_main_pid);

                                r = unit_watch_pid(UNIT(s), new_main_pid, false);
                                if (r < 0)
                                        log_unit_warning_errno(UNIT(s), r, "Failed to watch new main PID "PID_FMT" for service: %m", new_main_pid);

                                notify_dbus = true;
                        }
                }
        }

        /* Interpret READY=/STOPPING=/RELOADING=. Last one wins. */
        STRV_FOREACH_BACKWARDS(i, tags) {

                if (streq(*i, "READY=1")) {
                        s->notify_state = NOTIFY_READY;

                        /* Type=notify services inform us about completed
                         * initialization with READY=1 */
                        if (s->type == SERVICE_NOTIFY && s->state == SERVICE_START)
                                service_enter_start_post(s);

                        /* Sending READY=1 while we are reloading informs us
                         * that the reloading is complete */
                        if (s->state == SERVICE_RELOAD && s->control_pid == 0)
                                service_enter_running(s, SERVICE_SUCCESS);

                        notify_dbus = true;
                        break;

                } else if (streq(*i, "RELOADING=1")) {
                        s->notify_state = NOTIFY_RELOADING;

                        if (s->state == SERVICE_RUNNING)
                                service_enter_reload_by_notify(s);

                        notify_dbus = true;
                        break;

                } else if (streq(*i, "STOPPING=1")) {
                        s->notify_state = NOTIFY_STOPPING;

                        if (s->state == SERVICE_RUNNING)
                                service_enter_stop_by_notify(s);

                        notify_dbus = true;
                        break;
                }
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
        if (strv_find(tags, "FDSTOREREMOVE=1")) {
                const char *name;

                name = strv_find_startswith(tags, "FDNAME=");
                if (!name || !fdname_is_valid(name))
                        log_unit_warning(u, "FDSTOREREMOVE=1 requested, but no valid file descriptor name passed, ignoring.");
                else
                        service_remove_fd_store(s, name);

        } else if (strv_find(tags, "FDSTORE=1")) {
                const char *name;

                name = strv_find_startswith(tags, "FDNAME=");
                if (name && !fdname_is_valid(name)) {
                        log_unit_warning(u, "Passed FDNAME= name is invalid, ignoring.");
                        name = NULL;
                }

                (void) service_add_fd_store_set(s, fds, name);
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

static void service_bus_name_owner_change(
                Unit *u,
                const char *old_owner,
                const char *new_owner) {

        Service *s = SERVICE(u);
        int r;

        assert(s);

        assert(old_owner || new_owner);

        if (old_owner && new_owner)
                log_unit_debug(u, "D-Bus name %s changed owner from %s to %s", s->bus_name, old_owner, new_owner);
        else if (old_owner)
                log_unit_debug(u, "D-Bus name %s no longer registered by %s", s->bus_name, old_owner);
        else
                log_unit_debug(u, "D-Bus name %s now registered by %s", s->bus_name, new_owner);

        s->bus_name_good = !!new_owner;

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

        } else if (new_owner &&
                   s->main_pid <= 0 &&
                   IN_SET(s->state,
                          SERVICE_START,
                          SERVICE_START_POST,
                          SERVICE_RUNNING,
                          SERVICE_RELOAD)) {

                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
                pid_t pid;

                /* Try to acquire PID from bus service */

                r = sd_bus_get_name_creds(u->manager->api_bus, s->bus_name, SD_BUS_CREDS_PID, &creds);
                if (r >= 0)
                        r = sd_bus_creds_get_pid(creds, &pid);
                if (r >= 0) {
                        log_unit_debug(u, "D-Bus name %s is now owned by process " PID_FMT, s->bus_name, pid);

                        service_set_main_pid(s, pid);
                        unit_watch_pid(UNIT(s), pid, false);
                }
        }
}

int service_set_socket_fd(Service *s, int fd, Socket *sock, bool selinux_context_net) {
        _cleanup_free_ char *peer = NULL;
        int r;

        assert(s);
        assert(fd >= 0);

        /* This is called by the socket code when instantiating a new service for a stream socket and the socket needs
         * to be configured. We take ownership of the passed fd on success. */

        if (UNIT(s)->load_state != UNIT_LOADED)
                return -EINVAL;

        if (s->socket_fd >= 0)
                return -EBUSY;

        if (s->state != SERVICE_DEAD)
                return -EAGAIN;

        if (getpeername_pretty(fd, true, &peer) >= 0) {

                if (UNIT(s)->description) {
                        _cleanup_free_ char *a;

                        a = strjoin(UNIT(s)->description, " (", peer, ")");
                        if (!a)
                                return -ENOMEM;

                        r = unit_set_description(UNIT(s), a);
                }  else
                        r = unit_set_description(UNIT(s), peer);

                if (r < 0)
                        return r;
        }

        r = unit_add_two_dependencies(UNIT(sock), UNIT_BEFORE, UNIT_TRIGGERS, UNIT(s), false, UNIT_DEPENDENCY_IMPLICIT);
        if (r < 0)
                return r;

        s->socket_fd = fd;
        s->socket_fd_selinux_context_net = selinux_context_net;

        unit_ref_set(&s->accept_socket, UNIT(s), UNIT(sock));
        return 0;
}

static void service_reset_failed(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        if (s->state == SERVICE_FAILED)
                service_set_state(s, SERVICE_DEAD);

        s->result = SERVICE_SUCCESS;
        s->reload_result = SERVICE_SUCCESS;
        s->clean_result = SERVICE_SUCCESS;
        s->n_restarts = 0;
        s->flush_n_restarts = false;
}

static int service_kill(Unit *u, KillWho who, int signo, sd_bus_error *error) {
        Service *s = SERVICE(u);

        assert(s);

        return unit_kill_common(u, who, signo, s->main_pid, s->control_pid, error);
}

static int service_main_pid(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        return s->main_pid;
}

static int service_control_pid(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        return s->control_pid;
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
                      SERVICE_STOP,
                      SERVICE_STOP_WATCHDOG,
                      SERVICE_STOP_SIGTERM,
                      SERVICE_STOP_SIGKILL,
                      SERVICE_STOP_POST,
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

static int service_clean(Unit *u, ExecCleanMask mask) {
        _cleanup_strv_free_ char **l = NULL;
        Service *s = SERVICE(u);
        int r;

        assert(s);
        assert(mask != 0);

        if (s->state != SERVICE_DEAD)
                return -EBUSY;

        r = exec_context_get_clean_directories(&s->exec_context, u->manager->prefix, mask, &l);
        if (r < 0)
                return r;

        if (strv_isempty(l))
                return -EUNATCH;

        service_unwatch_control_pid(s);
        s->clean_result = SERVICE_SUCCESS;
        s->control_command = NULL;
        s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;

        r = service_arm_timer(s, usec_add(now(CLOCK_MONOTONIC), s->exec_context.timeout_clean_usec));
        if (r < 0)
                goto fail;

        r = unit_fork_and_watch_rm_rf(u, l, &s->control_pid);
        if (r < 0)
                goto fail;

        service_set_state(s, SERVICE_CLEANING);

        return 0;

fail:
        log_unit_warning_errno(u, r, "Failed to initiate cleaning: %m");
        s->clean_result = SERVICE_FAILURE_RESOURCES;
        s->timer_event_source = sd_event_source_unref(s->timer_event_source);
        return r;
}

static int service_can_clean(Unit *u, ExecCleanMask *ret) {
        Service *s = SERVICE(u);

        assert(s);

        return exec_context_get_clean_mask(&s->exec_context, ret);
}

static const char* const service_restart_table[_SERVICE_RESTART_MAX] = {
        [SERVICE_RESTART_NO] = "no",
        [SERVICE_RESTART_ON_SUCCESS] = "on-success",
        [SERVICE_RESTART_ON_FAILURE] = "on-failure",
        [SERVICE_RESTART_ON_ABNORMAL] = "on-abnormal",
        [SERVICE_RESTART_ON_WATCHDOG] = "on-watchdog",
        [SERVICE_RESTART_ON_ABORT] = "on-abort",
        [SERVICE_RESTART_ALWAYS] = "always",
};

DEFINE_STRING_TABLE_LOOKUP(service_restart, ServiceRestart);

static const char* const service_type_table[_SERVICE_TYPE_MAX] = {
        [SERVICE_SIMPLE] = "simple",
        [SERVICE_FORKING] = "forking",
        [SERVICE_ONESHOT] = "oneshot",
        [SERVICE_DBUS] = "dbus",
        [SERVICE_NOTIFY] = "notify",
        [SERVICE_IDLE] = "idle",
        [SERVICE_EXEC] = "exec",
};

DEFINE_STRING_TABLE_LOOKUP(service_type, ServiceType);

static const char* const service_exec_command_table[_SERVICE_EXEC_COMMAND_MAX] = {
        [SERVICE_EXEC_CONDITION] = "ExecCondition",
        [SERVICE_EXEC_START_PRE] = "ExecStartPre",
        [SERVICE_EXEC_START] = "ExecStart",
        [SERVICE_EXEC_START_POST] = "ExecStartPost",
        [SERVICE_EXEC_RELOAD] = "ExecReload",
        [SERVICE_EXEC_STOP] = "ExecStop",
        [SERVICE_EXEC_STOP_POST] = "ExecStopPost",
};

DEFINE_STRING_TABLE_LOOKUP(service_exec_command, ServiceExecCommand);

static const char* const service_exec_ex_command_table[_SERVICE_EXEC_COMMAND_MAX] = {
        [SERVICE_EXEC_CONDITION] = "ExecConditionEx",
        [SERVICE_EXEC_START_PRE] = "ExecStartPreEx",
        [SERVICE_EXEC_START] = "ExecStartEx",
        [SERVICE_EXEC_START_POST] = "ExecStartPostEx",
        [SERVICE_EXEC_RELOAD] = "ExecReloadEx",
        [SERVICE_EXEC_STOP] = "ExecStopEx",
        [SERVICE_EXEC_STOP_POST] = "ExecStopPostEx",
};

DEFINE_STRING_TABLE_LOOKUP(service_exec_ex_command, ServiceExecCommand);

static const char* const notify_state_table[_NOTIFY_STATE_MAX] = {
        [NOTIFY_UNKNOWN] = "unknown",
        [NOTIFY_READY] = "ready",
        [NOTIFY_RELOADING] = "reloading",
        [NOTIFY_STOPPING] = "stopping",
};

DEFINE_STRING_TABLE_LOOKUP(notify_state, NotifyState);

static const char* const service_result_table[_SERVICE_RESULT_MAX] = {
        [SERVICE_SUCCESS] = "success",
        [SERVICE_FAILURE_RESOURCES] = "resources",
        [SERVICE_FAILURE_PROTOCOL] = "protocol",
        [SERVICE_FAILURE_TIMEOUT] = "timeout",
        [SERVICE_FAILURE_EXIT_CODE] = "exit-code",
        [SERVICE_FAILURE_SIGNAL] = "signal",
        [SERVICE_FAILURE_CORE_DUMP] = "core-dump",
        [SERVICE_FAILURE_WATCHDOG] = "watchdog",
        [SERVICE_FAILURE_START_LIMIT_HIT] = "start-limit-hit",
        [SERVICE_FAILURE_OOM_KILL] = "oom-kill",
        [SERVICE_SKIP_CONDITION] = "exec-condition",
};

DEFINE_STRING_TABLE_LOOKUP(service_result, ServiceResult);

const UnitVTable service_vtable = {
        .object_size = sizeof(Service),
        .exec_context_offset = offsetof(Service, exec_context),
        .cgroup_context_offset = offsetof(Service, cgroup_context),
        .kill_context_offset = offsetof(Service, kill_context),
        .exec_runtime_offset = offsetof(Service, exec_runtime),
        .dynamic_creds_offset = offsetof(Service, dynamic_creds),

        .sections =
                "Unit\0"
                "Service\0"
                "Install\0",
        .private_section = "Service",

        .can_transient = true,
        .can_delegate = true,

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

        .kill = service_kill,
        .clean = service_clean,
        .can_clean = service_can_clean,

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

        .bus_vtable = bus_service_vtable,
        .bus_set_property = bus_service_set_property,
        .bus_commit_properties = bus_service_commit_properties,

        .get_timeout = service_get_timeout,
        .needs_console = service_needs_console,
        .exit_status = service_exit_status,

        .status_message_formats = {
                .starting_stopping = {
                        [0] = "Starting %s...",
                        [1] = "Stopping %s...",
                },
                .finished_start_job = {
                        [JOB_DONE]       = "Started %s.",
                        [JOB_FAILED]     = "Failed to start %s.",
                        [JOB_SKIPPED]    = "Skipped %s.",
                },
                .finished_stop_job = {
                        [JOB_DONE]       = "Stopped %s.",
                        [JOB_FAILED]     = "Stopped (with error) %s.",
                },
        },
};
