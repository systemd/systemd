/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include "async.h"
#include "manager.h"
#include "unit.h"
#include "service.h"
#include "load-fragment.h"
#include "load-dropin.h"
#include "log.h"
#include "strv.h"
#include "unit-name.h"
#include "unit-printf.h"
#include "dbus-service.h"
#include "special.h"
#include "exit-status.h"
#include "def.h"
#include "path-util.h"
#include "util.h"
#include "utf8.h"
#include "env-util.h"
#include "fileio.h"
#include "bus-error.h"
#include "bus-util.h"
#include "bus-kernel.h"
#include "formats-util.h"
#include "process-util.h"
#include "signal-util.h"

static const UnitActiveState state_translation_table[_SERVICE_STATE_MAX] = {
        [SERVICE_DEAD] = UNIT_INACTIVE,
        [SERVICE_START_PRE] = UNIT_ACTIVATING,
        [SERVICE_START] = UNIT_ACTIVATING,
        [SERVICE_START_POST] = UNIT_ACTIVATING,
        [SERVICE_RUNNING] = UNIT_ACTIVE,
        [SERVICE_EXITED] = UNIT_ACTIVE,
        [SERVICE_RELOAD] = UNIT_RELOADING,
        [SERVICE_STOP] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGABRT] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_STOP_POST] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_FAILED] = UNIT_FAILED,
        [SERVICE_AUTO_RESTART] = UNIT_ACTIVATING
};

/* For Type=idle we never want to delay any other jobs, hence we
 * consider idle jobs active as soon as we start working on them */
static const UnitActiveState state_translation_table_idle[_SERVICE_STATE_MAX] = {
        [SERVICE_DEAD] = UNIT_INACTIVE,
        [SERVICE_START_PRE] = UNIT_ACTIVE,
        [SERVICE_START] = UNIT_ACTIVE,
        [SERVICE_START_POST] = UNIT_ACTIVE,
        [SERVICE_RUNNING] = UNIT_ACTIVE,
        [SERVICE_EXITED] = UNIT_ACTIVE,
        [SERVICE_RELOAD] = UNIT_RELOADING,
        [SERVICE_STOP] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGABRT] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_STOP_POST] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_FAILED] = UNIT_FAILED,
        [SERVICE_AUTO_RESTART] = UNIT_ACTIVATING
};

static int service_dispatch_io(sd_event_source *source, int fd, uint32_t events, void *userdata);
static int service_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata);
static int service_dispatch_watchdog(sd_event_source *source, usec_t usec, void *userdata);

static void service_enter_signal(Service *s, ServiceState state, ServiceResult f);
static void service_enter_reload_by_notify(Service *s);

static void service_init(Unit *u) {
        Service *s = SERVICE(u);

        assert(u);
        assert(u->load_state == UNIT_STUB);

        s->timeout_start_usec = u->manager->default_timeout_start_usec;
        s->timeout_stop_usec = u->manager->default_timeout_stop_usec;
        s->restart_usec = u->manager->default_restart_usec;
        s->type = _SERVICE_TYPE_INVALID;
        s->socket_fd = -1;
        s->bus_endpoint_fd = -1;
        s->guess_main_pid = true;

        RATELIMIT_INIT(s->start_limit, u->manager->default_start_limit_interval, u->manager->default_start_limit_burst);

        s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;
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
        free(s->pid_file_pathspec);
        s->pid_file_pathspec = NULL;
}

static int service_set_main_pid(Service *s, pid_t pid) {
        pid_t ppid;

        assert(s);

        if (pid <= 1)
                return -EINVAL;

        if (pid == getpid())
                return -EINVAL;

        if (s->main_pid == pid && s->main_pid_known)
                return 0;

        if (s->main_pid != pid) {
                service_unwatch_main_pid(s);
                exec_status_start(&s->main_exec_status, pid);
        }

        s->main_pid = pid;
        s->main_pid_known = true;

        if (get_parent_of_pid(pid, &ppid) >= 0 && ppid != getpid()) {
                log_unit_warning(UNIT(s), "Supervising process "PID_FMT" which is not our child. We'll most likely not notice when it exits.", pid);
                s->main_pid_alien = true;
        } else
                s->main_pid_alien = false;

        return 0;
}

static void service_close_socket_fd(Service *s) {
        assert(s);

        s->socket_fd = asynchronous_close(s->socket_fd);
}

static void service_connection_unref(Service *s) {
        assert(s);

        if (!UNIT_ISSET(s->accept_socket))
                return;

        socket_connection_unref(SOCKET(UNIT_DEREF(s->accept_socket)));
        unit_ref_unset(&s->accept_socket);
}

static void service_stop_watchdog(Service *s) {
        assert(s);

        s->watchdog_event_source = sd_event_source_unref(s->watchdog_event_source);
        s->watchdog_timestamp = DUAL_TIMESTAMP_NULL;
}

static void service_start_watchdog(Service *s) {
        int r;

        assert(s);

        if (s->watchdog_usec <= 0)
                return;

        if (s->watchdog_event_source) {
                r = sd_event_source_set_time(s->watchdog_event_source, s->watchdog_timestamp.monotonic + s->watchdog_usec);
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
                                s->watchdog_timestamp.monotonic + s->watchdog_usec, 0,
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

static void service_reset_watchdog(Service *s) {
        assert(s);

        dual_timestamp_get(&s->watchdog_timestamp);
        service_start_watchdog(s);
}

static void service_fd_store_unlink(ServiceFDStore *fs) {

        if (!fs)
                return;

        if (fs->service) {
                assert(fs->service->n_fd_store > 0);
                LIST_REMOVE(fd_store, fs->service->fd_store, fs);
                fs->service->n_fd_store--;
        }

        if (fs->event_source) {
                sd_event_source_set_enabled(fs->event_source, SD_EVENT_OFF);
                sd_event_source_unref(fs->event_source);
        }

        safe_close(fs->fd);
        free(fs);
}

static void service_release_resources(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        if (!s->fd_store)
                return;

        log_unit_debug(u, "Releasing all resources.");

        while (s->fd_store)
                service_fd_store_unlink(s->fd_store);

        assert(s->n_fd_store == 0);
}

static void service_done(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        free(s->pid_file);
        s->pid_file = NULL;

        free(s->status_text);
        s->status_text = NULL;

        free(s->reboot_arg);
        s->reboot_arg = NULL;

        s->exec_runtime = exec_runtime_unref(s->exec_runtime);
        exec_command_free_array(s->exec_command, _SERVICE_EXEC_COMMAND_MAX);
        s->control_command = NULL;
        s->main_command = NULL;

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
                free(s->bus_name);
                s->bus_name = NULL;
        }

        s->bus_endpoint_fd = safe_close(s->bus_endpoint_fd);
        service_close_socket_fd(s);
        service_connection_unref(s);

        unit_ref_unset(&s->accept_socket);

        service_stop_watchdog(s);

        s->timer_event_source = sd_event_source_unref(s->timer_event_source);

        service_release_resources(u);
}

static int on_fd_store_io(sd_event_source *e, int fd, uint32_t revents, void *userdata) {
        ServiceFDStore *fs = userdata;

        assert(e);
        assert(fs);

        /* If we get either EPOLLHUP or EPOLLERR, it's time to remove this entry from the fd store */
        service_fd_store_unlink(fs);
        return 0;
}

static int service_add_fd_store(Service *s, int fd) {
        ServiceFDStore *fs;
        int r;

        assert(s);
        assert(fd >= 0);

        if (s->n_fd_store >= s->n_fd_store_max)
                return 0;

        LIST_FOREACH(fd_store, fs, s->fd_store) {
                r = same_fd(fs->fd, fd);
                if (r < 0)
                        return r;
                if (r > 0) {
                        /* Already included */
                        safe_close(fd);
                        return 1;
                }
        }

        fs = new0(ServiceFDStore, 1);
        if (!fs)
                return -ENOMEM;

        fs->fd = fd;
        fs->service = s;

        r = sd_event_add_io(UNIT(s)->manager->event, &fs->event_source, fd, 0, on_fd_store_io, fs);
        if (r < 0) {
                free(fs);
                return r;
        }

        (void) sd_event_source_set_description(fs->event_source, "service-fd-store");

        LIST_PREPEND(fd_store, s->fd_store, fs);
        s->n_fd_store++;

        return 1;
}

static int service_add_fd_store_set(Service *s, FDSet *fds) {
        int r;

        assert(s);

        if (fdset_size(fds) <= 0)
                return 0;

        while (s->n_fd_store < s->n_fd_store_max) {
                _cleanup_close_ int fd = -1;

                fd = fdset_steal_first(fds);
                if (fd < 0)
                        break;

                r = service_add_fd_store(s, fd);
                if (r < 0)
                        return log_unit_error_errno(UNIT(s), r, "Couldn't add fd to fd store: %m");
                if (r > 0) {
                        log_unit_debug(UNIT(s), "Added fd to fd store.");
                        fd = -1;
                }
        }

        if (fdset_size(fds) > 0)
                log_unit_warning(UNIT(s), "Tried to store more fds than FDStoreMax=%u allows, closing remaining.", s->n_fd_store_max);

        return 0;
}

static int service_arm_timer(Service *s, usec_t usec) {
        int r;

        assert(s);

        if (s->timer_event_source) {
                r = sd_event_source_set_time(s->timer_event_source, now(CLOCK_MONOTONIC) + usec);
                if (r < 0)
                        return r;

                return sd_event_source_set_enabled(s->timer_event_source, SD_EVENT_ONESHOT);
        }

        r = sd_event_add_time(
                        UNIT(s)->manager->event,
                        &s->timer_event_source,
                        CLOCK_MONOTONIC,
                        now(CLOCK_MONOTONIC) + usec, 0,
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

        if (!s->exec_command[SERVICE_EXEC_START] && !s->exec_command[SERVICE_EXEC_STOP]) {
                log_unit_error(UNIT(s), "Service lacks both ExecStart= and ExecStop= setting. Refusing.");
                return -EINVAL;
        }

        if (s->type != SERVICE_ONESHOT && !s->exec_command[SERVICE_EXEC_START]) {
                log_unit_error(UNIT(s), "Service has no ExecStart= setting, which is only allowed for Type=oneshot services. Refusing.");
                return -EINVAL;
        }

        if (!s->remain_after_exit && !s->exec_command[SERVICE_EXEC_START]) {
                log_unit_error(UNIT(s), "Service has no ExecStart= setting, which is only allowed for RemainAfterExit=yes services. Refusing.");
                return -EINVAL;
        }

        if (s->type != SERVICE_ONESHOT && s->exec_command[SERVICE_EXEC_START]->command_next) {
                log_unit_error(UNIT(s), "Service has more than one ExecStart= setting, which is only allowed for Type=oneshot services. Refusing.");
                return -EINVAL;
        }

        if (s->type == SERVICE_ONESHOT && s->restart != SERVICE_RESTART_NO) {
                log_unit_error(UNIT(s), "Service has Restart= setting other than no, which isn't allowed for Type=oneshot services. Refusing.");
                return -EINVAL;
        }

        if (s->type == SERVICE_ONESHOT && !exit_status_set_is_empty(&s->restart_force_status)) {
                log_unit_error(UNIT(s), "Service has RestartForceStatus= set, which isn't allowed for Type=oneshot services. Refusing.");
                return -EINVAL;
        }

        if (s->type == SERVICE_DBUS && !s->bus_name) {
                log_unit_error(UNIT(s), "Service is of type D-Bus but no D-Bus service name has been specified. Refusing.");
                return -EINVAL;
        }

        if (s->bus_name && s->type != SERVICE_DBUS)
                log_unit_warning(UNIT(s), "Service has a D-Bus service name specified, but is not of type dbus. Ignoring.");

        if (s->exec_context.pam_name && !(s->kill_context.kill_mode == KILL_CONTROL_GROUP || s->kill_context.kill_mode == KILL_MIXED)) {
                log_unit_error(UNIT(s), "Service has PAM enabled. Kill mode must be set to 'control-group' or 'mixed'. Refusing.");
                return -EINVAL;
        }

        return 0;
}

static int service_add_default_dependencies(Service *s) {
        int r;

        assert(s);

        /* Add a number of automatic dependencies useful for the
         * majority of services. */

        /* First, pull in base system */
        r = unit_add_two_dependencies_by_name(UNIT(s), UNIT_AFTER, UNIT_REQUIRES, SPECIAL_BASIC_TARGET, NULL, true);
        if (r < 0)
                return r;

        /* Second, activate normal shutdown */
        return unit_add_two_dependencies_by_name(UNIT(s), UNIT_BEFORE, UNIT_CONFLICTS, SPECIAL_SHUTDOWN_TARGET, NULL, true);
}

static void service_fix_output(Service *s) {
        assert(s);

        /* If nothing has been explicitly configured, patch default
         * output in. If input is socket/tty we avoid this however,
         * since in that case we want output to default to the same
         * place as we read input from. */

        if (s->exec_context.std_error == EXEC_OUTPUT_INHERIT &&
            s->exec_context.std_output == EXEC_OUTPUT_INHERIT &&
            s->exec_context.std_input == EXEC_INPUT_NULL)
                s->exec_context.std_error = UNIT(s)->manager->default_std_error;

        if (s->exec_context.std_output == EXEC_OUTPUT_INHERIT &&
            s->exec_context.std_input == EXEC_INPUT_NULL)
                s->exec_context.std_output = UNIT(s)->manager->default_std_output;
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
                s->timeout_start_usec = 0;

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

        if (s->type == SERVICE_NOTIFY && s->notify_access == NOTIFY_NONE)
                s->notify_access = NOTIFY_MAIN;

        if (s->watchdog_usec > 0 && s->notify_access == NOTIFY_NONE)
                s->notify_access = NOTIFY_MAIN;

        if (s->bus_name) {
                const char *n;

                n = strjoina(s->bus_name, ".busname");
                r = unit_add_dependency_by_name(UNIT(s), UNIT_AFTER, n, NULL, true);
                if (r < 0)
                        return r;

                r = unit_watch_bus_name(UNIT(s), s->bus_name);
                if (r == -EEXIST)
                        return log_unit_error_errno(UNIT(s), r, "Two services allocated for the same bus name %s, refusing operation.", s->bus_name);
                if (r < 0)
                        return log_unit_error_errno(UNIT(s), r, "Cannot watch bus name %s: %m", s->bus_name);
        }

        if (UNIT(s)->default_dependencies) {
                r = service_add_default_dependencies(s);
                if (r < 0)
                        return r;
        }

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
                "%sPermissionsStartOnly: %s\n"
                "%sRootDirectoryStartOnly: %s\n"
                "%sRemainAfterExit: %s\n"
                "%sGuessMainPID: %s\n"
                "%sType: %s\n"
                "%sRestart: %s\n"
                "%sNotifyAccess: %s\n"
                "%sNotifyState: %s\n",
                prefix, service_state_to_string(s->state),
                prefix, service_result_to_string(s->result),
                prefix, service_result_to_string(s->reload_result),
                prefix, yes_no(s->permissions_start_only),
                prefix, yes_no(s->root_directory_start_only),
                prefix, yes_no(s->remain_after_exit),
                prefix, yes_no(s->guess_main_pid),
                prefix, service_type_to_string(s->type),
                prefix, service_restart_to_string(s->restart),
                prefix, notify_access_to_string(s->notify_access),
                prefix, notify_state_to_string(s->notify_state));

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

        if (s->n_fd_store_max > 0) {
                fprintf(f,
                        "%sFile Descriptor Store Max: %u\n"
                        "%sFile Descriptor Store Current: %u\n",
                        prefix, s->n_fd_store_max,
                        prefix, s->n_fd_store);
        }
}

static int service_load_pid_file(Service *s, bool may_warn) {
        _cleanup_free_ char *k = NULL;
        int r;
        pid_t pid;

        assert(s);

        if (!s->pid_file)
                return -ENOENT;

        r = read_one_line_file(s->pid_file, &k);
        if (r < 0) {
                if (may_warn)
                        log_unit_info_errno(UNIT(s), r, "PID file %s not readable (yet?) after %s: %m", s->pid_file, service_state_to_string(s->state));
                return r;
        }

        r = parse_pid(k, &pid);
        if (r < 0) {
                if (may_warn)
                        log_unit_info_errno(UNIT(s), r, "Failed to read PID from file %s: %m", s->pid_file);
                return r;
        }

        if (!pid_is_alive(pid)) {
                if (may_warn)
                        log_unit_info(UNIT(s), "PID "PID_FMT" read from file %s does not exist or is a zombie.", pid, s->pid_file);
                return -ESRCH;
        }

        if (s->main_pid_known) {
                if (pid == s->main_pid)
                        return 0;

                log_unit_debug(UNIT(s), "Main PID changing: "PID_FMT" -> "PID_FMT, s->main_pid, pid);

                service_unwatch_main_pid(s);
                s->main_pid_known = false;
        } else
                log_unit_debug(UNIT(s), "Main PID loaded: "PID_FMT, pid);

        r = service_set_main_pid(s, pid);
        if (r < 0)
                return r;

        r = unit_watch_pid(UNIT(s), pid);
        if (r < 0) {
                /* FIXME: we need to do something here */
                log_unit_warning_errno(UNIT(s), r, "Failed to watch PID "PID_FMT" for service: %m", pid);
                return r;
        }

        return 0;
}

static int service_search_main_pid(Service *s) {
        pid_t pid = 0;
        int r;

        assert(s);

        /* If we know it anyway, don't ever fallback to unreliable
         * heuristics */
        if (s->main_pid_known)
                return 0;

        if (!s->guess_main_pid)
                return 0;

        assert(s->main_pid <= 0);

        r = unit_search_main_pid(UNIT(s), &pid);
        if (r < 0)
                return r;

        log_unit_debug(UNIT(s), "Main PID guessed: "PID_FMT, pid);
        r = service_set_main_pid(s, pid);
        if (r < 0)
                return r;

        r = unit_watch_pid(UNIT(s), pid);
        if (r < 0) {
                /* FIXME: we need to do something here */
                log_unit_warning_errno(UNIT(s), r, "Failed to watch PID "PID_FMT" from: %m", pid);
                return r;
        }

        return 0;
}

static void service_set_state(Service *s, ServiceState state) {
        ServiceState old_state;
        const UnitActiveState *table;

        assert(s);

        table = s->type == SERVICE_IDLE ? state_translation_table_idle : state_translation_table;

        old_state = s->state;
        s->state = state;

        service_unwatch_pid_file(s);

        if (!IN_SET(state,
                    SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST,
                    SERVICE_RELOAD,
                    SERVICE_STOP, SERVICE_STOP_SIGABRT, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                    SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL,
                    SERVICE_AUTO_RESTART))
                s->timer_event_source = sd_event_source_unref(s->timer_event_source);

        if (!IN_SET(state,
                    SERVICE_START, SERVICE_START_POST,
                    SERVICE_RUNNING, SERVICE_RELOAD,
                    SERVICE_STOP, SERVICE_STOP_SIGABRT, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                    SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL)) {
                service_unwatch_main_pid(s);
                s->main_command = NULL;
        }

        if (!IN_SET(state,
                    SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST,
                    SERVICE_RELOAD,
                    SERVICE_STOP, SERVICE_STOP_SIGABRT, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                    SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL)) {
                service_unwatch_control_pid(s);
                s->control_command = NULL;
                s->control_command_id = _SERVICE_EXEC_COMMAND_INVALID;
        }

        if (IN_SET(state, SERVICE_DEAD, SERVICE_FAILED, SERVICE_AUTO_RESTART))
                unit_unwatch_all_pids(UNIT(s));

        if (!IN_SET(state,
                    SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST,
                    SERVICE_RUNNING, SERVICE_RELOAD,
                    SERVICE_STOP, SERVICE_STOP_SIGABRT, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                    SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL) &&
            !(state == SERVICE_DEAD && UNIT(s)->job)) {
                service_close_socket_fd(s);
                service_connection_unref(s);
        }

        if (!IN_SET(state, SERVICE_START_POST, SERVICE_RUNNING, SERVICE_RELOAD))
                service_stop_watchdog(s);

        /* For the inactive states unit_notify() will trim the cgroup,
         * but for exit we have to do that ourselves... */
        if (state == SERVICE_EXITED && UNIT(s)->manager->n_reloading <= 0)
                unit_prune_cgroup(UNIT(s));

        /* For remain_after_exit services, let's see if we can "release" the
         * hold on the console, since unit_notify() only does that in case of
         * change of state */
        if (state == SERVICE_EXITED &&
            s->remain_after_exit &&
            UNIT(s)->manager->n_on_console > 0) {

                ExecContext *ec;

                ec = unit_get_exec_context(UNIT(s));
                if (ec && exec_context_may_touch_console(ec)) {
                        Manager *m = UNIT(s)->manager;

                        m->n_on_console --;
                        if (m->n_on_console == 0)
                                /* unset no_console_output flag, since the console is free */
                                m->no_console_output = false;
                }
        }

        if (old_state != state)
                log_unit_debug(UNIT(s), "Changed %s -> %s", service_state_to_string(old_state), service_state_to_string(state));

        unit_notify(UNIT(s), table[old_state], table[state], s->reload_result == SERVICE_SUCCESS);
        s->reload_result = SERVICE_SUCCESS;
}

static int service_coldplug(Unit *u) {
        Service *s = SERVICE(u);
        int r;

        assert(s);
        assert(s->state == SERVICE_DEAD);

        if (s->deserialized_state != s->state) {

                if (IN_SET(s->deserialized_state,
                           SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST,
                           SERVICE_RELOAD,
                           SERVICE_STOP, SERVICE_STOP_SIGABRT, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                           SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL)) {

                        usec_t k;

                        k = IN_SET(s->deserialized_state, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST, SERVICE_RELOAD) ? s->timeout_start_usec : s->timeout_stop_usec;

                        /* For the start/stop timeouts 0 means off */
                        if (k > 0) {
                                r = service_arm_timer(s, k);
                                if (r < 0)
                                        return r;
                        }
                }

                if (s->deserialized_state == SERVICE_AUTO_RESTART) {

                        /* The restart timeouts 0 means immediately */
                        r = service_arm_timer(s, s->restart_usec);
                        if (r < 0)
                                return r;
                }

                if (pid_is_unwaited(s->main_pid) &&
                    ((s->deserialized_state == SERVICE_START && IN_SET(s->type, SERVICE_FORKING, SERVICE_DBUS, SERVICE_ONESHOT, SERVICE_NOTIFY)) ||
                     IN_SET(s->deserialized_state,
                            SERVICE_START, SERVICE_START_POST,
                            SERVICE_RUNNING, SERVICE_RELOAD,
                            SERVICE_STOP, SERVICE_STOP_SIGABRT, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                            SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL))) {
                        r = unit_watch_pid(UNIT(s), s->main_pid);
                        if (r < 0)
                                return r;
                }

                if (pid_is_unwaited(s->control_pid) &&
                    IN_SET(s->deserialized_state,
                           SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST,
                           SERVICE_RELOAD,
                           SERVICE_STOP, SERVICE_STOP_SIGABRT, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                           SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL)) {
                        r = unit_watch_pid(UNIT(s), s->control_pid);
                        if (r < 0)
                                return r;
                }

                if (!IN_SET(s->deserialized_state, SERVICE_DEAD, SERVICE_FAILED, SERVICE_AUTO_RESTART))
                        unit_watch_all_pids(UNIT(s));

                if (IN_SET(s->deserialized_state, SERVICE_START_POST, SERVICE_RUNNING, SERVICE_RELOAD))
                        service_start_watchdog(s);

                service_set_state(s, s->deserialized_state);
        }

        return 0;
}

static int service_collect_fds(Service *s, int **fds, unsigned *n_fds) {
        _cleanup_free_ int *rfds = NULL;
        unsigned rn_fds = 0;
        Iterator i;
        int r;
        Unit *u;

        assert(s);
        assert(fds);
        assert(n_fds);

        if (s->socket_fd >= 0)
                return 0;

        SET_FOREACH(u, UNIT(s)->dependencies[UNIT_TRIGGERED_BY], i) {
                int *cfds;
                unsigned cn_fds;
                Socket *sock;

                if (u->type != UNIT_SOCKET)
                        continue;

                sock = SOCKET(u);

                r = socket_collect_fds(sock, &cfds, &cn_fds);
                if (r < 0)
                        return r;

                if (cn_fds <= 0) {
                        free(cfds);
                        continue;
                }

                if (!rfds) {
                        rfds = cfds;
                        rn_fds = cn_fds;
                } else {
                        int *t;

                        t = realloc(rfds, (rn_fds + cn_fds) * sizeof(int));
                        if (!t) {
                                free(cfds);
                                return -ENOMEM;
                        }

                        memcpy(t + rn_fds, cfds, cn_fds * sizeof(int));
                        rfds = t;
                        rn_fds += cn_fds;

                        free(cfds);

                }
        }

        if (s->n_fd_store > 0) {
                ServiceFDStore *fs;
                int *t;

                t = realloc(rfds, (rn_fds + s->n_fd_store) * sizeof(int));
                if (!t)
                        return -ENOMEM;

                rfds = t;
                LIST_FOREACH(fd_store, fs, s->fd_store)
                        rfds[rn_fds++] = fs->fd;
        }

        *fds = rfds;
        *n_fds = rn_fds;

        rfds = NULL;
        return 0;
}

static int service_spawn(
                Service *s,
                ExecCommand *c,
                usec_t timeout,
                bool pass_fds,
                bool apply_permissions,
                bool apply_chroot,
                bool apply_tty_stdin,
                bool is_control,
                pid_t *_pid) {

        pid_t pid;
        int r;
        int *fds = NULL;
        _cleanup_free_ int *fdsbuf = NULL;
        unsigned n_fds = 0, n_env = 0;
        _cleanup_free_ char *bus_endpoint_path = NULL;
        _cleanup_strv_free_ char
                **argv = NULL, **final_env = NULL, **our_env = NULL;
        const char *path;
        ExecParameters exec_params = {
                .apply_permissions   = apply_permissions,
                .apply_chroot        = apply_chroot,
                .apply_tty_stdin     = apply_tty_stdin,
                .bus_endpoint_fd     = -1,
                .selinux_context_net = s->socket_fd_selinux_context_net
        };

        assert(s);
        assert(c);
        assert(_pid);

        (void) unit_realize_cgroup(UNIT(s));
        if (s->reset_cpu_usage) {
                (void) unit_reset_cpu_usage(UNIT(s));
                s->reset_cpu_usage = false;
        }

        r = unit_setup_exec_runtime(UNIT(s));
        if (r < 0)
                goto fail;

        if (pass_fds ||
            s->exec_context.std_input == EXEC_INPUT_SOCKET ||
            s->exec_context.std_output == EXEC_OUTPUT_SOCKET ||
            s->exec_context.std_error == EXEC_OUTPUT_SOCKET) {

                if (s->socket_fd >= 0) {
                        fds = &s->socket_fd;
                        n_fds = 1;
                } else {
                        r = service_collect_fds(s, &fdsbuf, &n_fds);
                        if (r < 0)
                                goto fail;

                        fds = fdsbuf;
                }
        }

        if (timeout > 0) {
                r = service_arm_timer(s, timeout);
                if (r < 0)
                        goto fail;
        } else
                s->timer_event_source = sd_event_source_unref(s->timer_event_source);

        r = unit_full_printf_strv(UNIT(s), c->argv, &argv);
        if (r < 0)
                goto fail;

        our_env = new0(char*, 6);
        if (!our_env) {
                r = -ENOMEM;
                goto fail;
        }

        if (is_control ? s->notify_access == NOTIFY_ALL : s->notify_access != NOTIFY_NONE)
                if (asprintf(our_env + n_env++, "NOTIFY_SOCKET=%s", UNIT(s)->manager->notify_socket) < 0) {
                        r = -ENOMEM;
                        goto fail;
                }

        if (s->main_pid > 0)
                if (asprintf(our_env + n_env++, "MAINPID="PID_FMT, s->main_pid) < 0) {
                        r = -ENOMEM;
                        goto fail;
                }

        if (UNIT(s)->manager->running_as != MANAGER_SYSTEM)
                if (asprintf(our_env + n_env++, "MANAGERPID="PID_FMT, getpid()) < 0) {
                        r = -ENOMEM;
                        goto fail;
                }

        if (UNIT_DEREF(s->accept_socket)) {
                union sockaddr_union sa;
                socklen_t salen = sizeof(sa);

                r = getpeername(s->socket_fd, &sa.sa, &salen);
                if (r < 0) {
                        r = -errno;
                        goto fail;
                }

                if (IN_SET(sa.sa.sa_family, AF_INET, AF_INET6)) {
                        _cleanup_free_ char *addr = NULL;
                        char *t;
                        int port;

                        r = sockaddr_pretty(&sa.sa, salen, true, false, &addr);
                        if (r < 0)
                                goto fail;

                        t = strappend("REMOTE_ADDR=", addr);
                        if (!t) {
                                r = -ENOMEM;
                                goto fail;
                        }
                        our_env[n_env++] = t;

                        port = sockaddr_port(&sa.sa);
                        if (port < 0) {
                                r = port;
                                goto fail;
                        }

                        if (asprintf(&t, "REMOTE_PORT=%u", port) < 0) {
                                r = -ENOMEM;
                                goto fail;
                        }
                        our_env[n_env++] = t;
                }
        }

        final_env = strv_env_merge(2, UNIT(s)->manager->environment, our_env, NULL);
        if (!final_env) {
                r = -ENOMEM;
                goto fail;
        }

        if (is_control && UNIT(s)->cgroup_path) {
                path = strjoina(UNIT(s)->cgroup_path, "/control");
                cg_create(SYSTEMD_CGROUP_CONTROLLER, path);
        } else
                path = UNIT(s)->cgroup_path;

        if (s->exec_context.bus_endpoint) {
                r = bus_kernel_create_endpoint(UNIT(s)->manager->running_as == MANAGER_SYSTEM ? "system" : "user",
                                               UNIT(s)->id, &bus_endpoint_path);
                if (r < 0)
                        goto fail;

                /* Pass the fd to the exec_params so that the child process can upload the policy.
                 * Keep a reference to the fd in the service, so the endpoint is kept alive as long
                 * as the service is running. */
                exec_params.bus_endpoint_fd = s->bus_endpoint_fd = r;
        }

        exec_params.argv = argv;
        exec_params.fds = fds;
        exec_params.n_fds = n_fds;
        exec_params.environment = final_env;
        exec_params.confirm_spawn = UNIT(s)->manager->confirm_spawn;
        exec_params.cgroup_supported = UNIT(s)->manager->cgroup_supported;
        exec_params.cgroup_path = path;
        exec_params.cgroup_delegate = s->cgroup_context.delegate;
        exec_params.runtime_prefix = manager_get_runtime_prefix(UNIT(s)->manager);
        exec_params.watchdog_usec = s->watchdog_usec;
        exec_params.bus_endpoint_path = bus_endpoint_path;
        if (s->type == SERVICE_IDLE)
                exec_params.idle_pipe = UNIT(s)->manager->idle_pipe;

        r = exec_spawn(UNIT(s),
                       c,
                       &s->exec_context,
                       &exec_params,
                       s->exec_runtime,
                       &pid);
        if (r < 0)
                goto fail;

        r = unit_watch_pid(UNIT(s), pid);
        if (r < 0)
                /* FIXME: we need to do something here */
                goto fail;

        *_pid = pid;

        return 0;

fail:
        if (timeout)
                s->timer_event_source = sd_event_source_unref(s->timer_event_source);

        return r;
}

static int main_pid_good(Service *s) {
        assert(s);

        /* Returns 0 if the pid is dead, 1 if it is good, -1 if we
         * don't know */

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

_pure_ static int control_pid_good(Service *s) {
        assert(s);

        return s->control_pid > 0;
}

static int cgroup_good(Service *s) {
        int r;

        assert(s);

        if (!UNIT(s)->cgroup_path)
                return 0;

        r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, UNIT(s)->cgroup_path);
        if (r < 0)
                return r;

        return !r;
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

static void service_enter_dead(Service *s, ServiceResult f, bool allow_restart) {
        int r;
        assert(s);

        if (f != SERVICE_SUCCESS)
                s->result = f;

        service_set_state(s, s->result != SERVICE_SUCCESS ? SERVICE_FAILED : SERVICE_DEAD);

        if (s->result != SERVICE_SUCCESS) {
                log_unit_warning(UNIT(s), "Failed with result '%s'.", service_result_to_string(s->result));
                failure_action(UNIT(s)->manager, s->failure_action, s->reboot_arg);
        }

        if (allow_restart && service_shall_restart(s)) {

                r = service_arm_timer(s, s->restart_usec);
                if (r < 0)
                        goto fail;

                service_set_state(s, SERVICE_AUTO_RESTART);
        }

        /* The next restart might not be a manual stop, hence reset the flag indicating manual stops */
        s->forbid_restart = false;

        /* We want fresh tmpdirs in case service is started again immediately */
        exec_runtime_destroy(s->exec_runtime);
        s->exec_runtime = exec_runtime_unref(s->exec_runtime);

        /* Also, remove the runtime directory in */
        exec_context_destroy_runtime_directory(&s->exec_context, manager_get_runtime_prefix(UNIT(s)->manager));

        /* Try to delete the pid file. At this point it will be
         * out-of-date, and some software might be confused by it, so
         * let's remove it. */
        if (s->pid_file)
                unlink_noerrno(s->pid_file);

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to run install restart timer: %m");
        service_enter_dead(s, SERVICE_FAILURE_RESOURCES, false);
}

static void service_enter_stop_post(Service *s, ServiceResult f) {
        int r;
        assert(s);

        if (f != SERVICE_SUCCESS)
                s->result = f;

        service_unwatch_control_pid(s);
        unit_watch_all_pids(UNIT(s));

        s->control_command = s->exec_command[SERVICE_EXEC_STOP_POST];
        if (s->control_command) {
                s->control_command_id = SERVICE_EXEC_STOP_POST;

                r = service_spawn(s,
                                  s->control_command,
                                  s->timeout_stop_usec,
                                  false,
                                  !s->permissions_start_only,
                                  !s->root_directory_start_only,
                                  true,
                                  true,
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

        case SERVICE_STOP_SIGABRT:
                return KILL_ABORT;

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

        if (f != SERVICE_SUCCESS)
                s->result = f;

        unit_watch_all_pids(UNIT(s));

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
                if (s->timeout_stop_usec > 0) {
                        r = service_arm_timer(s, s->timeout_stop_usec);
                        if (r < 0)
                                goto fail;
                }

                service_set_state(s, state);
        } else if (IN_SET(state, SERVICE_STOP_SIGABRT, SERVICE_STOP_SIGTERM) && s->kill_context.send_sigkill)
                service_enter_signal(s, SERVICE_STOP_SIGKILL, SERVICE_SUCCESS);
        else if (IN_SET(state, SERVICE_STOP_SIGABRT, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL))
                service_enter_stop_post(s, SERVICE_SUCCESS);
        else if (state == SERVICE_FINAL_SIGTERM && s->kill_context.send_sigkill)
                service_enter_signal(s, SERVICE_FINAL_SIGKILL, SERVICE_SUCCESS);
        else
                service_enter_dead(s, SERVICE_SUCCESS, true);

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to kill processes: %m");

        if (IN_SET(state, SERVICE_STOP_SIGABRT, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL))
                service_enter_stop_post(s, SERVICE_FAILURE_RESOURCES);
        else
                service_enter_dead(s, SERVICE_FAILURE_RESOURCES, true);
}

static void service_enter_stop_by_notify(Service *s) {
        assert(s);

        unit_watch_all_pids(UNIT(s));

        if (s->timeout_stop_usec > 0)
                service_arm_timer(s, s->timeout_stop_usec);

        /* The service told us it's stopping, so it's as if we SIGTERM'd it. */
        service_set_state(s, SERVICE_STOP_SIGTERM);
}

static void service_enter_stop(Service *s, ServiceResult f) {
        int r;

        assert(s);

        if (f != SERVICE_SUCCESS)
                s->result = f;

        service_unwatch_control_pid(s);
        unit_watch_all_pids(UNIT(s));

        s->control_command = s->exec_command[SERVICE_EXEC_STOP];
        if (s->control_command) {
                s->control_command_id = SERVICE_EXEC_STOP;

                r = service_spawn(s,
                                  s->control_command,
                                  s->timeout_stop_usec,
                                  false,
                                  !s->permissions_start_only,
                                  !s->root_directory_start_only,
                                  false,
                                  true,
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

        if (f != SERVICE_SUCCESS)
                s->result = f;

        if (service_good(s)) {

                /* If there are any queued up sd_notify()
                 * notifications, process them now */
                if (s->notify_state == NOTIFY_RELOADING)
                        service_enter_reload_by_notify(s);
                else if (s->notify_state == NOTIFY_STOPPING)
                        service_enter_stop_by_notify(s);
                else
                        service_set_state(s, SERVICE_RUNNING);

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
                                  false,
                                  !s->permissions_start_only,
                                  !s->root_directory_start_only,
                                  false,
                                  true,
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

static void service_kill_control_processes(Service *s) {
        char *p;

        if (!UNIT(s)->cgroup_path)
                return;

        p = strjoina(UNIT(s)->cgroup_path, "/control");
        cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, p, SIGKILL, true, true, true, NULL);
}

static void service_enter_start(Service *s) {
        ExecCommand *c;
        pid_t pid;
        int r;

        assert(s);

        service_unwatch_control_pid(s);
        service_unwatch_main_pid(s);

        /* We want to ensure that nobody leaks processes from
         * START_PRE here, so let's go on a killing spree, People
         * should not spawn long running processes from START_PRE. */
        service_kill_control_processes(s);

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
                assert(s->type == SERVICE_ONESHOT);
                service_enter_start_post(s);
                return;
        }

        r = service_spawn(s,
                          c,
                          IN_SET(s->type, SERVICE_FORKING, SERVICE_DBUS, SERVICE_NOTIFY, SERVICE_ONESHOT) ? s->timeout_start_usec : 0,
                          true,
                          true,
                          true,
                          true,
                          false,
                          &pid);
        if (r < 0)
                goto fail;

        if (s->type == SERVICE_SIMPLE || s->type == SERVICE_IDLE) {
                /* For simple services we immediately start
                 * the START_POST binaries. */

                service_set_main_pid(s, pid);
                service_enter_start_post(s);

        } else  if (s->type == SERVICE_FORKING) {

                /* For forking services we wait until the start
                 * process exited. */

                s->control_pid = pid;
                service_set_state(s, SERVICE_START);

        } else if (s->type == SERVICE_ONESHOT ||
                   s->type == SERVICE_DBUS ||
                   s->type == SERVICE_NOTIFY) {

                /* For oneshot services we wait until the start
                 * process exited, too, but it is our main process. */

                /* For D-Bus services we know the main pid right away,
                 * but wait for the bus name to appear on the
                 * bus. Notify services are similar. */

                service_set_main_pid(s, pid);
                service_set_state(s, SERVICE_START);
        } else
                assert_not_reached("Unknown service type");

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to run 'start' task: %m");
        service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_FAILURE_RESOURCES);
}

static void service_enter_start_pre(Service *s) {
        int r;

        assert(s);

        service_unwatch_control_pid(s);

        s->control_command = s->exec_command[SERVICE_EXEC_START_PRE];
        if (s->control_command) {
                /* Before we start anything, let's clear up what might
                 * be left from previous runs. */
                service_kill_control_processes(s);

                s->control_command_id = SERVICE_EXEC_START_PRE;

                r = service_spawn(s,
                                  s->control_command,
                                  s->timeout_start_usec,
                                  false,
                                  !s->permissions_start_only,
                                  !s->root_directory_start_only,
                                  true,
                                  true,
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

static void service_enter_restart(Service *s) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(s);

        if (UNIT(s)->job && UNIT(s)->job->type == JOB_STOP) {
                /* Don't restart things if we are going down anyway */
                log_unit_info(UNIT(s), "Stop job pending for unit, delaying automatic restart.");

                r = service_arm_timer(s, s->restart_usec);
                if (r < 0)
                        goto fail;

                return;
        }

        /* Any units that are bound to this service must also be
         * restarted. We use JOB_RESTART (instead of the more obvious
         * JOB_START) here so that those dependency jobs will be added
         * as well. */
        r = manager_add_job(UNIT(s)->manager, JOB_RESTART, UNIT(s), JOB_FAIL, false, &error, NULL);
        if (r < 0)
                goto fail;

        /* Note that we stay in the SERVICE_AUTO_RESTART state here,
         * it will be canceled as part of the service_stop() call that
         * is executed as part of JOB_RESTART. */

        log_unit_debug(UNIT(s), "Scheduled restart job.");
        return;

fail:
        log_unit_warning(UNIT(s), "Failed to schedule restart job: %s", bus_error_message(&error, -r));
        service_enter_dead(s, SERVICE_FAILURE_RESOURCES, false);
}

static void service_enter_reload_by_notify(Service *s) {
        assert(s);

        if (s->timeout_start_usec > 0)
                service_arm_timer(s, s->timeout_start_usec);

        service_set_state(s, SERVICE_RELOAD);
}

static void service_enter_reload(Service *s) {
        int r;

        assert(s);

        service_unwatch_control_pid(s);

        s->control_command = s->exec_command[SERVICE_EXEC_RELOAD];
        if (s->control_command) {
                s->control_command_id = SERVICE_EXEC_RELOAD;

                r = service_spawn(s,
                                  s->control_command,
                                  s->timeout_start_usec,
                                  false,
                                  !s->permissions_start_only,
                                  !s->root_directory_start_only,
                                  false,
                                  true,
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
        int r;

        assert(s);
        assert(s->control_command);
        assert(s->control_command->command_next);

        assert(s->control_command_id != SERVICE_EXEC_START);

        s->control_command = s->control_command->command_next;
        service_unwatch_control_pid(s);

        r = service_spawn(s,
                          s->control_command,
                          IN_SET(s->state, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST, SERVICE_RUNNING, SERVICE_RELOAD) ? s->timeout_start_usec : s->timeout_stop_usec,
                          false,
                          !s->permissions_start_only,
                          !s->root_directory_start_only,
                          s->control_command_id == SERVICE_EXEC_START_PRE ||
                          s->control_command_id == SERVICE_EXEC_STOP_POST,
                          true,
                          &s->control_pid);
        if (r < 0)
                goto fail;

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to run next control task: %m");

        if (s->state == SERVICE_START_PRE)
                service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_FAILURE_RESOURCES);
        else if (s->state == SERVICE_STOP)
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
                          true,
                          true,
                          true,
                          true,
                          false,
                          &pid);
        if (r < 0)
                goto fail;

        service_set_main_pid(s, pid);

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to run next main task: %m");
        service_enter_stop(s, SERVICE_FAILURE_RESOURCES);
}

static int service_start_limit_test(Service *s) {
        assert(s);

        if (ratelimit_test(&s->start_limit))
                return 0;

        log_unit_warning(UNIT(s), "Start request repeated too quickly.");

        return failure_action(UNIT(s)->manager, s->start_limit_action, s->reboot_arg);
}

static int service_start(Unit *u) {
        Service *s = SERVICE(u);
        int r;

        assert(s);

        /* We cannot fulfill this request right now, try again later
         * please! */
        if (IN_SET(s->state,
                   SERVICE_STOP, SERVICE_STOP_SIGABRT, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                   SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL))
                return -EAGAIN;

        /* Already on it! */
        if (IN_SET(s->state, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST))
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
        r = service_start_limit_test(s);
        if (r < 0) {
                service_enter_dead(s, SERVICE_FAILURE_START_LIMIT, false);
                return r;
        }

        s->result = SERVICE_SUCCESS;
        s->reload_result = SERVICE_SUCCESS;
        s->main_pid_known = false;
        s->main_pid_alien = false;
        s->forbid_restart = false;
        s->reset_cpu_usage = true;

        free(s->status_text);
        s->status_text = NULL;
        s->status_errno = 0;

        s->notify_state = NOTIFY_UNKNOWN;

        service_enter_start_pre(s);
        return 1;
}

static int service_stop(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        /* Don't create restart jobs from manual stops. */
        s->forbid_restart = true;

        /* Already on it */
        if (IN_SET(s->state,
                   SERVICE_STOP, SERVICE_STOP_SIGABRT, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL, SERVICE_STOP_POST,
                   SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL))
                return 0;

        /* A restart will be scheduled or is in progress. */
        if (s->state == SERVICE_AUTO_RESTART) {
                service_set_state(s, SERVICE_DEAD);
                return 0;
        }

        /* If there's already something running we go directly into
         * kill mode. */
        if (IN_SET(s->state, SERVICE_START_PRE, SERVICE_START, SERVICE_START_POST, SERVICE_RELOAD)) {
                service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_SUCCESS);
                return 0;
        }

        assert(IN_SET(s->state, SERVICE_RUNNING, SERVICE_EXITED));

        service_enter_stop(s, SERVICE_SUCCESS);
        return 1;
}

static int service_reload(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        assert(s->state == SERVICE_RUNNING || s->state == SERVICE_EXITED);

        service_enter_reload(s);
        return 1;
}

_pure_ static bool service_can_reload(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        return !!s->exec_command[SERVICE_EXEC_RELOAD];
}

static int service_serialize(Unit *u, FILE *f, FDSet *fds) {
        Service *s = SERVICE(u);
        ServiceFDStore *fs;

        assert(u);
        assert(f);
        assert(fds);

        unit_serialize_item(u, f, "state", service_state_to_string(s->state));
        unit_serialize_item(u, f, "result", service_result_to_string(s->result));
        unit_serialize_item(u, f, "reload-result", service_result_to_string(s->reload_result));

        if (s->control_pid > 0)
                unit_serialize_item_format(u, f, "control-pid", PID_FMT, s->control_pid);

        if (s->main_pid_known && s->main_pid > 0)
                unit_serialize_item_format(u, f, "main-pid", PID_FMT, s->main_pid);

        unit_serialize_item(u, f, "main-pid-known", yes_no(s->main_pid_known));
        unit_serialize_item(u, f, "bus-name-good", yes_no(s->bus_name_good));

        if (s->status_text) {
                _cleanup_free_ char *c = NULL;

                c = cescape(s->status_text);
                unit_serialize_item(u, f, "status-text", strempty(c));
        }

        /* FIXME: There's a minor uncleanliness here: if there are
         * multiple commands attached here, we will start from the
         * first one again */
        if (s->control_command_id >= 0)
                unit_serialize_item(u, f, "control-command", service_exec_command_to_string(s->control_command_id));

        if (s->socket_fd >= 0) {
                int copy;

                copy = fdset_put_dup(fds, s->socket_fd);
                if (copy < 0)
                        return copy;

                unit_serialize_item_format(u, f, "socket-fd", "%i", copy);
        }

        if (s->bus_endpoint_fd >= 0) {
                int copy;

                copy = fdset_put_dup(fds, s->bus_endpoint_fd);
                if (copy < 0)
                        return copy;

                unit_serialize_item_format(u, f, "endpoint-fd", "%i", copy);
        }

        LIST_FOREACH(fd_store, fs, s->fd_store) {
                int copy;

                copy = fdset_put_dup(fds, fs->fd);
                if (copy < 0)
                        return copy;

                unit_serialize_item_format(u, f, "fd-store-fd", "%i", copy);
        }

        if (s->main_exec_status.pid > 0) {
                unit_serialize_item_format(u, f, "main-exec-status-pid", PID_FMT, s->main_exec_status.pid);
                dual_timestamp_serialize(f, "main-exec-status-start", &s->main_exec_status.start_timestamp);
                dual_timestamp_serialize(f, "main-exec-status-exit", &s->main_exec_status.exit_timestamp);

                if (dual_timestamp_is_set(&s->main_exec_status.exit_timestamp)) {
                        unit_serialize_item_format(u, f, "main-exec-status-code", "%i", s->main_exec_status.code);
                        unit_serialize_item_format(u, f, "main-exec-status-status", "%i", s->main_exec_status.status);
                }
        }

        if (dual_timestamp_is_set(&s->watchdog_timestamp))
                dual_timestamp_serialize(f, "watchdog-timestamp", &s->watchdog_timestamp);

        if (s->forbid_restart)
                unit_serialize_item(u, f, "forbid-restart", yes_no(s->forbid_restart));

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
                else {
                        service_set_main_pid(s, pid);
                        unit_watch_pid(UNIT(s), pid);
                }
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
        } else if (streq(key, "status-text")) {
                char *t;

                r = cunescape(value, 0, &t);
                if (r < 0)
                        log_unit_debug_errno(u, r, "Failed to unescape status text: %s", value);
                else {
                        free(s->status_text);
                        s->status_text = t;
                }

        } else if (streq(key, "control-command")) {
                ServiceExecCommand id;

                id = service_exec_command_from_string(value);
                if (id < 0)
                        log_unit_debug(u, "Failed to parse exec-command value: %s", value);
                else {
                        s->control_command_id = id;
                        s->control_command = s->exec_command[id];
                }
        } else if (streq(key, "socket-fd")) {
                int fd;

                if (safe_atoi(value, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse socket-fd value: %s", value);
                else {
                        asynchronous_close(s->socket_fd);
                        s->socket_fd = fdset_remove(fds, fd);
                }
        } else if (streq(key, "endpoint-fd")) {
                int fd;

                if (safe_atoi(value, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse endpoint-fd value: %s", value);
                else {
                        safe_close(s->bus_endpoint_fd);
                        s->bus_endpoint_fd = fdset_remove(fds, fd);
                }
        } else if (streq(key, "fd-store-fd")) {
                int fd;

                if (safe_atoi(value, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse fd-store-fd value: %s", value);
                else {
                        r = service_add_fd_store(s, fd);
                        if (r < 0)
                                log_unit_error_errno(u, r, "Failed to add fd to store: %m");
                        else if (r > 0)
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
                dual_timestamp_deserialize(value, &s->main_exec_status.start_timestamp);
        else if (streq(key, "main-exec-status-exit"))
                dual_timestamp_deserialize(value, &s->main_exec_status.exit_timestamp);
        else if (streq(key, "watchdog-timestamp"))
                dual_timestamp_deserialize(value, &s->watchdog_timestamp);
        else if (streq(key, "forbid-restart")) {
                int b;

                b = parse_boolean(value);
                if (b < 0)
                        log_unit_debug(u, "Failed to parse forbid-restart value: %s", value);
                else
                        s->forbid_restart = b;
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

static bool service_check_gc(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        /* Never clean up services that still have a process around,
         * even if the service is formally dead. */
        if (cgroup_good(s) > 0 ||
            main_pid_good(s) > 0 ||
            control_pid_good(s) > 0)
                return true;

        return false;
}

_pure_ static bool service_check_snapshot(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        return s->socket_fd < 0;
}

static int service_retry_pid_file(Service *s) {
        int r;

        assert(s->pid_file);
        assert(s->state == SERVICE_START || s->state == SERVICE_START_POST);

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

        r = path_spec_watch(s->pid_file_pathspec, service_dispatch_io);
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

        path_kill_slashes(ps->path);

        /* PATH_CHANGED would not be enough. There are daemons (sendmail) that
         * keep their PID file open all the time. */
        ps->type = PATH_MODIFIED;
        ps->inotify_fd = -1;

        s->pid_file_pathspec = ps;

        return service_watch_pid_file(s);
}

static int service_dispatch_io(sd_event_source *source, int fd, uint32_t events, void *userdata) {
        PathSpec *p = userdata;
        Service *s;

        assert(p);

        s = SERVICE(p->unit);

        assert(s);
        assert(fd >= 0);
        assert(s->state == SERVICE_START || s->state == SERVICE_START_POST);
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

static void service_notify_cgroup_empty_event(Unit *u) {
        Service *s = SERVICE(u);

        assert(u);

        log_unit_debug(u, "cgroup is empty");

        switch (s->state) {

                /* Waiting for SIGCHLD is usually more interesting,
                 * because it includes return codes/signals. Which is
                 * why we ignore the cgroup events for most cases,
                 * except when we don't know pid which to expect the
                 * SIGCHLD for. */

        case SERVICE_START:
        case SERVICE_START_POST:
                /* If we were hoping for the daemon to write its PID file,
                 * we can give up now. */
                if (s->pid_file_pathspec) {
                        log_unit_warning(u, "Daemon never wrote its PID file. Failing.");

                        service_unwatch_pid_file(s);
                        if (s->state == SERVICE_START)
                                service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_FAILURE_RESOURCES);
                        else
                                service_enter_stop(s, SERVICE_FAILURE_RESOURCES);
                }
                break;

        case SERVICE_RUNNING:
                /* service_enter_running() will figure out what to do */
                service_enter_running(s, SERVICE_SUCCESS);
                break;

        case SERVICE_STOP_SIGABRT:
        case SERVICE_STOP_SIGTERM:
        case SERVICE_STOP_SIGKILL:

                if (main_pid_good(s) <= 0 && !control_pid_good(s))
                        service_enter_stop_post(s, SERVICE_SUCCESS);

                break;

        case SERVICE_STOP_POST:
        case SERVICE_FINAL_SIGTERM:
        case SERVICE_FINAL_SIGKILL:
                if (main_pid_good(s) <= 0 && !control_pid_good(s))
                        service_enter_dead(s, SERVICE_SUCCESS, true);

                break;

        default:
                ;
        }
}

static void service_sigchld_event(Unit *u, pid_t pid, int code, int status) {
        Service *s = SERVICE(u);
        ServiceResult f;

        assert(s);
        assert(pid >= 0);

        if (UNIT(s)->fragment_path ? is_clean_exit(code, status, &s->success_status) :
                                     is_clean_exit_lsb(code, status, &s->success_status))
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
                if (service_load_pid_file(s, false) == 0)
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

                        if (s->main_command->ignore)
                                f = SERVICE_SUCCESS;
                } else if (s->exec_command[SERVICE_EXEC_START]) {

                        /* If this is a forked process, then we should
                         * ignore the return value if this was
                         * configured for the starter process */

                        if (s->exec_command[SERVICE_EXEC_START]->ignore)
                                f = SERVICE_SUCCESS;
                }

                log_struct(f == SERVICE_SUCCESS ? LOG_DEBUG : LOG_NOTICE,
                           LOG_UNIT_ID(u),
                           LOG_UNIT_MESSAGE(u, "Main process exited, code=%s, status=%i/%s",
                                            sigchld_code_to_string(code), status,
                                            strna(code == CLD_EXITED
                                                  ? exit_status_to_string(status, EXIT_STATUS_FULL)
                                                  : signal_to_string(status))),
                           "EXIT_CODE=%s", sigchld_code_to_string(code),
                           "EXIT_STATUS=%i", status,
                           NULL);

                if (f != SERVICE_SUCCESS)
                        s->result = f;

                if (s->main_command &&
                    s->main_command->command_next &&
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
                                                service_enter_signal(s, SERVICE_FINAL_SIGTERM, f);
                                        break;
                                }

                                /* Fall through */

                        case SERVICE_RUNNING:
                                service_enter_running(s, f);
                                break;

                        case SERVICE_STOP_SIGABRT:
                        case SERVICE_STOP_SIGTERM:
                        case SERVICE_STOP_SIGKILL:

                                if (!control_pid_good(s))
                                        service_enter_stop_post(s, f);

                                /* If there is still a control process, wait for that first */
                                break;

                        case SERVICE_STOP_POST:
                        case SERVICE_FINAL_SIGTERM:
                        case SERVICE_FINAL_SIGKILL:

                                if (!control_pid_good(s))
                                        service_enter_dead(s, f, true);
                                break;

                        default:
                                assert_not_reached("Uh, main process died at wrong time.");
                        }
                }

        } else if (s->control_pid == pid) {
                s->control_pid = 0;

                if (s->control_command) {
                        exec_status_exit(&s->control_command->exec_status, &s->exec_context, pid, code, status);

                        if (s->control_command->ignore)
                                f = SERVICE_SUCCESS;
                }

                log_unit_full(u, f == SERVICE_SUCCESS ? LOG_DEBUG : LOG_NOTICE, 0,
                              "Control process exited, code=%s status=%i",
                              sigchld_code_to_string(code), status);

                if (f != SERVICE_SUCCESS)
                        s->result = f;

                /* Immediately get rid of the cgroup, so that the
                 * kernel doesn't delay the cgroup empty messages for
                 * the service cgroup any longer than necessary */
                service_kill_control_processes(s);

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

                        case SERVICE_START_PRE:
                                if (f == SERVICE_SUCCESS)
                                        service_enter_start(s);
                                else
                                        service_enter_signal(s, SERVICE_FINAL_SIGTERM, f);
                                break;

                        case SERVICE_START:
                                if (s->type != SERVICE_FORKING)
                                        /* Maybe spurious event due to a reload that changed the type? */
                                        break;

                                if (f != SERVICE_SUCCESS) {
                                        service_enter_signal(s, SERVICE_FINAL_SIGTERM, f);
                                        break;
                                }

                                if (s->pid_file) {
                                        bool has_start_post;
                                        int r;

                                        /* Let's try to load the pid file here if we can.
                                         * The PID file might actually be created by a START_POST
                                         * script. In that case don't worry if the loading fails. */

                                        has_start_post = !!s->exec_command[SERVICE_EXEC_START_POST];
                                        r = service_load_pid_file(s, !has_start_post);
                                        if (!has_start_post && r < 0) {
                                                r = service_demand_pid_file(s);
                                                if (r < 0 || !cgroup_good(s))
                                                        service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_FAILURE_RESOURCES);
                                                break;
                                        }
                                } else
                                        (void) service_search_main_pid(s);

                                service_enter_start_post(s);
                                break;

                        case SERVICE_START_POST:
                                if (f != SERVICE_SUCCESS) {
                                        service_enter_stop(s, f);
                                        break;
                                }

                                if (s->pid_file) {
                                        int r;

                                        r = service_load_pid_file(s, true);
                                        if (r < 0) {
                                                r = service_demand_pid_file(s);
                                                if (r < 0 || !cgroup_good(s))
                                                        service_enter_stop(s, SERVICE_FAILURE_RESOURCES);
                                                break;
                                        }
                                } else
                                        (void) service_search_main_pid(s);

                                service_enter_running(s, SERVICE_SUCCESS);
                                break;

                        case SERVICE_RELOAD:
                                if (f == SERVICE_SUCCESS) {
                                        service_load_pid_file(s, true);
                                        (void) service_search_main_pid(s);
                                }

                                s->reload_result = f;
                                service_enter_running(s, SERVICE_SUCCESS);
                                break;

                        case SERVICE_STOP:
                                service_enter_signal(s, SERVICE_STOP_SIGTERM, f);
                                break;

                        case SERVICE_STOP_SIGABRT:
                        case SERVICE_STOP_SIGTERM:
                        case SERVICE_STOP_SIGKILL:
                                if (main_pid_good(s) <= 0)
                                        service_enter_stop_post(s, f);

                                /* If there is still a service
                                 * process around, wait until
                                 * that one quit, too */
                                break;

                        case SERVICE_STOP_POST:
                        case SERVICE_FINAL_SIGTERM:
                        case SERVICE_FINAL_SIGKILL:
                                if (main_pid_good(s) <= 0)
                                        service_enter_dead(s, f, true);
                                break;

                        default:
                                assert_not_reached("Uh, control process died at wrong time.");
                        }
                }
        }

        /* Notify clients about changed exit status */
        unit_add_to_dbus_queue(u);

        /* We got one SIGCHLD for the service, let's watch all
         * processes that are now running of the service, and watch
         * that. Among the PIDs we then watch will be children
         * reassigned to us, which hopefully allows us to identify
         * when all children are gone */
        unit_tidy_watch_pids(u, s->main_pid, s->control_pid);
        unit_watch_all_pids(u);

        /* If the PID set is empty now, then let's finish this off */
        if (set_isempty(u->pids))
                service_notify_cgroup_empty_event(u);
}

static int service_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata) {
        Service *s = SERVICE(userdata);

        assert(s);
        assert(source == s->timer_event_source);

        switch (s->state) {

        case SERVICE_START_PRE:
        case SERVICE_START:
                log_unit_warning(UNIT(s), "%s operation timed out. Terminating.", s->state == SERVICE_START ? "Start" : "Start-pre");
                service_enter_signal(s, SERVICE_FINAL_SIGTERM, SERVICE_FAILURE_TIMEOUT);
                break;

        case SERVICE_START_POST:
                log_unit_warning(UNIT(s), "Start-post operation timed out. Stopping.");
                service_enter_stop(s, SERVICE_FAILURE_TIMEOUT);
                break;

        case SERVICE_RELOAD:
                log_unit_warning(UNIT(s), "Reload operation timed out. Stopping.");
                s->reload_result = SERVICE_FAILURE_TIMEOUT;
                service_enter_running(s, SERVICE_SUCCESS);
                break;

        case SERVICE_STOP:
                log_unit_warning(UNIT(s), "Stopping timed out. Terminating.");
                service_enter_signal(s, SERVICE_STOP_SIGTERM, SERVICE_FAILURE_TIMEOUT);
                break;

        case SERVICE_STOP_SIGABRT:
                log_unit_warning(UNIT(s), "State 'stop-sigabrt' timed out. Terminating.");
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
                log_unit_info(UNIT(s),
                              s->restart_usec > 0 ?
                              "Service hold-off time over, scheduling restart." :
                              "Service has no hold-off time, scheduling restart.");
                service_enter_restart(s);
                break;

        default:
                assert_not_reached("Timeout at wrong time.");
        }

        return 0;
}

static int service_dispatch_watchdog(sd_event_source *source, usec_t usec, void *userdata) {
        Service *s = SERVICE(userdata);
        char t[FORMAT_TIMESPAN_MAX];

        assert(s);
        assert(source == s->watchdog_event_source);

        log_unit_error(UNIT(s), "Watchdog timeout (limit %s)!",
                       format_timespan(t, sizeof(t), s->watchdog_usec, 1));

        service_enter_signal(s, SERVICE_STOP_SIGABRT, SERVICE_FAILURE_WATCHDOG);

        return 0;
}

static void service_notify_message(Unit *u, pid_t pid, char **tags, FDSet *fds) {
        Service *s = SERVICE(u);
        _cleanup_free_ char *cc = NULL;
        bool notify_dbus = false;
        const char *e;

        assert(u);

        cc = strv_join(tags, ", ");

        if (s->notify_access == NOTIFY_NONE) {
                log_unit_warning(u, "Got notification message from PID "PID_FMT", but reception is disabled.", pid);
                return;
        } else if (s->notify_access == NOTIFY_MAIN && pid != s->main_pid) {
                if (s->main_pid != 0)
                        log_unit_warning(u, "Got notification message from PID "PID_FMT", but reception only permitted for main PID "PID_FMT, pid, s->main_pid);
                else
                        log_unit_debug(u, "Got notification message from PID "PID_FMT", but reception only permitted for main PID which is currently not known", pid);
                return;
        } else
                log_unit_debug(u, "Got notification message from PID "PID_FMT" (%s)", pid, isempty(cc) ? "n/a" : cc);

        /* Interpret MAINPID= */
        e = strv_find_startswith(tags, "MAINPID=");
        if (e && IN_SET(s->state, SERVICE_START, SERVICE_START_POST, SERVICE_RUNNING, SERVICE_RELOAD)) {
                if (parse_pid(e, &pid) < 0)
                        log_unit_warning(u, "Failed to parse MAINPID= field in notification message: %s", e);
                else {
                        service_set_main_pid(s, pid);
                        unit_watch_pid(UNIT(s), pid);
                        notify_dbus = true;
                }
        }

        /* Interpret RELOADING= */
        if (strv_find(tags, "RELOADING=1")) {

                s->notify_state = NOTIFY_RELOADING;

                if (s->state == SERVICE_RUNNING)
                        service_enter_reload_by_notify(s);

                notify_dbus = true;
        }

        /* Interpret READY= */
        if (strv_find(tags, "READY=1")) {

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
        }

        /* Interpret STOPPING= */
        if (strv_find(tags, "STOPPING=1")) {

                s->notify_state = NOTIFY_STOPPING;

                if (s->state == SERVICE_RUNNING)
                        service_enter_stop_by_notify(s);

                notify_dbus = true;
        }

        /* Interpret STATUS= */
        e = strv_find_startswith(tags, "STATUS=");
        if (e) {
                _cleanup_free_ char *t = NULL;

                if (!isempty(e)) {
                        if (!utf8_is_valid(e))
                                log_unit_warning(u, "Status message in notification message is not UTF-8 clean.");
                        else {
                                t = strdup(e);
                                if (!t)
                                        log_oom();
                        }
                }

                if (!streq_ptr(s->status_text, t)) {

                        free(s->status_text);
                        s->status_text = t;
                        t = NULL;

                        notify_dbus = true;
                }
        }

        /* Interpret ERRNO= */
        e = strv_find_startswith(tags, "ERRNO=");
        if (e) {
                int status_errno;

                if (safe_atoi(e, &status_errno) < 0 || status_errno < 0)
                        log_unit_warning(u, "Failed to parse ERRNO= field in notification message: %s", e);
                else {
                        if (s->status_errno != status_errno) {
                                s->status_errno = status_errno;
                                notify_dbus = true;
                        }
                }
        }

        /* Interpret WATCHDOG= */
        if (strv_find(tags, "WATCHDOG=1")) {
                service_reset_watchdog(s);
        }

        /* Add the passed fds to the fd store */
        if (strv_find(tags, "FDSTORE=1")) {
                service_add_fd_store_set(s, fds);
        }

        /* Notify clients about changed status or main pid */
        if (notify_dbus)
                unit_add_to_dbus_queue(u);
}

static int service_get_timeout(Unit *u, uint64_t *timeout) {
        Service *s = SERVICE(u);
        int r;

        if (!s->timer_event_source)
                return 0;

        r = sd_event_source_get_time(s->timer_event_source, timeout);
        if (r < 0)
                return r;

        return 1;
}

static void service_bus_name_owner_change(
                Unit *u,
                const char *name,
                const char *old_owner,
                const char *new_owner) {

        Service *s = SERVICE(u);
        int r;

        assert(s);
        assert(name);

        assert(streq(s->bus_name, name));
        assert(old_owner || new_owner);

        if (old_owner && new_owner)
                log_unit_debug(u, "D-Bus name %s changed owner from %s to %s", name, old_owner, new_owner);
        else if (old_owner)
                log_unit_debug(u, "D-Bus name %s no longer registered by %s", name, old_owner);
        else
                log_unit_debug(u, "D-Bus name %s now registered by %s", name, new_owner);

        s->bus_name_good = !!new_owner;

        if (s->type == SERVICE_DBUS) {

                /* service_enter_running() will figure out what to
                 * do */
                if (s->state == SERVICE_RUNNING)
                        service_enter_running(s, SERVICE_SUCCESS);
                else if (s->state == SERVICE_START && new_owner)
                        service_enter_start_post(s);

        } else if (new_owner &&
                   s->main_pid <= 0 &&
                   (s->state == SERVICE_START ||
                    s->state == SERVICE_START_POST ||
                    s->state == SERVICE_RUNNING ||
                    s->state == SERVICE_RELOAD)) {

                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                pid_t pid;

                /* Try to acquire PID from bus service */

                r = sd_bus_get_name_creds(u->manager->api_bus, name, SD_BUS_CREDS_PID, &creds);
                if (r >= 0)
                        r = sd_bus_creds_get_pid(creds, &pid);
                if (r >= 0) {
                        log_unit_debug(u, "D-Bus name %s is now owned by process %u", name, (unsigned) pid);

                        service_set_main_pid(s, pid);
                        unit_watch_pid(UNIT(s), pid);
                }
        }
}

int service_set_socket_fd(Service *s, int fd, Socket *sock, bool selinux_context_net) {
        _cleanup_free_ char *peer = NULL;
        int r;

        assert(s);
        assert(fd >= 0);

        /* This is called by the socket code when instantiating a new
         * service for a stream socket and the socket needs to be
         * configured. */

        if (UNIT(s)->load_state != UNIT_LOADED)
                return -EINVAL;

        if (s->socket_fd >= 0)
                return -EBUSY;

        if (s->state != SERVICE_DEAD)
                return -EAGAIN;

        if (getpeername_pretty(fd, &peer) >= 0) {

                if (UNIT(s)->description) {
                        _cleanup_free_ char *a;

                        a = strjoin(UNIT(s)->description, " (", peer, ")", NULL);
                        if (!a)
                                return -ENOMEM;

                        r = unit_set_description(UNIT(s), a);
                }  else
                        r = unit_set_description(UNIT(s), peer);

                if (r < 0)
                        return r;
        }

        s->socket_fd = fd;
        s->socket_fd_selinux_context_net = selinux_context_net;

        unit_ref_set(&s->accept_socket, UNIT(sock));

        return unit_add_two_dependencies(UNIT(sock), UNIT_BEFORE, UNIT_TRIGGERS, UNIT(s), false);
}

static void service_reset_failed(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        if (s->state == SERVICE_FAILED)
                service_set_state(s, SERVICE_DEAD);

        s->result = SERVICE_SUCCESS;
        s->reload_result = SERVICE_SUCCESS;

        RATELIMIT_RESET(s->start_limit);
}

static int service_kill(Unit *u, KillWho who, int signo, sd_bus_error *error) {
        Service *s = SERVICE(u);

        return unit_kill_common(u, who, signo, s->main_pid, s->control_pid, error);
}

static const char* const service_state_table[_SERVICE_STATE_MAX] = {
        [SERVICE_DEAD] = "dead",
        [SERVICE_START_PRE] = "start-pre",
        [SERVICE_START] = "start",
        [SERVICE_START_POST] = "start-post",
        [SERVICE_RUNNING] = "running",
        [SERVICE_EXITED] = "exited",
        [SERVICE_RELOAD] = "reload",
        [SERVICE_STOP] = "stop",
        [SERVICE_STOP_SIGABRT] = "stop-sigabrt",
        [SERVICE_STOP_SIGTERM] = "stop-sigterm",
        [SERVICE_STOP_SIGKILL] = "stop-sigkill",
        [SERVICE_STOP_POST] = "stop-post",
        [SERVICE_FINAL_SIGTERM] = "final-sigterm",
        [SERVICE_FINAL_SIGKILL] = "final-sigkill",
        [SERVICE_FAILED] = "failed",
        [SERVICE_AUTO_RESTART] = "auto-restart",
};

DEFINE_STRING_TABLE_LOOKUP(service_state, ServiceState);

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
        [SERVICE_IDLE] = "idle"
};

DEFINE_STRING_TABLE_LOOKUP(service_type, ServiceType);

static const char* const service_exec_command_table[_SERVICE_EXEC_COMMAND_MAX] = {
        [SERVICE_EXEC_START_PRE] = "ExecStartPre",
        [SERVICE_EXEC_START] = "ExecStart",
        [SERVICE_EXEC_START_POST] = "ExecStartPost",
        [SERVICE_EXEC_RELOAD] = "ExecReload",
        [SERVICE_EXEC_STOP] = "ExecStop",
        [SERVICE_EXEC_STOP_POST] = "ExecStopPost",
};

DEFINE_STRING_TABLE_LOOKUP(service_exec_command, ServiceExecCommand);

static const char* const notify_access_table[_NOTIFY_ACCESS_MAX] = {
        [NOTIFY_NONE] = "none",
        [NOTIFY_MAIN] = "main",
        [NOTIFY_ALL] = "all"
};

DEFINE_STRING_TABLE_LOOKUP(notify_access, NotifyAccess);

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
        [SERVICE_FAILURE_TIMEOUT] = "timeout",
        [SERVICE_FAILURE_EXIT_CODE] = "exit-code",
        [SERVICE_FAILURE_SIGNAL] = "signal",
        [SERVICE_FAILURE_CORE_DUMP] = "core-dump",
        [SERVICE_FAILURE_WATCHDOG] = "watchdog",
        [SERVICE_FAILURE_START_LIMIT] = "start-limit"
};

DEFINE_STRING_TABLE_LOOKUP(service_result, ServiceResult);

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

        .serialize = service_serialize,
        .deserialize_item = service_deserialize_item,

        .active_state = service_active_state,
        .sub_state_to_string = service_sub_state_to_string,

        .check_gc = service_check_gc,
        .check_snapshot = service_check_snapshot,

        .sigchld_event = service_sigchld_event,

        .reset_failed = service_reset_failed,

        .notify_cgroup_empty = service_notify_cgroup_empty_event,
        .notify_message = service_notify_message,

        .bus_name_owner_change = service_bus_name_owner_change,

        .bus_vtable = bus_service_vtable,
        .bus_set_property = bus_service_set_property,
        .bus_commit_properties = bus_service_commit_properties,

        .get_timeout = service_get_timeout,
        .can_transient = true,

        .status_message_formats = {
                .starting_stopping = {
                        [0] = "Starting %s...",
                        [1] = "Stopping %s...",
                },
                .finished_start_job = {
                        [JOB_DONE]       = "Started %s.",
                        [JOB_FAILED]     = "Failed to start %s.",
                },
                .finished_stop_job = {
                        [JOB_DONE]       = "Stopped %s.",
                        [JOB_FAILED]     = "Stopped (with error) %s.",
                },
        },
};
