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

#include "strv.h"
#include "path-util.h"
#include "unit.h"
#include "service.h"
#include "dbus-execute.h"
#include "dbus-kill.h"
#include "dbus-cgroup.h"
#include "dbus-service.h"
#include "bus-util.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_type, service_type, ServiceType);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, service_result, ServiceResult);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_restart, service_restart, ServiceRestart);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_notify_access, notify_access, NotifyAccess);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_failure_action, failure_action, FailureAction);

const sd_bus_vtable bus_service_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Type", "s", property_get_type, offsetof(Service, type), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Restart", "s", property_get_restart, offsetof(Service, restart), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PIDFile", "s", NULL, offsetof(Service, pid_file), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("NotifyAccess", "s", property_get_notify_access, offsetof(Service, notify_access), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RestartUSec", "t", bus_property_get_usec, offsetof(Service, restart_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TimeoutStartUSec", "t", bus_property_get_usec, offsetof(Service, timeout_start_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TimeoutStopUSec", "t", bus_property_get_usec, offsetof(Service, timeout_stop_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WatchdogUSec", "t", bus_property_get_usec, offsetof(Service, watchdog_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("WatchdogTimestamp", offsetof(Service, watchdog_timestamp), 0),
        SD_BUS_PROPERTY("StartLimitInterval", "t", bus_property_get_usec, offsetof(Service, start_limit.interval), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("StartLimitBurst", "u", bus_property_get_unsigned, offsetof(Service, start_limit.burst), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("StartLimitAction", "s", property_get_failure_action, offsetof(Service, start_limit_action), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RebootArgument", "s", NULL, offsetof(Service, reboot_arg), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("FailureAction", "s", property_get_failure_action, offsetof(Service, failure_action), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PermissionsStartOnly", "b", bus_property_get_bool, offsetof(Service, permissions_start_only), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RootDirectoryStartOnly", "b", bus_property_get_bool, offsetof(Service, root_directory_start_only), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RemainAfterExit", "b", bus_property_get_bool, offsetof(Service, remain_after_exit), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("GuessMainPID", "b", bus_property_get_bool, offsetof(Service, guess_main_pid), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MainPID", "u", bus_property_get_pid, offsetof(Service, main_pid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("ControlPID", "u", bus_property_get_pid, offsetof(Service, control_pid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("BusName", "s", NULL, offsetof(Service, bus_name), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("FileDescriptorStoreMax", "u", NULL, offsetof(Service, n_fd_store_max), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("StatusText", "s", NULL, offsetof(Service, status_text), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("StatusErrno", "i", NULL, offsetof(Service, status_errno), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Service, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("USBFunctionDescriptors", "s", NULL, offsetof(Service, usb_function_descriptors), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("USBFunctionStrings", "s", NULL, offsetof(Service, usb_function_strings), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_EXEC_STATUS_VTABLE("ExecMain", offsetof(Service, main_exec_status), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStartPre", offsetof(Service, exec_command[SERVICE_EXEC_START_PRE]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStart", offsetof(Service, exec_command[SERVICE_EXEC_START]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStartPost", offsetof(Service, exec_command[SERVICE_EXEC_START_POST]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecReload", offsetof(Service, exec_command[SERVICE_EXEC_RELOAD]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStop", offsetof(Service, exec_command[SERVICE_EXEC_STOP]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStopPost", offsetof(Service, exec_command[SERVICE_EXEC_STOP_POST]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_VTABLE_END
};

static int bus_service_set_transient_property(
                Service *s,
                const char *name,
                sd_bus_message *message,
                UnitSetPropertiesMode mode,
                sd_bus_error *error) {

        int r;

        assert(s);
        assert(name);
        assert(message);

        if (streq(name, "RemainAfterExit")) {
                int b;

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        s->remain_after_exit = b;
                        unit_write_drop_in_private_format(UNIT(s), mode, name, "RemainAfterExit=%s\n", yes_no(b));
                }

                return 1;

        } else if (streq(name, "Type")) {
                const char *t;
                ServiceType k;

                r = sd_bus_message_read(message, "s", &t);
                if (r < 0)
                        return r;

                k = service_type_from_string(t);
                if (k < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid service type %s", t);

                if (mode != UNIT_CHECK) {
                        s->type = k;
                        unit_write_drop_in_private_format(UNIT(s), mode, name, "Type=%s\n", service_type_to_string(s->type));
                }

                return 1;

        } else if (streq(name, "ExecStart")) {
                unsigned n = 0;

                r = sd_bus_message_enter_container(message, 'a', "(sasb)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_enter_container(message, 'r', "sasb")) > 0) {
                        _cleanup_strv_free_ char **argv = NULL;
                        const char *path;
                        int b;

                        r = sd_bus_message_read(message, "s", &path);
                        if (r < 0)
                                return r;

                        if (!path_is_absolute(path))
                                return sd_bus_error_set_errnof(error, EINVAL, "Path %s is not absolute.", path);

                        r = sd_bus_message_read_strv(message, &argv);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_read(message, "b", &b);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_exit_container(message);
                        if (r < 0)
                                return r;

                        if (mode != UNIT_CHECK) {
                                ExecCommand *c;

                                c = new0(ExecCommand, 1);
                                if (!c)
                                        return -ENOMEM;

                                c->path = strdup(path);
                                if (!c->path) {
                                        free(c);
                                        return -ENOMEM;
                                }

                                c->argv = argv;
                                argv = NULL;

                                c->ignore = b;

                                path_kill_slashes(c->path);
                                exec_command_append_list(&s->exec_command[SERVICE_EXEC_START], c);
                        }

                        n++;
                }

                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        ExecCommand *c;
                        size_t size = 0;

                        if (n == 0)
                                s->exec_command[SERVICE_EXEC_START] = exec_command_free_list(s->exec_command[SERVICE_EXEC_START]);

                        f = open_memstream(&buf, &size);
                        if (!f)
                                return -ENOMEM;

                        fputs("ExecStart=\n", f);

                        LIST_FOREACH(command, c, s->exec_command[SERVICE_EXEC_START]) {
                                _cleanup_free_ char *a;

                                a = strv_join_quoted(c->argv);
                                if (!a)
                                        return -ENOMEM;

                                fprintf(f, "ExecStart=%s@%s %s\n",
                                        c->ignore ? "-" : "",
                                        c->path,
                                        a);
                        }

                        fflush(f);
                        unit_write_drop_in_private(UNIT(s), mode, name, buf);
                }

                return 1;
        }

        return 0;
}

int bus_service_set_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitSetPropertiesMode mode,
                sd_bus_error *error) {

        Service *s = SERVICE(u);
        int r;

        assert(s);
        assert(name);
        assert(message);

        r = bus_cgroup_set_property(u, &s->cgroup_context, name, message, mode, error);
        if (r != 0)
                return r;

        if (u->transient && u->load_state == UNIT_STUB) {
                /* This is a transient unit, let's load a little more */

                r = bus_service_set_transient_property(s, name, message, mode, error);
                if (r != 0)
                        return r;

                r = bus_exec_context_set_transient_property(u, &s->exec_context, name, message, mode, error);
                if (r != 0)
                        return r;

                r = bus_kill_context_set_transient_property(u, &s->kill_context, name, message, mode, error);
                if (r != 0)
                        return r;
        }

        return 0;
}

int bus_service_commit_properties(Unit *u) {
        assert(u);

        unit_update_cgroup_members_masks(u);
        unit_realize_cgroup(u);

        return 0;
}
