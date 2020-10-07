/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "alloc-util.h"
#include "async.h"
#include "bus-get-properties.h"
#include "dbus-cgroup.h"
#include "dbus-execute.h"
#include "dbus-kill.h"
#include "dbus-manager.h"
#include "dbus-service.h"
#include "dbus-util.h"
#include "execute.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fileio.h"
#include "locale-util.h"
#include "mount-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "selinux-access.h"
#include "service.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "unit.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_type, service_type, ServiceType);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, service_result, ServiceResult);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_restart, service_restart, ServiceRestart);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_notify_access, notify_access, NotifyAccess);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_emergency_action, emergency_action, EmergencyAction);
static BUS_DEFINE_PROPERTY_GET(property_get_timeout_abort_usec, "t", Service, service_timeout_abort_usec);
static BUS_DEFINE_PROPERTY_GET(property_get_watchdog_usec, "t", Service, service_get_watchdog_usec);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_timeout_failure_mode, service_timeout_failure_mode, ServiceTimeoutFailureMode);

static int property_get_exit_status_set(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        const ExitStatusSet *status_set = userdata;
        unsigned n;
        int r;

        assert(bus);
        assert(reply);
        assert(status_set);

        r = sd_bus_message_open_container(reply, 'r', "aiai");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "i");
        if (r < 0)
                return r;

        BITMAP_FOREACH(n, &status_set->status) {
                assert(n < 256);

                r = sd_bus_message_append_basic(reply, 'i', &n);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "i");
        if (r < 0)
                return r;

        BITMAP_FOREACH(n, &status_set->signal) {
                const char *str;

                str = signal_to_string(n);
                if (!str)
                        continue;

                r = sd_bus_message_append_basic(reply, 'i', &n);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_close_container(reply);
}

static int bus_service_method_mount(sd_bus_message *message, void *userdata, sd_bus_error *error, bool is_image) {
        _cleanup_(mount_options_free_allp) MountOptions *options = NULL;
        const char *dest, *src, *propagate_directory;
        int read_only, make_file_or_directory;
        Unit *u = userdata;
        ExecContext *c;
        pid_t unit_pid;
        int r;

        assert(message);
        assert(u);

        if (!MANAGER_IS_SYSTEM(u->manager))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Adding bind mounts at runtime is only supported for system managers.");

        r = mac_selinux_unit_access_check(u, message, "start", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "ssbb", &src, &dest, &read_only, &make_file_or_directory);
        if (r < 0)
                return r;

        if (!path_is_absolute(src) || !path_is_normalized(src))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Source path must be absolute and normalized.");

        if (!is_image && isempty(dest))
                dest = src;
        else if (!path_is_absolute(dest) || !path_is_normalized(dest))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Destination path must be absolute and normalized.");

        if (is_image) {
                r = bus_read_mount_options(message, error, &options, NULL, "");
                if (r < 0)
                        return r;
        }

        r = bus_verify_manage_units_async_full(
                        u,
                        is_image ? "mount-image" : "bind-mount",
                        CAP_SYS_ADMIN,
                        N_("Authentication is required to mount on '$(unit)'."),
                        true,
                        message,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        if (u->type != UNIT_SERVICE)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unit is not of type .service");

        /* If it would be dropped at startup time, return an error. The context should always be available, but
         * there's an assert in exec_needs_mount_namespace, so double-check just in case. */
        c = unit_get_exec_context(u);
        if (!c)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Cannot access unit execution context");
        if (path_startswith_strv(dest, c->inaccessible_paths))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "%s is not accessible to this unit", dest);

        /* Ensure that the unit was started in a private mount namespace */
        if (!exec_needs_mount_namespace(c, NULL, unit_get_exec_runtime(u)))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unit not running in private mount namespace, cannot activate bind mount");

        unit_pid = unit_main_pid(u);
        if (unit_pid == 0 || !UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(u)))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unit is not running");

        propagate_directory = strjoina("/run/systemd/propagate/", u->id);
        if (is_image)
                r = mount_image_in_namespace(unit_pid,
                                             propagate_directory,
                                             "/run/systemd/incoming/",
                                             src, dest, read_only, make_file_or_directory, options);
        else
                r = bind_mount_in_namespace(unit_pid,
                                            propagate_directory,
                                            "/run/systemd/incoming/",
                                            src, dest, read_only, make_file_or_directory);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to mount %s on %s in unit's namespace: %m", src, dest);

        return sd_bus_reply_method_return(message, NULL);
}

int bus_service_method_bind_mount(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_service_method_mount(message, userdata, error, false);
}

int bus_service_method_mount_image(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_service_method_mount(message, userdata, error, true);
}

const sd_bus_vtable bus_service_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Type", "s", property_get_type, offsetof(Service, type), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Restart", "s", property_get_restart, offsetof(Service, restart), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PIDFile", "s", NULL, offsetof(Service, pid_file), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("NotifyAccess", "s", property_get_notify_access, offsetof(Service, notify_access), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RestartUSec", "t", bus_property_get_usec, offsetof(Service, restart_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TimeoutStartUSec", "t", bus_property_get_usec, offsetof(Service, timeout_start_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TimeoutStopUSec", "t", bus_property_get_usec, offsetof(Service, timeout_stop_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TimeoutAbortUSec", "t", property_get_timeout_abort_usec, 0, 0),
        SD_BUS_PROPERTY("TimeoutStartFailureMode", "s", property_get_timeout_failure_mode, offsetof(Service, timeout_start_failure_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TimeoutStopFailureMode", "s", property_get_timeout_failure_mode, offsetof(Service, timeout_stop_failure_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RuntimeMaxUSec", "t", bus_property_get_usec, offsetof(Service, runtime_max_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WatchdogUSec", "t", property_get_watchdog_usec, 0, 0),
        BUS_PROPERTY_DUAL_TIMESTAMP("WatchdogTimestamp", offsetof(Service, watchdog_timestamp), 0),
        SD_BUS_PROPERTY("PermissionsStartOnly", "b", bus_property_get_bool, offsetof(Service, permissions_start_only), SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN), /* 😷 deprecated */
        SD_BUS_PROPERTY("RootDirectoryStartOnly", "b", bus_property_get_bool, offsetof(Service, root_directory_start_only), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RemainAfterExit", "b", bus_property_get_bool, offsetof(Service, remain_after_exit), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("GuessMainPID", "b", bus_property_get_bool, offsetof(Service, guess_main_pid), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RestartPreventExitStatus", "(aiai)", property_get_exit_status_set, offsetof(Service, restart_prevent_status), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RestartForceExitStatus", "(aiai)", property_get_exit_status_set, offsetof(Service, restart_force_status), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SuccessExitStatus", "(aiai)", property_get_exit_status_set, offsetof(Service, success_status), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MainPID", "u", bus_property_get_pid, offsetof(Service, main_pid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("ControlPID", "u", bus_property_get_pid, offsetof(Service, control_pid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("BusName", "s", NULL, offsetof(Service, bus_name), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("FileDescriptorStoreMax", "u", bus_property_get_unsigned, offsetof(Service, n_fd_store_max), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("NFileDescriptorStore", "u", bus_property_get_unsigned, offsetof(Service, n_fd_store), 0),
        SD_BUS_PROPERTY("StatusText", "s", NULL, offsetof(Service, status_text), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("StatusErrno", "i", bus_property_get_int, offsetof(Service, status_errno), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Service, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("ReloadResult", "s", property_get_result, offsetof(Service, reload_result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("CleanResult", "s", property_get_result, offsetof(Service, clean_result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("USBFunctionDescriptors", "s", NULL, offsetof(Service, usb_function_descriptors), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("USBFunctionStrings", "s", NULL, offsetof(Service, usb_function_strings), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("UID", "u", bus_property_get_uid, offsetof(Unit, ref_uid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("GID", "u", bus_property_get_gid, offsetof(Unit, ref_gid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("NRestarts", "u", bus_property_get_unsigned, offsetof(Service, n_restarts), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("OOMPolicy", "s", bus_property_get_oom_policy, offsetof(Service, oom_policy), SD_BUS_VTABLE_PROPERTY_CONST),

        BUS_EXEC_STATUS_VTABLE("ExecMain", offsetof(Service, main_exec_status), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecCondition", offsetof(Service, exec_command[SERVICE_EXEC_CONDITION]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_EX_COMMAND_LIST_VTABLE("ExecConditionEx", offsetof(Service, exec_command[SERVICE_EXEC_CONDITION]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStartPre", offsetof(Service, exec_command[SERVICE_EXEC_START_PRE]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_EX_COMMAND_LIST_VTABLE("ExecStartPreEx", offsetof(Service, exec_command[SERVICE_EXEC_START_PRE]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStart", offsetof(Service, exec_command[SERVICE_EXEC_START]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_EX_COMMAND_LIST_VTABLE("ExecStartEx", offsetof(Service, exec_command[SERVICE_EXEC_START]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStartPost", offsetof(Service, exec_command[SERVICE_EXEC_START_POST]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_EX_COMMAND_LIST_VTABLE("ExecStartPostEx", offsetof(Service, exec_command[SERVICE_EXEC_START_POST]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecReload", offsetof(Service, exec_command[SERVICE_EXEC_RELOAD]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_EX_COMMAND_LIST_VTABLE("ExecReloadEx", offsetof(Service, exec_command[SERVICE_EXEC_RELOAD]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStop", offsetof(Service, exec_command[SERVICE_EXEC_STOP]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_EX_COMMAND_LIST_VTABLE("ExecStopEx", offsetof(Service, exec_command[SERVICE_EXEC_STOP]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStopPost", offsetof(Service, exec_command[SERVICE_EXEC_STOP_POST]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_EX_COMMAND_LIST_VTABLE("ExecStopPostEx", offsetof(Service, exec_command[SERVICE_EXEC_STOP_POST]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),

        SD_BUS_METHOD_WITH_NAMES("BindMount",
                                 "ssbb",
                                 SD_BUS_PARAM(source)
                                 SD_BUS_PARAM(destination)
                                 SD_BUS_PARAM(read_only)
                                 SD_BUS_PARAM(mkdir),
                                 NULL,,
                                 bus_service_method_bind_mount,
                                 SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_NAMES("MountImage",
                                 "ssbba(ss)",
                                 SD_BUS_PARAM(source)
                                 SD_BUS_PARAM(destination)
                                 SD_BUS_PARAM(read_only)
                                 SD_BUS_PARAM(mkdir)
                                 SD_BUS_PARAM(options),
                                 NULL,,
                                 bus_service_method_mount_image,
                                 SD_BUS_VTABLE_UNPRIVILEGED),

        /* The following four are obsolete, and thus marked hidden here. They moved into the Unit interface */
        SD_BUS_PROPERTY("StartLimitInterval", "t", bus_property_get_usec, offsetof(Unit, start_ratelimit.interval), SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("StartLimitBurst", "u", bus_property_get_unsigned, offsetof(Unit, start_ratelimit.burst), SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("StartLimitAction", "s", property_get_emergency_action, offsetof(Unit, start_limit_action), SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("FailureAction", "s", property_get_emergency_action, offsetof(Unit, failure_action), SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("RebootArgument", "s", NULL, offsetof(Unit, reboot_arg), SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_VTABLE_END
};

static int bus_set_transient_exit_status(
                Unit *u,
                const char *name,
                ExitStatusSet *status_set,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        const int32_t *status, *signal;
        size_t n_status, n_signal, i;
        int r;

        r = sd_bus_message_enter_container(message, 'r', "aiai");
        if (r < 0)
                return r;

        r = sd_bus_message_read_array(message, 'i', (const void **) &status, &n_status);
        if (r < 0)
                return r;

        r = sd_bus_message_read_array(message, 'i', (const void **) &signal, &n_signal);
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(message);
        if (r < 0)
                return r;

        n_status /= sizeof(int32_t);
        n_signal /= sizeof(int32_t);

        if (n_status == 0 && n_signal == 0 && !UNIT_WRITE_FLAGS_NOOP(flags)) {
                exit_status_set_free(status_set);
                unit_write_settingf(u, flags, name, "%s=", name);
                return 1;
        }

        for (i = 0; i < n_status; i++) {
                if (status[i] < 0 || status[i] > 255)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid status code in %s: %"PRIi32, name, status[i]);

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        r = bitmap_set(&status_set->status, status[i]);
                        if (r < 0)
                                return r;

                        unit_write_settingf(u, flags, name, "%s=%"PRIi32, name, status[i]);
                }
        }

        for (i = 0; i < n_signal; i++) {
                const char *str;

                str = signal_to_string((int) signal[i]);
                if (!str)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid signal in %s: %"PRIi32, name, signal[i]);

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        r = bitmap_set(&status_set->signal, signal[i]);
                        if (r < 0)
                                return r;

                        unit_write_settingf(u, flags, name, "%s=%s", name, str);
                }
        }

        return 1;
}

static int bus_set_transient_std_fd(
                Unit *u,
                const char *name,
                int *p,
                bool *b,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        int fd, r;

        assert(p);
        assert(b);

        r = sd_bus_message_read(message, "h", &fd);
        if (r < 0)
                return r;

        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                int copy;

                copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
                if (copy < 0)
                        return -errno;

                asynchronous_close(*p);
                *p = copy;
                *b = true;
        }

        return 1;
}
static BUS_DEFINE_SET_TRANSIENT_PARSE(notify_access, NotifyAccess, notify_access_from_string);
static BUS_DEFINE_SET_TRANSIENT_PARSE(service_type, ServiceType, service_type_from_string);
static BUS_DEFINE_SET_TRANSIENT_PARSE(service_restart, ServiceRestart, service_restart_from_string);
static BUS_DEFINE_SET_TRANSIENT_PARSE(oom_policy, OOMPolicy, oom_policy_from_string);
static BUS_DEFINE_SET_TRANSIENT_STRING_WITH_CHECK(bus_name, sd_bus_service_name_is_valid);
static BUS_DEFINE_SET_TRANSIENT_PARSE(timeout_failure_mode, ServiceTimeoutFailureMode, service_timeout_failure_mode_from_string);

static int bus_service_set_transient_property(
                Service *s,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        Unit *u = UNIT(s);
        ServiceExecCommand ci;
        int r;

        assert(s);
        assert(name);
        assert(message);

        flags |= UNIT_PRIVATE;

        if (streq(name, "PermissionsStartOnly"))
                return bus_set_transient_bool(u, name, &s->permissions_start_only, message, flags, error);

        if (streq(name, "RootDirectoryStartOnly"))
                return bus_set_transient_bool(u, name, &s->root_directory_start_only, message, flags, error);

        if (streq(name, "RemainAfterExit"))
                return bus_set_transient_bool(u, name, &s->remain_after_exit, message, flags, error);

        if (streq(name, "GuessMainPID"))
                return bus_set_transient_bool(u, name, &s->guess_main_pid, message, flags, error);

        if (streq(name, "Type"))
                return bus_set_transient_service_type(u, name, &s->type, message, flags, error);

        if (streq(name, "OOMPolicy"))
                return bus_set_transient_oom_policy(u, name, &s->oom_policy, message, flags, error);

        if (streq(name, "RestartUSec"))
                return bus_set_transient_usec(u, name, &s->restart_usec, message, flags, error);

        if (streq(name, "TimeoutStartUSec")) {
                r = bus_set_transient_usec(u, name, &s->timeout_start_usec, message, flags, error);
                if (r >= 0 && !UNIT_WRITE_FLAGS_NOOP(flags))
                        s->start_timeout_defined = true;

                return r;
        }

        if (streq(name, "TimeoutStopUSec"))
                return bus_set_transient_usec(u, name, &s->timeout_stop_usec, message, flags, error);

        if (streq(name, "TimeoutAbortUSec")) {
                r = bus_set_transient_usec(u, name, &s->timeout_abort_usec, message, flags, error);
                if (r >= 0 && !UNIT_WRITE_FLAGS_NOOP(flags))
                        s->timeout_abort_set = true;
                return r;
        }

        if (streq(name, "TimeoutStartFailureMode"))
                return bus_set_transient_timeout_failure_mode(u, name, &s->timeout_start_failure_mode, message, flags, error);

        if (streq(name, "TimeoutStopFailureMode"))
                return bus_set_transient_timeout_failure_mode(u, name, &s->timeout_stop_failure_mode, message, flags, error);

        if (streq(name, "RuntimeMaxUSec"))
                return bus_set_transient_usec(u, name, &s->runtime_max_usec, message, flags, error);

        if (streq(name, "WatchdogUSec"))
                return bus_set_transient_usec(u, name, &s->watchdog_usec, message, flags, error);

        if (streq(name, "FileDescriptorStoreMax"))
                return bus_set_transient_unsigned(u, name, &s->n_fd_store_max, message, flags, error);

        if (streq(name, "NotifyAccess"))
                return bus_set_transient_notify_access(u, name, &s->notify_access, message, flags, error);

        if (streq(name, "PIDFile")) {
                _cleanup_free_ char *n = NULL;
                const char *v, *e;

                r = sd_bus_message_read(message, "s", &v);
                if (r < 0)
                        return r;

                if (!isempty(v)) {
                        n = path_make_absolute(v, u->manager->prefix[EXEC_DIRECTORY_RUNTIME]);
                        if (!n)
                                return -ENOMEM;

                        path_simplify(n, true);

                        if (!path_is_normalized(n))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "PIDFile= path '%s' is not valid", n);

                        e = path_startswith(n, "/var/run/");
                        if (e) {
                                char *z;

                                z = path_join("/run", e);
                                if (!z)
                                        return log_oom();

                                if (!UNIT_WRITE_FLAGS_NOOP(flags))
                                        log_unit_notice(u, "Transient unit's PIDFile= property references path below legacy directory /var/run, updating %s → %s; please update client accordingly.", n, z);

                                free_and_replace(n, z);
                        }
                }

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        free_and_replace(s->pid_file, n);
                        unit_write_settingf(u, flags, name, "%s=%s", name, strempty(s->pid_file));
                }

                return 1;
        }

        if (streq(name, "USBFunctionDescriptors"))
                return bus_set_transient_path(u, name, &s->usb_function_descriptors, message, flags, error);

        if (streq(name, "USBFunctionStrings"))
                return bus_set_transient_path(u, name, &s->usb_function_strings, message, flags, error);

        if (streq(name, "BusName"))
                return bus_set_transient_bus_name(u, name, &s->bus_name, message, flags, error);

        if (streq(name, "Restart"))
                return bus_set_transient_service_restart(u, name, &s->restart, message, flags, error);

        if (streq(name, "RestartPreventExitStatus"))
                return bus_set_transient_exit_status(u, name, &s->restart_prevent_status, message, flags, error);

        if (streq(name, "RestartForceExitStatus"))
                return bus_set_transient_exit_status(u, name, &s->restart_force_status, message, flags, error);

        if (streq(name, "SuccessExitStatus"))
                return bus_set_transient_exit_status(u, name, &s->success_status, message, flags, error);

        ci = service_exec_command_from_string(name);
        ci = (ci >= 0) ? ci : service_exec_ex_command_from_string(name);
        if (ci >= 0)
                return bus_set_transient_exec_command(u, name, &s->exec_command[ci], message, flags, error);

        if (streq(name, "StandardInputFileDescriptor"))
                return bus_set_transient_std_fd(u, name, &s->stdin_fd, &s->exec_context.stdio_as_fds, message, flags, error);

        if (streq(name, "StandardOutputFileDescriptor"))
                return bus_set_transient_std_fd(u, name, &s->stdout_fd, &s->exec_context.stdio_as_fds, message, flags, error);

        if (streq(name, "StandardErrorFileDescriptor"))
                return bus_set_transient_std_fd(u, name, &s->stderr_fd, &s->exec_context.stdio_as_fds, message, flags, error);

        return 0;
}

int bus_service_set_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        Service *s = SERVICE(u);
        int r;

        assert(s);
        assert(name);
        assert(message);

        r = bus_cgroup_set_property(u, &s->cgroup_context, name, message, flags, error);
        if (r != 0)
                return r;

        if (u->transient && u->load_state == UNIT_STUB) {
                /* This is a transient unit, let's load a little more */

                r = bus_service_set_transient_property(s, name, message, flags, error);
                if (r != 0)
                        return r;

                r = bus_exec_context_set_transient_property(u, &s->exec_context, name, message, flags, error);
                if (r != 0)
                        return r;

                r = bus_kill_context_set_transient_property(u, &s->kill_context, name, message, flags, error);
                if (r != 0)
                        return r;
        }

        return 0;
}

int bus_service_commit_properties(Unit *u) {
        assert(u);

        unit_realize_cgroup(u);

        return 0;
}
