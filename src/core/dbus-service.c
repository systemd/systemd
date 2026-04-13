/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "alloc-util.h"
#include "async.h"
#include "bus-common-errors.h"
#include "bus-get-properties.h"
#include "constants.h"
#include "dbus-cgroup.h"
#include "dbus-execute.h"
#include "dbus-kill.h"
#include "dbus-manager.h"
#include "dbus-service.h"
#include "dbus-util.h"
#include "dissect-image.h"
#include "execute.h"
#include "exit-status.h"
#include "fd-util.h"
#include "glyph-util.h"
#include "locale-util.h"
#include "manager.h"
#include "mount-util.h"
#include "open-file.h"
#include "path-util.h"
#include "selinux-access.h"
#include "service.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "unit.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_type, service_type, ServiceType);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_exit_type, service_exit_type, ServiceExitType);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, service_result, ServiceResult);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_restart, service_restart, ServiceRestart);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_restart_mode, service_restart_mode, ServiceRestartMode);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_emergency_action, emergency_action, EmergencyAction);
static BUS_DEFINE_PROPERTY_GET2(property_get_notify_access, "s", Service, service_get_notify_access, notify_access_to_string);
static BUS_DEFINE_PROPERTY_GET(property_get_restart_usec_next, "t", Service, service_restart_usec_next);
static BUS_DEFINE_PROPERTY_GET(property_get_timeout_abort_usec, "t", Service, service_timeout_abort_usec);
static BUS_DEFINE_PROPERTY_GET(property_get_watchdog_usec, "t", Service, service_get_watchdog_usec);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_timeout_failure_mode, service_timeout_failure_mode, ServiceTimeoutFailureMode);

static int property_get_open_files(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        OpenFile **open_files = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "(sst)");
        if (r < 0)
                return r;

        LIST_FOREACH(open_files, of, *open_files) {
                r = sd_bus_message_append(reply, "(sst)", of->path, of->fdname, (uint64_t) of->flags);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_extra_file_descriptors(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Service *s = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
                return r;

        FOREACH_ARRAY(i, s->extra_fds, s->n_extra_fds) {
                r = sd_bus_message_append_basic(reply, 's', i->fdname);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_refresh_on_reload(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Service *s = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(bus);
        assert(reply);

        r = service_refresh_on_reload_to_strv(s->refresh_on_reload_flags, &l);
        if (r < 0)
                return r;

        return sd_bus_message_append_strv(reply, l);
}

static int property_get_exit_status_set(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        const ExitStatusSet *status_set = ASSERT_PTR(userdata);
        unsigned n;
        int r;

        assert(bus);
        assert(reply);

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

static int bus_service_method_mount(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error, bool is_image) {
        MountInNamespaceFlags flags = 0;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(message);

        if (!MANAGER_IS_SYSTEM(u->manager))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_NOT_SUPPORTED, "Adding bind mounts at runtime is only supported by system manager");

        r = unit_can_live_mount(u, reterr_error);
        if (r < 0)
                return log_unit_debug_errno(u, r, "Cannot schedule live mount operation: %s", bus_error_message(reterr_error, r));

        r = mac_selinux_unit_access_check(u, message, "start", reterr_error);
        if (r < 0)
                return r;

        _cleanup_(mount_options_free_allp) MountOptions *options = NULL;
        const char *src, *dest;
        int read_only, make_file_or_directory;

        r = sd_bus_message_read(message, "ssbb", &src, &dest, &read_only, &make_file_or_directory);
        if (r < 0)
                return r;

        if (!path_is_absolute(src) || !path_is_normalized(src))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Source path must be absolute and normalized");

        if (!is_image && isempty(dest))
                dest = src;
        else if (!path_is_absolute(dest) || !path_is_normalized(dest))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Destination path must be absolute and normalized");

        if (is_image) {
                r = bus_read_mount_options(message, reterr_error, &options,
                                           /* in_out_format_str = */ NULL, /* separator = */ NULL);
                if (r < 0)
                        return r;
        }

        r = bus_verify_manage_units_async_full(
                        u,
                        is_image ? "mount-image" : "bind-mount",
                        N_("Authentication is required to mount on '$(unit)'."),
                        message,
                        reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        if (is_image)
                flags |= MOUNT_IN_NAMESPACE_IS_IMAGE;
        if (read_only)
                flags |= MOUNT_IN_NAMESPACE_READ_ONLY;
        if (make_file_or_directory)
                flags |= MOUNT_IN_NAMESPACE_MAKE_FILE_OR_DIRECTORY;

        r = unit_live_mount(u, src, dest, message, flags, options, reterr_error);
        if (r < 0)
                return r;

        return 1;
}

int bus_service_method_bind_mount(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return bus_service_method_mount(message, userdata, reterr_error, false);
}

int bus_service_method_mount_image(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return bus_service_method_mount(message, userdata, reterr_error, true);
}

int bus_service_method_dump_file_descriptor_store(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Service *s = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_unit_access_check(UNIT(s), message, "status", reterr_error);
        if (r < 0)
                return r;

        if (s->n_fd_store_max == 0 && s->n_fd_store == 0)
                return sd_bus_error_setf(reterr_error, BUS_ERROR_FILE_DESCRIPTOR_STORE_DISABLED, "File descriptor store not enabled for %s.", UNIT(s)->id);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(suuutuusu)");
        if (r < 0)
                return r;

        LIST_FOREACH(fd_store, i, s->fd_store) {
                _cleanup_free_ char *path = NULL;
                struct stat st;
                int flags;

                if (fstat(i->fd, &st) < 0) {
                        log_debug_errno(errno, "Failed to stat() file descriptor entry '%s', skipping.", strna(i->fdname));
                        continue;
                }

                flags = fcntl(i->fd, F_GETFL);
                if (flags < 0) {
                        log_debug_errno(errno, "Failed to issue F_GETFL on file descriptor entry '%s', skipping.", strna(i->fdname));
                        continue;
                }

                /* glibc implies O_LARGEFILE everywhere on 64-bit off_t builds, but forgets to hide it away on
                 * F_GETFL, but provides no definition to check for that. Let's mask the flag away manually,
                 * to not confuse clients. */
                flags &= ~RAW_O_LARGEFILE;

                (void) fd_get_path(i->fd, &path);

                r = sd_bus_message_append(
                                reply,
                                "(suuutuusu)",
                                i->fdname,
                                (uint32_t) st.st_mode,
                                (uint32_t) major(st.st_dev), (uint32_t) minor(st.st_dev),
                                (uint64_t) st.st_ino,
                                (uint32_t) major(st.st_rdev), (uint32_t) minor(st.st_rdev),
                                path,
                                (uint32_t) flags);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

#if __SIZEOF_SIZE_T__ == 8
static int property_get_size_as_uint32(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        size_t *value = ASSERT_PTR(userdata);
        uint32_t sz = *value >= UINT32_MAX ? UINT32_MAX : (uint32_t) *value;

        /* Returns a size_t as a D-Bus "u" type, i.e. as 32-bit value, even if size_t is 64-bit. We'll saturate if it doesn't fit. */

        return sd_bus_message_append_basic(reply, 'u', &sz);
}
#elif __SIZEOF_SIZE_T__ == 4
#define property_get_size_as_uint32 ((sd_bus_property_get_t) NULL)
#else
#error "Unexpected size of size_t"
#endif

const sd_bus_vtable bus_service_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Type", "s", property_get_type, offsetof(Service, type), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ExitType", "s", property_get_exit_type, offsetof(Service, exit_type), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Restart", "s", property_get_restart, offsetof(Service, restart), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RestartMode", "s", property_get_restart_mode, offsetof(Service, restart_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PIDFile", "s", NULL, offsetof(Service, pid_file), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("NotifyAccess", "s", property_get_notify_access, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("RestartUSec", "t", bus_property_get_usec, offsetof(Service, restart_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RestartSteps", "u", bus_property_get_unsigned, offsetof(Service, restart_steps), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RestartMaxDelayUSec", "t", bus_property_get_usec, offsetof(Service, restart_max_delay_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RestartUSecNext", "t", property_get_restart_usec_next, 0, 0),
        SD_BUS_PROPERTY("TimeoutStartUSec", "t", bus_property_get_usec, offsetof(Service, timeout_start_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TimeoutStopUSec", "t", bus_property_get_usec, offsetof(Service, timeout_stop_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TimeoutAbortUSec", "t", property_get_timeout_abort_usec, 0, 0),
        SD_BUS_PROPERTY("TimeoutStartFailureMode", "s", property_get_timeout_failure_mode, offsetof(Service, timeout_start_failure_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TimeoutStopFailureMode", "s", property_get_timeout_failure_mode, offsetof(Service, timeout_stop_failure_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RuntimeMaxUSec", "t", bus_property_get_usec, offsetof(Service, runtime_max_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RuntimeRandomizedExtraUSec", "t", bus_property_get_usec, offsetof(Service, runtime_rand_extra_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WatchdogUSec", "t", property_get_watchdog_usec, 0, 0),
        BUS_PROPERTY_DUAL_TIMESTAMP("WatchdogTimestamp", offsetof(Service, watchdog_timestamp), 0),
        SD_BUS_PROPERTY("PermissionsStartOnly", "b", bus_property_get_bool, offsetof(Service, permissions_start_only), SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN), /* 😷 deprecated */
        SD_BUS_PROPERTY("RootDirectoryStartOnly", "b", bus_property_get_bool, offsetof(Service, root_directory_start_only), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RemainAfterExit", "b", bus_property_get_bool, offsetof(Service, remain_after_exit), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("GuessMainPID", "b", bus_property_get_bool, offsetof(Service, guess_main_pid), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RestartPreventExitStatus", "(aiai)", property_get_exit_status_set, offsetof(Service, restart_prevent_status), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RestartForceExitStatus", "(aiai)", property_get_exit_status_set, offsetof(Service, restart_force_status), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SuccessExitStatus", "(aiai)", property_get_exit_status_set, offsetof(Service, success_status), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MainPID", "u", bus_property_get_pid, offsetof(Service, main_pid.pid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("ControlPID", "u", bus_property_get_pid, offsetof(Service, control_pid.pid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("BusName", "s", NULL, offsetof(Service, bus_name), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("FileDescriptorStoreMax", "u", bus_property_get_unsigned, offsetof(Service, n_fd_store_max), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("NFileDescriptorStore", "u", property_get_size_as_uint32, offsetof(Service, n_fd_store), 0),
        SD_BUS_PROPERTY("FileDescriptorStorePreserve", "s", bus_property_get_exec_preserve_mode, offsetof(Service, fd_store_preserve_mode), 0),
        SD_BUS_PROPERTY("StatusText", "s", NULL, offsetof(Service, status_text), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("StatusErrno", "i", bus_property_get_int, offsetof(Service, status_errno), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("StatusBusError", "s", NULL, offsetof(Service, status_bus_error), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("StatusVarlinkError", "s", NULL, offsetof(Service, status_varlink_error), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Service, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("ReloadResult", "s", property_get_result, offsetof(Service, reload_result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("CleanResult", "s", property_get_result, offsetof(Service, clean_result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("LiveMountResult", "s", property_get_result, offsetof(Service, live_mount_result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("USBFunctionDescriptors", "s", NULL, offsetof(Service, usb_function_descriptors), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("USBFunctionStrings", "s", NULL, offsetof(Service, usb_function_strings), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("UID", "u", bus_property_get_uid, offsetof(Unit, ref_uid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("GID", "u", bus_property_get_gid, offsetof(Unit, ref_gid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("NRestarts", "u", bus_property_get_unsigned, offsetof(Service, n_restarts), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("OOMPolicy", "s", bus_property_get_oom_policy, offsetof(Service, oom_policy), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("OpenFile", "a(sst)", property_get_open_files, offsetof(Service, open_files), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ExtraFileDescriptorNames", "as", property_get_extra_file_descriptors, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ReloadSignal", "i", bus_property_get_int, offsetof(Service, reload_signal), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RefreshOnReload", "as", property_get_refresh_on_reload, 0, SD_BUS_VTABLE_PROPERTY_CONST),

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
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecReloadPost", offsetof(Service, exec_command[SERVICE_EXEC_RELOAD_POST]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_EX_COMMAND_LIST_VTABLE("ExecReloadPostEx", offsetof(Service, exec_command[SERVICE_EXEC_RELOAD_POST]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStop", offsetof(Service, exec_command[SERVICE_EXEC_STOP]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_EX_COMMAND_LIST_VTABLE("ExecStopEx", offsetof(Service, exec_command[SERVICE_EXEC_STOP]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_LIST_VTABLE("ExecStopPost", offsetof(Service, exec_command[SERVICE_EXEC_STOP_POST]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_EX_COMMAND_LIST_VTABLE("ExecStopPostEx", offsetof(Service, exec_command[SERVICE_EXEC_STOP_POST]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),

        SD_BUS_METHOD_WITH_ARGS("BindMount",
                                SD_BUS_ARGS("s", source, "s", destination, "b", read_only, "b", mkdir),
                                SD_BUS_NO_RESULT,
                                bus_service_method_bind_mount,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("MountImage",
                                SD_BUS_ARGS("s", source, "s", destination, "b", read_only, "b", mkdir, "a(ss)", options),
                                SD_BUS_NO_RESULT,
                                bus_service_method_mount_image,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("DumpFileDescriptorStore",
                                SD_BUS_NO_ARGS,
                                SD_BUS_ARGS("a(suuutuusu)", entries),
                                bus_service_method_dump_file_descriptor_store,
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
                sd_bus_error *reterr_error) {

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
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid status code in %s: %"PRIi32, name, status[i]);

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
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid signal in %s: %"PRIi32, name, signal[i]);

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        r = bitmap_set(&status_set->signal, signal[i]);
                        if (r < 0)
                                return r;

                        unit_write_settingf(u, flags, name, "%s=%s", name, str);
                }
        }

        return 1;
}

static int bus_set_transient_exec_context_fd(
                Unit *u,
                const char *name,
                int *p,
                bool *b,
                int verify_mode,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *reterr_error) {

        int fd, r;

        assert(name);
        assert(p);
        assert(b);
        assert((verify_mode & ~O_ACCMODE_STRICT) == 0);

        r = sd_bus_message_read(message, "h", &fd);
        if (r < 0)
                return r;

        r = fd_vet_accmode(fd, verify_mode);
        if (r < 0)
                return sd_bus_error_set_errnof(reterr_error, r, "%s passed is of incompatible type: %m", name);

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
static BUS_DEFINE_SET_TRANSIENT_PARSE(service_exit_type, ServiceExitType, service_exit_type_from_string);
static BUS_DEFINE_SET_TRANSIENT_PARSE(service_restart, ServiceRestart, service_restart_from_string);
static BUS_DEFINE_SET_TRANSIENT_PARSE(service_restart_mode, ServiceRestartMode, service_restart_mode_from_string);
static BUS_DEFINE_SET_TRANSIENT_PARSE(oom_policy, OOMPolicy, oom_policy_from_string);
static BUS_DEFINE_SET_TRANSIENT_STRING_WITH_CHECK(bus_name, sd_bus_service_name_is_valid);
static BUS_DEFINE_SET_TRANSIENT_PARSE(timeout_failure_mode, ServiceTimeoutFailureMode, service_timeout_failure_mode_from_string);
static BUS_DEFINE_SET_TRANSIENT_TO_STRING(reload_signal, "i", int32_t, int, "%" PRIi32, signal_to_string_with_check);

static int bus_service_set_transient_property(
                Service *s,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *reterr_error) {

        Unit *u = UNIT(s);
        ServiceExecCommand ci;
        int r;

        assert(s);
        assert(name);
        assert(message);

        flags |= UNIT_PRIVATE;

        if (streq(name, "PermissionsStartOnly"))
                return bus_set_transient_bool(u, name, &s->permissions_start_only, message, flags, reterr_error);

        if (streq(name, "RootDirectoryStartOnly"))
                return bus_set_transient_bool(u, name, &s->root_directory_start_only, message, flags, reterr_error);

        if (streq(name, "RemainAfterExit"))
                return bus_set_transient_bool(u, name, &s->remain_after_exit, message, flags, reterr_error);

        if (streq(name, "GuessMainPID"))
                return bus_set_transient_bool(u, name, &s->guess_main_pid, message, flags, reterr_error);

        if (streq(name, "Type"))
                return bus_set_transient_service_type(u, name, &s->type, message, flags, reterr_error);

        if (streq(name, "ExitType"))
                return bus_set_transient_service_exit_type(u, name, &s->exit_type, message, flags, reterr_error);

        if (streq(name, "OOMPolicy"))
                return bus_set_transient_oom_policy(u, name, &s->oom_policy, message, flags, reterr_error);

        if (streq(name, "RestartUSec"))
                return bus_set_transient_usec(u, name, &s->restart_usec, message, flags, reterr_error);

        if (streq(name, "RestartSteps"))
                return bus_set_transient_unsigned(u, name, &s->restart_steps, message, flags, reterr_error);

        if (streq(name, "RestartMaxDelayUSec"))
                return bus_set_transient_usec(u, name, &s->restart_max_delay_usec, message, flags, reterr_error);

        if (streq(name, "TimeoutStartUSec")) {
                r = bus_set_transient_usec(u, name, &s->timeout_start_usec, message, flags, reterr_error);
                if (r >= 0 && !UNIT_WRITE_FLAGS_NOOP(flags))
                        s->start_timeout_defined = true;

                return r;
        }

        if (streq(name, "TimeoutStopUSec"))
                return bus_set_transient_usec(u, name, &s->timeout_stop_usec, message, flags, reterr_error);

        if (streq(name, "TimeoutAbortUSec")) {
                r = bus_set_transient_usec(u, name, &s->timeout_abort_usec, message, flags, reterr_error);
                if (r >= 0 && !UNIT_WRITE_FLAGS_NOOP(flags))
                        s->timeout_abort_set = true;
                return r;
        }

        if (streq(name, "TimeoutStartFailureMode"))
                return bus_set_transient_timeout_failure_mode(u, name, &s->timeout_start_failure_mode, message, flags, reterr_error);

        if (streq(name, "TimeoutStopFailureMode"))
                return bus_set_transient_timeout_failure_mode(u, name, &s->timeout_stop_failure_mode, message, flags, reterr_error);

        if (streq(name, "RuntimeMaxUSec"))
                return bus_set_transient_usec(u, name, &s->runtime_max_usec, message, flags, reterr_error);

        if (streq(name, "RuntimeRandomizedExtraUSec"))
                return bus_set_transient_usec(u, name, &s->runtime_rand_extra_usec, message, flags, reterr_error);

        if (streq(name, "WatchdogUSec"))
                return bus_set_transient_usec(u, name, &s->watchdog_usec, message, flags, reterr_error);

        if (streq(name, "FileDescriptorStoreMax"))
                return bus_set_transient_unsigned(u, name, &s->n_fd_store_max, message, flags, reterr_error);

        if (streq(name, "FileDescriptorStorePreserve"))
                return bus_set_transient_exec_preserve_mode(u, name, &s->fd_store_preserve_mode, message, flags, reterr_error);

        if (streq(name, "NotifyAccess"))
                return bus_set_transient_notify_access(u, name, &s->notify_access, message, flags, reterr_error);

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

                        path_simplify(n);

                        if (!path_is_normalized(n))
                                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "PIDFile= path '%s' is not valid", n);

                        e = path_startswith(n, "/var/run/");
                        if (e) {
                                char *z;

                                z = path_join("/run", e);
                                if (!z)
                                        return log_oom();

                                if (!UNIT_WRITE_FLAGS_NOOP(flags))
                                        log_unit_notice(u, "Transient unit's PIDFile= property references path below legacy directory /var/run, updating %s %s %s; please update client accordingly.",
                                                        n, glyph(GLYPH_ARROW_RIGHT), z);

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
                return bus_set_transient_path(u, name, &s->usb_function_descriptors, message, flags, reterr_error);

        if (streq(name, "USBFunctionStrings"))
                return bus_set_transient_path(u, name, &s->usb_function_strings, message, flags, reterr_error);

        if (streq(name, "BusName"))
                return bus_set_transient_bus_name(u, name, &s->bus_name, message, flags, reterr_error);

        if (streq(name, "Restart"))
                return bus_set_transient_service_restart(u, name, &s->restart, message, flags, reterr_error);

        if (streq(name, "RestartMode"))
                return bus_set_transient_service_restart_mode(u, name, &s->restart_mode, message, flags, reterr_error);

        if (streq(name, "RestartPreventExitStatus"))
                return bus_set_transient_exit_status(u, name, &s->restart_prevent_status, message, flags, reterr_error);

        if (streq(name, "RestartForceExitStatus"))
                return bus_set_transient_exit_status(u, name, &s->restart_force_status, message, flags, reterr_error);

        if (streq(name, "SuccessExitStatus"))
                return bus_set_transient_exit_status(u, name, &s->success_status, message, flags, reterr_error);

        ci = service_exec_command_from_string(name);
        if (ci < 0)
                ci = service_exec_ex_command_from_string(name);
        if (ci >= 0)
                return bus_set_transient_exec_command(u, name, &s->exec_command[ci], message, flags, reterr_error);

        if (streq(name, "StandardInputFileDescriptor"))
                return bus_set_transient_exec_context_fd(u, name, &s->stdin_fd, &s->exec_context.stdio_as_fds, O_RDONLY, message, flags, reterr_error);

        if (streq(name, "StandardOutputFileDescriptor"))
                return bus_set_transient_exec_context_fd(u, name, &s->stdout_fd, &s->exec_context.stdio_as_fds, O_WRONLY, message, flags, reterr_error);

        if (streq(name, "StandardErrorFileDescriptor"))
                return bus_set_transient_exec_context_fd(u, name, &s->stderr_fd, &s->exec_context.stdio_as_fds, O_WRONLY, message, flags, reterr_error);

        if (streq(name, "OpenFile")) {
                const char *path, *fdname;
                uint64_t offlags;

                r = sd_bus_message_enter_container(message, 'a', "(sst)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "(sst)", &path, &fdname, &offlags)) > 0) {
                        _cleanup_(open_file_freep) OpenFile *of = NULL;
                        _cleanup_free_ char *ofs = NULL;

                        of = new(OpenFile, 1);
                        if (!of)
                                return -ENOMEM;

                        *of = (OpenFile) {
                                .path = strdup(path),
                                .fdname = strdup(fdname),
                                .flags = offlags,
                        };

                        if (!of->path || !of->fdname)
                                return -ENOMEM;

                        r = open_file_validate(of);
                        if (r < 0)
                                return r;

                        if (UNIT_WRITE_FLAGS_NOOP(flags))
                                continue;

                        r = open_file_to_string(of, &ofs);
                        if (r < 0)
                                return sd_bus_error_set_errnof(
                                                reterr_error, r, "Failed to convert OpenFile= value to string: %m");

                        LIST_APPEND(open_files, s->open_files, TAKE_PTR(of));
                        unit_write_settingf(u, flags | UNIT_ESCAPE_SPECIFIERS, name, "OpenFile=%s", ofs);
                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                return 1;
        }

        if (streq(name, "ReloadSignal"))
                return bus_set_transient_reload_signal(u, name, &s->reload_signal, message, flags, reterr_error);

        if (streq(name, "ExtraFileDescriptors")) {
                r = sd_bus_message_enter_container(message, 'a', "(hs)");
                if (r < 0)
                        return r;

                for (;;) {
                        const char *fdname;
                        int fd;

                        r = sd_bus_message_read(message, "(hs)", &fd, &fdname);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        /* Disallow empty string for ExtraFileDescriptors.
                         * Unlike OpenFile, StandardInput and friends, there isn't a good sane
                         * default for an arbitrary FD. */
                        if (isempty(fdname) || !fdname_is_valid(fdname))
                                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid extra fd name: %s", fdname);

                        if (s->n_extra_fds >= NOTIFY_FD_MAX)
                                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_LIMITS_EXCEEDED, "Too many extra fds sent");

                        if (UNIT_WRITE_FLAGS_NOOP(flags))
                                continue;

                        if (!GREEDY_REALLOC(s->extra_fds, s->n_extra_fds + 1))
                                return -ENOMEM;

                        _cleanup_free_ char *fdname_dup = strdup(fdname);
                        if (!fdname_dup)
                                return -ENOMEM;

                        _cleanup_close_ int fd_dup = fcntl(fd, F_DUPFD_CLOEXEC, 3);
                        if (fd_dup < 0)
                                return -errno;

                        s->extra_fds[s->n_extra_fds++] = (ServiceExtraFD) {
                                .fd = TAKE_FD(fd_dup),
                                .fdname = TAKE_PTR(fdname_dup),
                        };
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                return 1;
        }

        if (streq(name, "RootDirectoryFileDescriptor")) {
                int fd;

                r = sd_bus_message_read(message, "h", &fd);
                if (r < 0)
                        return r;

                r = fd_verify_directory(fd);
                if (r < 0)
                        return sd_bus_error_set_errnof(reterr_error, r, "RootDirectoryFileDescriptor= is not a directory: %m");

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        int fd_clone;

                        /* Note that this invalidates the fd we got from the client. They won't be able to
                         * move_mount() it themselves. If they already move_mount()'ed it themselves, this
                         * will fail to clone the fd. */
                        fd_clone = mount_fd_clone(fd, /* recursive= */ true, /* replacement_fd= */ NULL);
                        if (fd_clone < 0)
                                return fd_clone;

                        /* We're closing our own clone here, which shouldn't need an asynchronous_close(). */
                        close_and_replace(s->root_directory_fd, fd_clone);
                        s->exec_context.root_directory_as_fd = true;
                }

                return 1;
        }

        if (streq(name, "RefreshOnReload")) {
                const char *t;
                int invert;

                r = sd_bus_message_enter_container(message, 'a', "(bs)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "(bs)", &invert, &t)) > 0) {
                        ServiceRefreshOnReload f;

                        f = service_refresh_on_reload_flag_from_string(t);
                        if (f < 0)
                                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid RefreshOnReload= value: %s", t);

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                if (!s->refresh_on_reload_set)
                                        s->refresh_on_reload_flags = invert ? (SERVICE_REFRESH_ON_RELOAD_DEFAULT & ~f) : f;
                                else
                                        SET_FLAG(s->refresh_on_reload_flags, f, !invert);

                                s->refresh_on_reload_set = true;
                                unit_write_settingf(u, flags, name, "%s=%s%s", name, invert ? "~" : "", t);
                        }
                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags) && !s->refresh_on_reload_set) { /* empty array? */
                        s->refresh_on_reload_flags = 0;
                        s->refresh_on_reload_set = true;
                        unit_write_settingf(u, flags, name, "%s=no", name);
                }

                return 1;
        }

        return 0;
}

int bus_service_set_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *reterr_error) {

        Service *s = SERVICE(u);
        int r;

        assert(s);
        assert(name);
        assert(message);

        r = bus_cgroup_set_property(u, &s->cgroup_context, name, message, flags, reterr_error);
        if (r != 0)
                return r;

        if (u->transient && u->load_state == UNIT_STUB) {
                /* This is a transient unit, let's allow a little more */

                r = bus_service_set_transient_property(s, name, message, flags, reterr_error);
                if (r != 0)
                        return r;

                r = bus_exec_context_set_transient_property(u, &s->exec_context, name, message, flags, reterr_error);
                if (r != 0)
                        return r;

                r = bus_kill_context_set_transient_property(u, &s->kill_context, name, message, flags, reterr_error);
                if (r != 0)
                        return r;
        }

        return 0;
}

int bus_service_commit_properties(Unit *u) {
        assert(u);

        (void) unit_realize_cgroup(u);

        return 0;
}
