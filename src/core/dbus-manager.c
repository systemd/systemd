/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/capability.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "architecture.h"
#include "bitfield.h"
#include "build.h"
#include "bus-common-errors.h"
#include "bus-get-properties.h"
#include "bus-log-control-api.h"
#include "bus-message-util.h"
#include "bus-util.h"
#include "chase.h"
#include "confidential-virt.h"
#include "dbus-cgroup.h"
#include "dbus-execute.h"
#include "dbus.h"
#include "dbus-job.h"
#include "dbus-manager.h"
#include "dbus-scope.h"
#include "dbus-service.h"
#include "dbus-unit.h"
#include "dbus-util.h"
#include "dynamic-user.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "initrd-util.h"
#include "install.h"
#include "locale-util.h"
#include "log.h"
#include "manager-dump.h"
#include "manager.h"
#include "memfd-util.h"
#include "os-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "selinux-access.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "syslog-util.h"
#include "taint.h"
#include "unit-name.h"
#include "user-util.h"
#include "version.h"
#include "virt.h"
#include "watchdog.h"

static UnitFileFlags unit_file_bools_to_flags(bool runtime, bool force) {
        return (runtime ? UNIT_FILE_RUNTIME : 0) |
               (force   ? UNIT_FILE_FORCE   : 0);
}

BUS_DEFINE_PROPERTY_GET_ENUM(bus_property_get_oom_policy, oom_policy, OOMPolicy);
BUS_DEFINE_PROPERTY_GET_ENUM(bus_property_get_emergency_action, emergency_action, EmergencyAction);

static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_version, "s", GIT_VERSION);
static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_features, "s", systemd_features);
static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_architecture, "s", architecture_to_string(uname_architecture()));
static BUS_DEFINE_PROPERTY_GET2(property_get_system_state, "s", Manager, manager_state, manager_state_to_string);
static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_timer_slack_nsec, "t", (uint64_t) prctl(PR_GET_TIMERSLACK));
static BUS_DEFINE_PROPERTY_GET_REF(property_get_hashmap_size, "u", Hashmap *, hashmap_size);
static BUS_DEFINE_PROPERTY_GET_REF(property_get_set_size, "u", Set *, set_size);
static BUS_DEFINE_PROPERTY_GET(property_get_default_timeout_abort_usec, "t", Manager, manager_default_timeout_abort_usec);
static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_watchdog_device, "s", watchdog_get_device());
static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_watchdog_last_ping_realtime, "t", watchdog_get_last_ping(CLOCK_REALTIME));
static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_watchdog_last_ping_monotonic, "t", watchdog_get_last_ping(CLOCK_MONOTONIC));
static BUS_DEFINE_PROPERTY_GET(property_get_progress, "d", Manager, manager_get_progress);

static int property_get_virtualization(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Virtualization v;

        assert(bus);
        assert(reply);

        v = detect_virtualization();

        /* Make sure to return the empty string when we detect no virtualization, as that is the API.
         *
         * https://github.com/systemd/systemd/issues/1423
         */

        return sd_bus_message_append(
                        reply, "s",
                        v == VIRTUALIZATION_NONE ? NULL : virtualization_to_string(v));
}

static int property_get_confidential_virtualization(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        ConfidentialVirtualization v;

        assert(bus);
        assert(reply);

        v = detect_confidential_virtualization();

        return sd_bus_message_append(
                        reply, "s",
                        v <= 0 ? NULL : confidential_virtualization_to_string(v));
}

static int property_get_tainted(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        assert(bus);
        assert(reply);

        _cleanup_free_ char *s = taint_string();
        if (!s)
                return log_oom();

        return sd_bus_message_append(reply, "s", s);
}

static int property_set_log_target(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *value,
                void *userdata,
                sd_bus_error *reterr_error) {

        Manager *m = userdata;
        const char *t;
        int r;

        assert(bus);
        assert(value);

        r = sd_bus_message_read(value, "s", &t);
        if (r < 0)
                return r;

        if (isempty(t))
                manager_restore_original_log_target(m);
        else {
                LogTarget target;

                target = log_target_from_string(t);
                if (target < 0)
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid log target '%s'", t);

                manager_override_log_target(m, target);
        }

        return 0;
}

static int property_set_log_level(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *value,
                void *userdata,
                sd_bus_error *reterr_error) {

        Manager *m = userdata;
        const char *t;
        int r;

        assert(bus);
        assert(value);

        r = sd_bus_message_read(value, "s", &t);
        if (r < 0)
                return r;

        if (isempty(t))
                manager_restore_original_log_level(m);
        else {
                int level;

                level = log_level_from_string(t);
                if (level < 0)
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid log level '%s'", t);

                manager_override_log_level(m, level);
        }

        return 0;
}

static int property_get_environment(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        _cleanup_strv_free_ char **l = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = manager_get_effective_environment(m, &l);
        if (r < 0)
                return r;

        return sd_bus_message_append_strv(reply, l);
}

static int property_get_show_status(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Manager *m = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "b", manager_get_show_status_on(m));
}

static int property_get_runtime_watchdog(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Manager *m = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "t", manager_get_watchdog(m, WATCHDOG_RUNTIME));
}

static int property_get_pretimeout_watchdog(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Manager *m = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "t", manager_get_watchdog(m, WATCHDOG_PRETIMEOUT));
}

static int property_get_pretimeout_watchdog_governor(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Manager *m = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "s", m->watchdog_pretimeout_governor);
}

static int property_get_reboot_watchdog(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Manager *m = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "t", manager_get_watchdog(m, WATCHDOG_REBOOT));
}

static int property_get_kexec_watchdog(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Manager *m = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "t", manager_get_watchdog(m, WATCHDOG_KEXEC));
}

static int property_set_watchdog(Manager *m, WatchdogType type, sd_bus_message *value) {
        usec_t timeout;
        int r;

        assert(m);
        assert(value);

        assert_cc(sizeof(usec_t) == sizeof(uint64_t));

        r = sd_bus_message_read(value, "t", &timeout);
        if (r < 0)
                return r;

        manager_override_watchdog(m, type, timeout);
        return 0;
}

static int property_set_runtime_watchdog(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *value,
                void *userdata,
                sd_bus_error *reterr_error) {

        return property_set_watchdog(userdata, WATCHDOG_RUNTIME, value);
}

static int property_set_pretimeout_watchdog(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *value,
                void *userdata,
                sd_bus_error *reterr_error) {

        return property_set_watchdog(userdata, WATCHDOG_PRETIMEOUT, value);
}

static int property_set_pretimeout_watchdog_governor(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *value,
                void *userdata,
                sd_bus_error *reterr_error) {

        Manager *m = ASSERT_PTR(userdata);
        char *governor;
        int r;

        r = sd_bus_message_read(value, "s", &governor);
        if (r < 0)
                return r;
        if (!string_is_safe(governor))
                return -EINVAL;

        return manager_override_watchdog_pretimeout_governor(m, governor);
}

static int property_set_reboot_watchdog(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *value,
                void *userdata,
                sd_bus_error *reterr_error) {

        return property_set_watchdog(userdata, WATCHDOG_REBOOT, value);
}

static int property_set_kexec_watchdog(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *value,
                void *userdata,
                sd_bus_error *reterr_error) {

        _unused_ Manager *m = ASSERT_PTR(userdata);

        assert(bus);
        assert(value);

        return property_set_watchdog(userdata, WATCHDOG_KEXEC, value);
}

static int property_get_oom_score_adjust(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Manager *m = ASSERT_PTR(userdata);
        int r, n;

        assert(bus);
        assert(reply);

        if (m->defaults.oom_score_adjust_set)
                n = m->defaults.oom_score_adjust;
        else {
                n = 0;
                r = get_oom_score_adjust(&n);
                if (r < 0)
                        log_debug_errno(r, "Failed to read current OOM score adjustment value, ignoring: %m");
        }

        return sd_bus_message_append(reply, "i", n);
}

static int property_get_transactions_with_cycle(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "t");
        if (r < 0)
                return r;

        uint64_t *id;
        SET_FOREACH(id, m->transactions_with_cycle) {
                r = sd_bus_message_append_basic(reply, 't', id);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int bus_get_unit_by_name(Manager *m, sd_bus_message *message, const char *name, Unit **ret_unit, sd_bus_error *reterr_error) {
        Unit *u;
        int r;

        assert(m);
        assert(message);
        assert(ret_unit);

        /* More or less a wrapper around manager_get_unit() that generates nice errors and has one trick up
         * its sleeve: if the name is specified empty we use the client's unit. */

        if (isempty(name)) {
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

                r = bus_query_sender_pidref(message, &pidref);
                if (r < 0)
                        return r;

                u = manager_get_unit_by_pidref(m, &pidref);
                if (!u)
                        return sd_bus_error_set(reterr_error, BUS_ERROR_NO_SUCH_UNIT, "Client not member of any unit.");
        } else {
                u = manager_get_unit(m, name);
                if (!u)
                        return sd_bus_error_setf(reterr_error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s not loaded.", name);
        }

        *ret_unit = u;
        return 0;
}

static int bus_load_unit_by_name(Manager *m, sd_bus_message *message, const char *name, Unit **ret_unit, sd_bus_error *reterr_error) {
        assert(m);
        assert(message);
        assert(ret_unit);

        /* Pretty much the same as bus_get_unit_by_name(), but we also load the unit if necessary. */

        if (isempty(name))
                return bus_get_unit_by_name(m, message, name, ret_unit, reterr_error);

        return manager_load_unit(m, name, NULL, reterr_error, ret_unit);
}

static int reply_unit_path(Unit *u, sd_bus_message *message, sd_bus_error *reterr_error) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(u);
        assert(message);

        r = mac_selinux_unit_access_check(u, message, "status", reterr_error);
        if (r < 0)
                return r;

        path = unit_dbus_path(u);
        if (!path)
                return log_oom();

        return sd_bus_reply_method_return(message, "o", path);
}

static int method_get_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        const char *name;
        Unit *u;
        int r;

        assert(message);

        /* Anyone can call this method */

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = bus_get_unit_by_name(m, message, name, &u, reterr_error);
        if (r < 0)
                return r;

        return reply_unit_path(u, message, reterr_error);
}

static int method_get_unit_by_pid(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        Unit *u;
        int r;

        assert(message);

        assert_cc(sizeof(pid_t) == sizeof(uint32_t));

        /* Anyone can call this method */

        r = sd_bus_message_read(message, "u", &pidref.pid);
        if (r < 0)
                return r;
        if (pidref.pid < 0)
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid PID " PID_FMT, pidref.pid);
        if (pidref.pid == 0) {
                r = bus_query_sender_pidref(message, &pidref);
                if (r < 0)
                        return r;
        }

        u = manager_get_unit_by_pidref(m, &pidref);
        if (!u)
                return sd_bus_error_setf(reterr_error, BUS_ERROR_NO_UNIT_FOR_PID, "PID "PID_FMT" does not belong to any loaded unit.", pidref.pid);

        return reply_unit_path(u, message, reterr_error);
}

static int method_get_unit_by_invocation_id(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_free_ char *path = NULL;
        Manager *m = ASSERT_PTR(userdata);
        sd_id128_t id;
        Unit *u;
        int r;

        assert(message);

        /* Anyone can call this method */

        if (bus_message_read_id128(message, &id) < 0)
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid invocation ID");

        if (sd_id128_is_null(id)) {
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

                r = bus_query_sender_pidref(message, &pidref);
                if (r < 0)
                        return r;

                u = manager_get_unit_by_pidref(m, &pidref);
                if (!u)
                        return sd_bus_error_setf(reterr_error, BUS_ERROR_NO_SUCH_UNIT,
                                                 "Client " PID_FMT " not member of any unit.", pidref.pid);
        } else {
                u = hashmap_get(m->units_by_invocation_id, &id);
                if (!u)
                        return sd_bus_error_setf(reterr_error, BUS_ERROR_NO_UNIT_FOR_INVOCATION_ID, "No unit with the specified invocation ID " SD_ID128_FORMAT_STR " known.", SD_ID128_FORMAT_VAL(id));
        }

        r = mac_selinux_unit_access_check(u, message, "status", reterr_error);
        if (r < 0)
                return r;

        /* So here's a special trick: the bus path we return actually references the unit by its invocation
         * ID instead of the unit name. This means it stays valid only as long as the invocation ID stays the
         * same. */
        path = unit_dbus_path_invocation_id(u);
        if (!path)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", path);
}

static int method_get_unit_by_control_group(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = userdata;
        const char *cgroup;
        Unit *u;
        int r;

        r = sd_bus_message_read(message, "s", &cgroup);
        if (r < 0)
                return r;

        if (!path_is_absolute(cgroup))
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Control group path is not absolute: %s", cgroup);

        if (!path_is_normalized(cgroup))
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Control group path is not normalized: %s", cgroup);

        u = manager_get_unit_by_cgroup(m, cgroup);
        if (!u)
                return sd_bus_error_setf(reterr_error, BUS_ERROR_NO_SUCH_UNIT,
                                         "Control group '%s' is not valid or not managed by this instance",
                                         cgroup);

        return reply_unit_path(u, message, reterr_error);
}

static int method_get_unit_by_pidfd(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        Manager *m = ASSERT_PTR(userdata);
        _cleanup_free_ char *path = NULL;
        int r, pidfd;
        Unit *u;

        assert(message);

        r = sd_bus_message_read(message, "h", &pidfd);
        if (r < 0)
                return r;

        r = pidref_set_pidfd(&pidref, pidfd);
        if (r < 0)
                return sd_bus_error_set_errnof(reterr_error, r, "Failed to get PID from PIDFD: %m");

        u = manager_get_unit_by_pidref(m, &pidref);
        if (!u)
                return sd_bus_error_setf(reterr_error, BUS_ERROR_NO_UNIT_FOR_PID, "PID "PID_FMT" does not belong to any loaded unit.", pidref.pid);

        r = mac_selinux_unit_access_check(u, message, "status", reterr_error);
        if (r < 0)
                return r;

        path = unit_dbus_path(u);
        if (!path)
                return log_oom();

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "os", path, u->id);
        if (r < 0)
                return r;

        r = sd_bus_message_append_array(reply, 'y', u->invocation_id.bytes, sizeof(u->invocation_id.bytes));
        if (r < 0)
                return r;

        /* Double-check that the process is still alive and that the PID did not change before returning the
         * answer. */
        r = pidref_verify(&pidref);
        if (r == -ESRCH)
                return sd_bus_error_setf(reterr_error,
                                         BUS_ERROR_NO_SUCH_PROCESS,
                                         "The PIDFD's PID "PID_FMT" changed during the lookup operation.",
                                         pidref.pid);
        if (r < 0)
                return sd_bus_error_set_errnof(reterr_error, r, "Failed to get PID from PIDFD: %m");

        return sd_bus_message_send(reply);
}

static int method_load_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        const char *name;
        Unit *u;
        int r;

        assert(message);

        /* Anyone can call this method */

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = bus_load_unit_by_name(m, message, name, &u, reterr_error);
        if (r < 0)
                return r;

        return reply_unit_path(u, message, reterr_error);
}

static int method_start_unit_generic(sd_bus_message *message, Manager *m, JobType job_type, bool reload_if_possible, sd_bus_error *reterr_error) {
        const char *name;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_load_unit(m, name, NULL, reterr_error, &u);
        if (r < 0)
                return r;

        return bus_unit_method_start_generic(message, u, job_type, reload_if_possible, reterr_error);
}

static int method_start_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_start_unit_generic(message, userdata, JOB_START, /* reload_if_possible= */ false, reterr_error);
}

static int method_stop_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_start_unit_generic(message, userdata, JOB_STOP, /* reload_if_possible= */ false, reterr_error);
}

static int method_reload_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_start_unit_generic(message, userdata, JOB_RELOAD, /* reload_if_possible= */ false, reterr_error);
}

static int method_restart_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_start_unit_generic(message, userdata, JOB_RESTART, /* reload_if_possible= */ false, reterr_error);
}

static int method_try_restart_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_start_unit_generic(message, userdata, JOB_TRY_RESTART, /* reload_if_possible= */ false, reterr_error);
}

static int method_reload_or_restart_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_start_unit_generic(message, userdata, JOB_RESTART, /* reload_if_possible= */ true, reterr_error);
}

static int method_reload_or_try_restart_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_start_unit_generic(message, userdata, JOB_TRY_RESTART, /* reload_if_possible= */ true, reterr_error);
}

typedef enum GenericUnitOperationFlags {
        GENERIC_UNIT_LOAD            = 1 << 0, /* Load if the unit is not loaded yet */
        GENERIC_UNIT_VALIDATE_LOADED = 1 << 1, /* Verify unit is properly loaded before forwarding call */
} GenericUnitOperationFlags;

static int method_generic_unit_operation(
                sd_bus_message *message,
                Manager *m,
                sd_bus_error *reterr_error,
                UnitType type,
                sd_bus_message_handler_t handler,
                GenericUnitOperationFlags flags) {

        const char *name;
        Unit *u;
        int r;

        assert(message);
        assert(m);
        assert(handler);

        /* Read the first argument from the command and pass the operation to the specified per-unit
         * method. */

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        if (!isempty(name) && FLAGS_SET(flags, GENERIC_UNIT_LOAD))
                r = manager_load_unit(m, name, NULL, reterr_error, &u);
        else
                r = bus_get_unit_by_name(m, message, name, &u, reterr_error);
        if (r < 0)
                return r;

        if (type != _UNIT_TYPE_INVALID && u->type != type)
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_NOT_SUPPORTED,
                                         "%s operation is not supported for unit type '%s'",
                                         sd_bus_message_get_member(message), unit_type_to_string(u->type));

        if (FLAGS_SET(flags, GENERIC_UNIT_VALIDATE_LOADED)) {
                r = bus_unit_validate_load_state(u, reterr_error);
                if (r < 0)
                        return r;
        }

        return handler(message, u, reterr_error);
}

static int method_enqueue_unit_job(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        /* We don't bother with GENERIC_UNIT_VALIDATE_LOADED here, as the job logic validates that anyway */
        return method_generic_unit_operation(message, userdata, reterr_error, _UNIT_TYPE_INVALID, bus_unit_method_enqueue_job, GENERIC_UNIT_LOAD);
}

static int method_start_unit_replace(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        const char *old_name;
        Unit *u;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &old_name);
        if (r < 0)
                return r;

        r = bus_get_unit_by_name(m, message, old_name, &u, reterr_error);
        if (r < 0)
                return r;
        if (!u->job || u->job->type != JOB_START)
                return sd_bus_error_setf(reterr_error, BUS_ERROR_NO_SUCH_JOB, "No job queued for unit %s", old_name);

        return method_start_unit_generic(message, m, JOB_START, /* reload_if_possible= */ false, reterr_error);
}

static int method_kill_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        /* We don't bother with GENERIC_UNIT_LOAD or GENERIC_UNIT_VALIDATE_LOADED here, as it shouldn't
         * matter whether a unit is loaded for killing any processes in the unit's cgroup. */
        return method_generic_unit_operation(message, userdata, reterr_error, _UNIT_TYPE_INVALID, bus_unit_method_kill, /* flags= */ 0);
}

static int method_kill_unit_subgroup(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        /* We don't bother with GENERIC_UNIT_LOAD or GENERIC_UNIT_VALIDATE_LOADED here, as it shouldn't
         * matter whether a unit is loaded for killing any processes in the unit's cgroup. */
        return method_generic_unit_operation(message, userdata, reterr_error, _UNIT_TYPE_INVALID, bus_unit_method_kill_subgroup, /* flags= */ 0);
}

static int method_clean_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        /* Load the unit if necessary, in order to load it, and insist on the unit being loaded to be
         * cleaned */
        return method_generic_unit_operation(message, userdata, reterr_error, _UNIT_TYPE_INVALID, bus_unit_method_clean, GENERIC_UNIT_LOAD|GENERIC_UNIT_VALIDATE_LOADED);
}

static int method_freeze_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        /* Only active units can be frozen, which must be properly loaded already */
        return method_generic_unit_operation(message, userdata, reterr_error, _UNIT_TYPE_INVALID, bus_unit_method_freeze, GENERIC_UNIT_VALIDATE_LOADED);
}

static int method_thaw_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        /* Same as freeze above */
        return method_generic_unit_operation(message, userdata, reterr_error, _UNIT_TYPE_INVALID, bus_unit_method_thaw, GENERIC_UNIT_VALIDATE_LOADED);
}

static int method_reset_failed_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        /* Don't load the unit (because unloaded units can't be in failed state), and don't insist on the
         * unit to be loaded properly (since a failed unit might have its unit file disappeared) */
        return method_generic_unit_operation(message, userdata, reterr_error, _UNIT_TYPE_INVALID, bus_unit_method_reset_failed, /* flags= */ 0);
}

static int method_set_unit_properties(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        /* Only change properties on fully loaded units, and load them in order to set properties */
        return method_generic_unit_operation(message, userdata, reterr_error, _UNIT_TYPE_INVALID, bus_unit_method_set_properties, GENERIC_UNIT_LOAD|GENERIC_UNIT_VALIDATE_LOADED);
}

static int method_bind_mount_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        /* Only add mounts on fully loaded units */
        return method_generic_unit_operation(message, userdata, reterr_error, UNIT_SERVICE, bus_service_method_bind_mount, GENERIC_UNIT_VALIDATE_LOADED);
}

static int method_mount_image_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        /* Only add mounts on fully loaded units */
        return method_generic_unit_operation(message, userdata, reterr_error, UNIT_SERVICE, bus_service_method_mount_image, GENERIC_UNIT_VALIDATE_LOADED);
}

static int method_ref_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        /* Only allow reffing of fully loaded units, and make sure reffing a unit loads it. */
        return method_generic_unit_operation(message, userdata, reterr_error, _UNIT_TYPE_INVALID, bus_unit_method_ref, GENERIC_UNIT_LOAD|GENERIC_UNIT_VALIDATE_LOADED);
}

static int method_unref_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        /* Dropping a ref OTOH should not require the unit to still be loaded. And since a reffed unit is a
         * loaded unit there's no need to load the unit for unreffing it. */
        return method_generic_unit_operation(message, userdata, reterr_error, _UNIT_TYPE_INVALID, bus_unit_method_unref, /* flags= */ 0);
}

static int reply_unit_info(sd_bus_message *reply, Unit *u) {
        _cleanup_free_ char *unit_path = NULL, *job_path = NULL;
        Unit *following;

        following = unit_following(u);

        unit_path = unit_dbus_path(u);
        if (!unit_path)
                return -ENOMEM;

        if (u->job) {
                job_path = job_dbus_path(u->job);
                if (!job_path)
                        return -ENOMEM;
        }

        return sd_bus_message_append(
                        reply, "(ssssssouso)",
                        u->id,
                        unit_description(u),
                        unit_load_state_to_string(u->load_state),
                        unit_active_state_to_string(unit_active_state(u)),
                        unit_sub_state_to_string(u),
                        following ? following->id : "",
                        unit_path,
                        u->job ? u->job->id : 0,
                        u->job ? job_type_to_string(u->job->type) : "",
                        empty_to_root(job_path));
}

static int method_list_units_by_names(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;
        _cleanup_strv_free_ char **units = NULL;

        assert(message);

        r = sd_bus_message_read_strv(message, &units);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(ssssssouso)");
        if (r < 0)
                return r;

        STRV_FOREACH(unit, units) {
                Unit *u;

                if (!unit_name_is_valid(*unit, UNIT_NAME_ANY))
                        continue;

                r = bus_load_unit_by_name(m, message, *unit, &u, reterr_error);
                if (r < 0)
                        return r;

                r = reply_unit_info(reply, u);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int method_get_unit_processes(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        /* Don't load a unit actively (since it won't have any processes if it's not loaded), but don't
         * insist on the unit being loaded either (because even improperly loaded units might still have
         * processes around). */
        return method_generic_unit_operation(message, userdata, reterr_error, _UNIT_TYPE_INVALID, bus_unit_method_get_processes, /* flags= */ 0);
}

static int method_attach_processes_to_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        /* Don't allow attaching new processes to units that aren't loaded. Don't bother with loading a unit
         * for this purpose though, as an unloaded unit is a stopped unit, and we don't allow attaching
         * processes to stopped units anyway. */
        return method_generic_unit_operation(message, userdata, reterr_error, _UNIT_TYPE_INVALID, bus_unit_method_attach_processes, GENERIC_UNIT_VALIDATE_LOADED);
}

static int method_remove_subgroup_from_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        /* Don't allow removal of subgroups from units that aren't loaded. But allow loading the unit, since
         * this is clean-up work, that is OK to do when the unit is stopped already. */
        return method_generic_unit_operation(message, userdata, reterr_error, _UNIT_TYPE_INVALID, bus_unit_method_remove_subgroup, GENERIC_UNIT_LOAD|GENERIC_UNIT_VALIDATE_LOADED);
}

static int transient_unit_from_message(
                Manager *m,
                sd_bus_message *message,
                const char *name,
                Unit **ret_unit,
                sd_bus_error *reterr_error) {

        UnitType t;
        Unit *u;
        int r;

        assert(m);
        assert(message);
        assert(name);

        t = unit_name_to_type(name);
        if (t < 0)
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Invalid unit name or type: %s", name);

        if (!unit_vtable[t]->can_transient)
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Unit type %s does not support transient units.",
                                         unit_type_to_string(t));

        r = manager_load_unit(m, name, NULL, reterr_error, &u);
        if (r < 0)
                return r;

        if (!unit_is_pristine(u))
                return sd_bus_error_setf(reterr_error, BUS_ERROR_UNIT_EXISTS,
                                         "Unit %s was already loaded or has a fragment file.", name);

        /* OK, the unit failed to load and is unreferenced, now let's
         * fill in the transient data instead */
        r = unit_make_transient(u);
        if (r < 0)
                return r;

        /* Set our properties */
        r = bus_unit_set_properties(u, message, UNIT_RUNTIME, false, reterr_error);
        if (r < 0)
                return r;

        /* If the client asked for it, automatically add a reference to this unit. */
        if (u->bus_track_add) {
                r = bus_unit_track_add_sender(u, message);
                if (r < 0)
                        return log_error_errno(r, "Failed to watch sender: %m");
        }

        /* Now load the missing bits of the unit we just created */
        unit_add_to_load_queue(u);
        manager_dispatch_load_queue(m);

        if (ret_unit)
                *ret_unit = u;

        return 0;
}

static int transient_aux_units_from_message(
                Manager *m,
                sd_bus_message *message,
                sd_bus_error *reterr_error) {

        int r;

        assert(m);
        assert(message);

        r = sd_bus_message_enter_container(message, 'a', "(sa(sv))");
        if (r < 0)
                return r;

        while ((r = sd_bus_message_enter_container(message, 'r', "sa(sv)")) > 0) {
                const char *name;

                r = sd_bus_message_read(message, "s", &name);
                if (r < 0)
                        return r;

                r = transient_unit_from_message(m, message, name, /* ret_unit= */ NULL, reterr_error);
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;
        }
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(message);
        if (r < 0)
                return r;

        return 0;
}

static int method_start_transient_unit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        const char *name, *smode;
        Manager *m = ASSERT_PTR(userdata);
        JobMode mode;
        Unit *u;
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "start", reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "ss", &name, &smode);
        if (r < 0)
                return r;

        mode = job_mode_from_string(smode);
        if (mode < 0)
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Job mode %s is invalid.", smode);

        r = bus_verify_manage_units_async_impl(
                        m,
                        name,
                        "start",
                        N_("Authentication is required to start transient unit '$(unit)'."),
                        message,
                        reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = transient_unit_from_message(m, message, name, &u, reterr_error);
        if (r < 0)
                return r;

        r = transient_aux_units_from_message(m, message, reterr_error);
        if (r < 0)
                return r;

        /* Finally, start it */
        return bus_unit_queue_job(message, u, JOB_START, mode, 0, reterr_error);
}

static int method_get_job(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_free_ char *path = NULL;
        Manager *m = ASSERT_PTR(userdata);
        uint32_t id;
        Job *j;
        int r;

        assert(message);

        /* Anyone can call this method */

        r = sd_bus_message_read(message, "u", &id);
        if (r < 0)
                return r;

        j = manager_get_job(m, id);
        if (!j)
                return sd_bus_error_setf(reterr_error, BUS_ERROR_NO_SUCH_JOB, "Job %u does not exist.", (unsigned) id);

        r = mac_selinux_unit_access_check(j->unit, message, "status", reterr_error);
        if (r < 0)
                return r;

        path = job_dbus_path(j);
        if (!path)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", path);
}

static int method_cancel_job(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        uint32_t id;
        Job *j;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "u", &id);
        if (r < 0)
                return r;

        j = manager_get_job(m, id);
        if (!j)
                return sd_bus_error_setf(reterr_error, BUS_ERROR_NO_SUCH_JOB, "Job %u does not exist.", (unsigned) id);

        return bus_job_method_cancel(message, j, reterr_error);
}

static int method_clear_jobs(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "reload", reterr_error);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async(m, message, reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        manager_clear_jobs(m);

        return sd_bus_reply_method_return(message, NULL);
}

static int method_reset_failed(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "reload", reterr_error);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async(m, message, reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        manager_reset_failed(m);

        return sd_bus_reply_method_return(message, NULL);
}

static int list_units_filtered(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error, char **states, char **patterns) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        const char *k;
        Unit *u;
        int r;

        assert(message);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(ssssssouso)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH_KEY(u, k, m->units) {
                if (k != u->id)
                        continue;

                if (!unit_passes_filter(u, states, patterns))
                        continue;

                r = reply_unit_info(reply, u);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int method_list_units(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return list_units_filtered(message, userdata, reterr_error, NULL, NULL);
}

static int method_list_units_filtered(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_strv_free_ char **states = NULL;
        int r;

        r = sd_bus_message_read_strv(message, &states);
        if (r < 0)
                return r;

        return list_units_filtered(message, userdata, reterr_error, states, NULL);
}

static int method_list_units_by_patterns(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_strv_free_ char **states = NULL;
        _cleanup_strv_free_ char **patterns = NULL;
        int r;

        r = sd_bus_message_read_strv(message, &states);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &patterns);
        if (r < 0)
                return r;

        return list_units_filtered(message, userdata, reterr_error, states, patterns);
}

static int method_list_jobs(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Job *j;
        int r;

        assert(message);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(usssoo)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(j, m->jobs) {
                _cleanup_free_ char *unit_path = NULL, *job_path = NULL;

                job_path = job_dbus_path(j);
                if (!job_path)
                        return -ENOMEM;

                unit_path = unit_dbus_path(j->unit);
                if (!unit_path)
                        return -ENOMEM;

                r = sd_bus_message_append(
                                reply, "(usssoo)",
                                j->id,
                                j->unit->id,
                                job_type_to_string(j->type),
                                job_state_to_string(j->state),
                                job_path,
                                unit_path);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int method_subscribe(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", reterr_error);
        if (r < 0)
                return r;

        if (sd_bus_message_get_bus(message) == m->api_bus) {

                /* Note that direct bus connection subscribe by
                 * default, we only track peers on the API bus here */

                if (!m->subscribed) {
                        r = sd_bus_track_new(sd_bus_message_get_bus(message), &m->subscribed, NULL, NULL);
                        if (r < 0)
                                return r;
                }

                r = sd_bus_track_add_sender(m->subscribed, message);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_error_set(reterr_error, BUS_ERROR_ALREADY_SUBSCRIBED, "Client is already subscribed.");
        }

        return sd_bus_reply_method_return(message, NULL);
}

static int method_unsubscribe(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", reterr_error);
        if (r < 0)
                return r;

        if (sd_bus_message_get_bus(message) == m->api_bus) {
                r = sd_bus_track_remove_sender(m->subscribed, message);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_error_set(reterr_error, BUS_ERROR_NOT_SUBSCRIBED, "Client is not subscribed.");
        }

        return sd_bus_reply_method_return(message, NULL);
}

static int dump_impl(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *reterr_error,
                char **patterns,
                int (*reply)(sd_bus_message *, char *)) {

        _cleanup_free_ char *dump = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        /* 'status' access is the bare minimum always needed for this, as the policy might straight out
         * forbid a client from querying any information from systemd, regardless of any rate limiting. */
        r = mac_selinux_access_check(message, "status", reterr_error);
        if (r < 0)
                return r;

        /* Rate limit reached? Check if the caller is privileged/allowed by policy to bypass this. We
         * check the rate limit first to avoid the expensive roundtrip to polkit when not needed. */
        if (!ratelimit_below(&m->dump_ratelimit)) {
                /* We need a way for SELinux to constrain the operation when the rate limit is active, even
                 * if polkit would allow it, but we cannot easily add new named permissions, so we need to
                 * use an existing one. Reload/reexec are also slow but non-destructive/modifying
                 * operations, and can cause PID1 to stall. So it seems similar enough in terms of security
                 * considerations and impact, and thus use the same access check for dumps which, given the
                 * large amount of data to fetch, can stall PID1 for quite some time. */
                r = mac_selinux_access_check(message, "reload", /* error= */ NULL);
                if (r < 0)
                        goto ratelimited;

                r = bus_verify_bypass_dump_ratelimit_async(m, message, /* reterr_error= */ NULL);
                if (r < 0)
                        goto ratelimited;
                if (r == 0)
                        /* No authorization for now, but the async polkit stuff will call us again when it
                         * has it */
                        return 1;
        }

        r = manager_get_dump_string(m, patterns, &dump);
        if (r < 0)
                return r;

        return reply(message, dump);

ratelimited:
        log_warning("Dump request rejected due to rate limit on unprivileged callers, blocked for %s.",
                    FORMAT_TIMESPAN(ratelimit_left(&m->dump_ratelimit), USEC_PER_SEC));
        return sd_bus_error_setf(reterr_error,
                                 SD_BUS_ERROR_LIMITS_EXCEEDED,
                                 "Dump request rejected due to rate limit on unprivileged callers, blocked for %s.",
                                 FORMAT_TIMESPAN(ratelimit_left(&m->dump_ratelimit), USEC_PER_SEC));
}

static int reply_dump(sd_bus_message *message, char *dump) {
        return sd_bus_reply_method_return(message, "s", dump);
}

static int method_dump(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return dump_impl(message, userdata, reterr_error, NULL, reply_dump);
}

static int reply_dump_by_fd(sd_bus_message *message, char *dump) {
        _cleanup_close_ int fd = -EBADF;

        fd = memfd_new_and_seal_string("dump", dump);
        if (fd < 0)
                return fd;

        return sd_bus_reply_method_return(message, "h", fd);
}

static int method_dump_by_fd(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return dump_impl(message, userdata, reterr_error, NULL, reply_dump_by_fd);
}

static int dump_units_matching_patterns(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *reterr_error,
                int (*reply)(sd_bus_message *, char *)) {
        _cleanup_strv_free_ char **patterns = NULL;
        int r;

        r = sd_bus_message_read_strv(message, &patterns);
        if (r < 0)
                return r;

        return dump_impl(message, userdata, reterr_error, patterns, reply);
}

static int method_dump_units_matching_patterns(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return dump_units_matching_patterns(message, userdata, reterr_error, reply_dump);
}

static int method_dump_units_matching_patterns_by_fd(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return dump_units_matching_patterns(message, userdata, reterr_error, reply_dump_by_fd);
}

static int method_refuse_snapshot(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return sd_bus_error_set(reterr_error, SD_BUS_ERROR_NOT_SUPPORTED, "Support for snapshots has been removed.");
}

static void log_caller(sd_bus_message *message, Manager *manager, const char *method) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

        assert(message);
        assert(manager);
        assert(method);

        if (sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID|SD_BUS_CREDS_PIDFD|SD_BUS_CREDS_AUGMENT, &creds) < 0)
                return;

        /* We need at least the PID, otherwise there's nothing to log, the rest is optional. */
        if (bus_creds_get_pidref(creds, &pidref) < 0)
                return;

        manager_log_caller(manager, &pidref, method);
}

static int method_reload(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "reload", reterr_error);
        if (r < 0)
                return r;

        r = bus_verify_reload_daemon_async(m, message, reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        /* Write a log message noting the unit or process who requested the Reload() */
        log_caller(message, m, "Reload");

        /* Check the rate limit after the authorization succeeds, to avoid denial-of-service issues. */
        if (!ratelimit_below(&m->reload_reexec_ratelimit)) {
                log_warning("Reloading request rejected due to rate limit.");
                return sd_bus_error_set(reterr_error,
                                        SD_BUS_ERROR_LIMITS_EXCEEDED,
                                        "Reload() request rejected due to rate limit.");
        }

        /* Instead of sending the reply back right away, we just
         * remember that we need to and then send it after the reload
         * is finished. That way the caller knows when the reload
         * finished. */

        assert(!m->pending_reload_message_dbus);
        assert(!m->pending_reload_message_vl);
        r = sd_bus_message_new_method_return(message, &m->pending_reload_message_dbus);
        if (r < 0)
                return r;

        m->objective = MANAGER_RELOAD;

        return 1;
}

static int method_reexecute(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "reload", reterr_error);
        if (r < 0)
                return r;

        r = bus_verify_reload_daemon_async(m, message, reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        /* Write a log message noting the unit or process who requested the Reexecute() */
        log_caller(message, m, "Reexecution");

        /* Check the rate limit after the authorization succeeds, to avoid denial-of-service issues. */
        if (!ratelimit_below(&m->reload_reexec_ratelimit)) {
                log_warning("Reexecution request rejected due to rate limit.");
                return sd_bus_error_set(reterr_error,
                                        SD_BUS_ERROR_LIMITS_EXCEEDED,
                                        "Reexecute() request rejected due to rate limit.");
        }

        /* We don't send a reply back here, the client should
         * just wait for us disconnecting. */

        m->objective = MANAGER_REEXECUTE;
        return 1;
}

static int method_exit(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "halt", reterr_error);
        if (r < 0)
                return r;

        log_caller(message, m, "Exit");

        /* Exit() (in contrast to SetExitCode()) is actually allowed even if
         * we are running on the host. It will fall back on reboot() in
         * systemd-shutdown if it cannot do the exit() because it isn't a
         * container. */

        m->objective = MANAGER_EXIT;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_reboot(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_NOT_SUPPORTED,
                                        "Reboot is only supported by system manager.");

        r = mac_selinux_access_check(message, "reboot", reterr_error);
        if (r < 0)
                return r;

        log_caller(message, m, "Reboot");

        m->objective = MANAGER_REBOOT;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_soft_reboot(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        _cleanup_free_ char *rt = NULL;
        const char *root;
        int r;

        assert(message);

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_NOT_SUPPORTED,
                                        "Soft reboot is only supported by system manager.");

        r = mac_selinux_access_check(message, "reboot", reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "s", &root);
        if (r < 0)
                return r;

        if (!isempty(root)) {
                if (!path_is_valid(root))
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "New root directory '%s' must be a valid path.", root);
                if (!path_is_absolute(root))
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "New root directory path '%s' is not absolute.", root);

                r = path_simplify_alloc(root, &rt);
                if (r < 0)
                        return r;
        }

        log_caller(message, m, "Soft reboot");

        free_and_replace(m->switch_root, rt);
        m->objective = MANAGER_SOFT_REBOOT;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_poweroff(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_NOT_SUPPORTED,
                                        "Powering off is only supported by system manager.");

        r = mac_selinux_access_check(message, "halt", reterr_error);
        if (r < 0)
                return r;

        log_caller(message, m, "Poweroff");

        m->objective = MANAGER_POWEROFF;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_halt(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_NOT_SUPPORTED,
                                        "Halt is only supported by system manager.");

        r = mac_selinux_access_check(message, "halt", reterr_error);
        if (r < 0)
                return r;

        log_caller(message, m, "Halt");

        m->objective = MANAGER_HALT;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_kexec(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_NOT_SUPPORTED,
                                        "KExec is only supported by system manager.");

        r = mac_selinux_access_check(message, "reboot", reterr_error);
        if (r < 0)
                return r;

        log_caller(message, m, "Kexec");

        m->objective = MANAGER_KEXEC;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_switch_root(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        _cleanup_free_ char *ri = NULL, *rt = NULL;
        const char *root, *init;
        int r;

        assert(message);

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_NOT_SUPPORTED,
                                        "Root switching is only supported by system manager.");

        r = mac_selinux_access_check(message, "reboot", reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "ss", &root, &init);
        if (r < 0)
                return r;

        if (isempty(root))
                /* If path is not specified, default to "/sysroot" which is what we generally expect initrds
                 * to use */
                root = "/sysroot";
        else {
                if (!path_is_valid(root))
                        return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                                "New root directory must be a valid path.");

                if (!path_is_absolute(root))
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "New root path '%s' is not absolute.", root);

                r = path_is_root(root);
                if (r < 0)
                        return sd_bus_error_set_errnof(reterr_error, r,
                                                       "Failed to check if new root directory '%s' is the same as old root: %m",
                                                       root);
                if (r > 0)
                        return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                                "New root directory cannot be the old root directory.");
        }

        /* Safety check */
        if (!in_initrd())
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                        "Not in initrd, refusing switch-root operation.");

        r = path_is_os_tree(root);
        if (r < 0)
                return sd_bus_error_set_errnof(reterr_error, r,
                                               "Failed to determine whether root path '%s' contains an OS tree: %m",
                                               root);
        if (r == 0)
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Specified switch root path '%s' does not seem to be an OS tree. os-release file is missing.",
                                         root);

        if (!isempty(init)) {
                if (!path_is_valid(init))
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Path to init binary '%s' is not a valid path.", init);

                if (!path_is_absolute(init))
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Path to init binary '%s' not absolute.", init);

                r = chase_and_access(init, root, CHASE_PREFIX_ROOT, X_OK, NULL);
                if (r == -EACCES)
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Init binary %s is not executable.", init);
                if (r < 0)
                        return sd_bus_error_set_errnof(reterr_error, r,
                                                       "Could not resolve init executable %s: %m", init);
        }

        r = path_simplify_alloc(root, &rt);
        if (r < 0)
                return r;

        if (!isempty(init)) {
                r = path_simplify_alloc(init, &ri);
                if (r < 0)
                        return r;
        }

        free_and_replace(m->switch_root, rt);
        free_and_replace(m->switch_root_init, ri);

        m->objective = MANAGER_SWITCH_ROOT;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_set_environment(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_strv_free_ char **plus = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "reload", reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &plus);
        if (r < 0)
                return r;
        if (!strv_env_is_valid(plus))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid environment assignments");

        r = bus_verify_set_environment_async(m, message, reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = manager_client_environment_modify(m, NULL, plus);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_unset_environment(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_strv_free_ char **minus = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "reload", reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &minus);
        if (r < 0)
                return r;

        if (!strv_env_name_or_assignment_is_valid(minus))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                        "Invalid environment variable names or assignments");

        r = bus_verify_set_environment_async(m, message, reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = manager_client_environment_modify(m, minus, NULL);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_unset_and_set_environment(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_strv_free_ char **minus = NULL, **plus = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "reload", reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &minus);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &plus);
        if (r < 0)
                return r;

        if (!strv_env_name_or_assignment_is_valid(minus))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                        "Invalid environment variable names or assignments");
        if (!strv_env_is_valid(plus))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                        "Invalid environment assignments");

        r = bus_verify_set_environment_async(m, message, reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = manager_client_environment_modify(m, minus, plus);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_set_exit_code(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        uint8_t code;
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "exit", reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_read_basic(message, 'y', &code);
        if (r < 0)
                return r;

        m->return_value = code;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_lookup_dynamic_user_by_name(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        const char *name;
        uid_t uid;
        int r;

        assert(message);

        r = sd_bus_message_read_basic(message, 's', &name);
        if (r < 0)
                return r;

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_NOT_SUPPORTED,
                                        "Dynamic users are only supported in the system instance.");
        if (!valid_user_group_name(name, VALID_USER_RELAX))
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                         "User name invalid: %s", name);

        r = dynamic_user_lookup_name(m, name, &uid);
        if (r == -ESRCH)
                return sd_bus_error_setf(reterr_error, BUS_ERROR_NO_SUCH_DYNAMIC_USER,
                                         "Dynamic user %s does not exist.", name);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "u", (uint32_t) uid);
}

static int method_lookup_dynamic_user_by_uid(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_free_ char *name = NULL;
        Manager *m = ASSERT_PTR(userdata);
        uid_t uid;
        int r;

        assert(message);

        assert_cc(sizeof(uid_t) == sizeof(uint32_t));
        r = sd_bus_message_read_basic(message, 'u', &uid);
        if (r < 0)
                return r;

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_NOT_SUPPORTED,
                                        "Dynamic users are only supported in the system instance.");
        if (!uid_is_valid(uid))
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                         "User ID invalid: " UID_FMT, uid);

        r = dynamic_user_lookup_uid(m, uid, &name);
        if (r == -ESRCH)
                return sd_bus_error_setf(reterr_error, BUS_ERROR_NO_SUCH_DYNAMIC_USER,
                                         "Dynamic user ID " UID_FMT " does not exist.", uid);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "s", name);
}

static int method_get_dynamic_users(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        DynamicUser *d;
        int r;

        assert(message);

        assert_cc(sizeof(uid_t) == sizeof(uint32_t));

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_NOT_SUPPORTED,
                                        "Dynamic users are only supported in the system instance.");

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(us)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(d, m->dynamic_users) {
                uid_t uid;

                r = dynamic_user_current(d, &uid);
                if (r == -EAGAIN) /* not realized yet? */
                        continue;
                if (r < 0)
                        return sd_bus_error_set(reterr_error, SD_BUS_ERROR_FAILED,
                                                "Failed to look up a dynamic user.");

                r = sd_bus_message_append(reply, "(us)", uid, d->name);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int method_enqueue_marked_jobs(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "start", reterr_error);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async(m, message, reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        log_info("Queuing reload/restart jobs for marked units%s", glyph(GLYPH_ELLIPSIS));

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "o");
        if (r < 0)
                return r;

        Unit *u;
        char *k;
        int ret = 0;
        HASHMAP_FOREACH_KEY(u, k, m->units) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                /* ignore aliases */
                if (u->id != k)
                        continue;

                BusUnitQueueFlags flags;
                JobType job;
                if (BIT_SET(u->markers, UNIT_MARKER_NEEDS_RESTART)) {
                        flags = 0;
                        job = JOB_TRY_RESTART;
                } else if (BIT_SET(u->markers, UNIT_MARKER_NEEDS_RELOAD)) {
                        flags = BUS_UNIT_QUEUE_RELOAD_IF_POSSIBLE;
                        job = JOB_TRY_RESTART;
                } else if (BIT_SET(u->markers, UNIT_MARKER_NEEDS_STOP)) {
                        flags = 0;
                        job = JOB_STOP;
                } else if (BIT_SET(u->markers, UNIT_MARKER_NEEDS_START)) {
                        flags = 0;
                        job = JOB_START;
                } else
                        continue;

                r = mac_selinux_unit_access_check(u, message, job_type_to_access_method(job), &error);
                if (r >= 0)
                        r = bus_unit_queue_job_one(message, u,
                                                   job, JOB_FAIL, flags,
                                                   reply, &error);
                if (ERRNO_IS_NEG_RESOURCE(r))
                        return r;
                if (r < 0)
                        RET_GATHER(ret, log_unit_warning_errno(u, r, "Failed to enqueue marked job: %s",
                                                               bus_error_message(&error, r)));
        }

        if (ret < 0)
                return sd_bus_error_set_errnof(reterr_error, ret,
                                               "Failed to enqueue some jobs, see logs for details: %m");

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int list_unit_files_by_patterns(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error, char **states, char **patterns) {
        Manager *m = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_hashmap_free_ Hashmap *h = NULL;
        int r;

        assert(message);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = unit_file_get_list(m->runtime_scope, /* root_dir= */ NULL, states, patterns, &h);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(ss)");
        if (r < 0)
                return r;

        UnitFileList *item;
        HASHMAP_FOREACH(item, h) {
                r = sd_bus_message_append(reply, "(ss)", item->path, unit_file_state_to_string(item->state));
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int method_list_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return list_unit_files_by_patterns(message, userdata, reterr_error, NULL, NULL);
}

static int method_list_unit_files_by_patterns(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_strv_free_ char **states = NULL;
        _cleanup_strv_free_ char **patterns = NULL;
        int r;

        r = sd_bus_message_read_strv(message, &states);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &patterns);
        if (r < 0)
                return r;

        return list_unit_files_by_patterns(message, userdata, reterr_error, states, patterns);
}

static int method_get_unit_file_state(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        const char *name;
        UnitFileState state;
        int r;

        assert(message);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = unit_file_get_state(m->runtime_scope, NULL, name, &state);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "s", unit_file_state_to_string(state));
}

static int method_get_default_target(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_free_ char *default_target = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", reterr_error);
        if (r < 0)
                return r;

        r = unit_file_get_default(m->runtime_scope, NULL, &default_target);
        if (r == -ERFKILL)
                return sd_bus_error_set(reterr_error, BUS_ERROR_UNIT_MASKED, "Default target unit file is masked.");
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "s", default_target);
}

static int send_unit_files_changed(sd_bus *bus, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;
        int r;

        assert(bus);

        r = sd_bus_message_new_signal(bus, &message,
                                      "/org/freedesktop/systemd1",
                                      "org.freedesktop.systemd1.Manager",
                                      "UnitFilesChanged");
        if (r < 0)
                return r;

        return sd_bus_send(bus, message, NULL);
}

static void manager_unit_files_changed(Manager *m, const InstallChange *changes, size_t n_changes) {
        int r;

        assert(m);
        assert(changes || n_changes == 0);

        if (!install_changes_have_modification(changes, n_changes))
                return;

        /* See comments for this variable in manager.h */
        m->unit_file_state_outdated = true;

        r = bus_foreach_bus(m, NULL, send_unit_files_changed, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to send UnitFilesChanged signal, ignoring: %m");
}

static int install_error(
                sd_bus_error *reterr_error,
                int c,
                InstallChange *changes,
                size_t n_changes) {

        int r;

        /* Create an error reply, using the error information from changes[] if possible, and fall back to
         * generating an error from error code c. The error message only describes the first error. */

        assert(changes || n_changes == 0);

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

        FOREACH_ARRAY(i, changes, n_changes) {
                _cleanup_free_ char *err_message = NULL;
                const char *bus_error;

                if (i->type >= 0)
                        continue;

                r = install_change_dump_error(i, &err_message, &bus_error);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        return sd_bus_error_set_errnof(reterr_error, r, "File %s: %m", i->path);

                return sd_bus_error_set(reterr_error, bus_error, err_message);
        }

        return c < 0 ? c : -EINVAL;
}

static int reply_install_changes_and_free(
                Manager *m,
                sd_bus_message *message,
                int carries_install_info,
                InstallChange *changes,
                size_t n_changes,
                sd_bus_error *reterr_error) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        bool bad = false, good = false;
        int r;

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        if (carries_install_info >= 0) {
                r = sd_bus_message_append(reply, "b", carries_install_info);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_open_container(reply, 'a', "(sss)");
        if (r < 0)
                return r;

        FOREACH_ARRAY(i, changes, n_changes) {
                if (i->type < 0) {
                        bad = true;
                        continue;
                }

                r = sd_bus_message_append(
                                reply, "(sss)",
                                install_change_type_to_string(i->type),
                                i->path,
                                i->source);
                if (r < 0)
                        return r;

                good = true;
        }

        /* If there was a failed change, and no successful change, then return the first failure as proper
         * method call error. */
        if (bad && !good)
                return install_error(reterr_error, 0, TAKE_PTR(changes), n_changes);

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int method_enable_unit_files_generic(
                sd_bus_message *message,
                Manager *m,
                int (*call)(RuntimeScope scope, UnitFileFlags flags, const char *root_dir, char * const *files, InstallChange **changes, size_t *n_changes),
                bool carries_install_info,
                sd_bus_error *reterr_error) {

        _cleanup_strv_free_ char **l = NULL;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileFlags flags;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        if (sd_bus_message_is_method_call(message, NULL, "EnableUnitFilesWithFlags")) {
                uint64_t raw_flags;

                r = sd_bus_message_read(message, "t", &raw_flags);
                if (r < 0)
                        return r;
                if ((raw_flags & ~_UNIT_FILE_FLAGS_MASK_PUBLIC) != 0)
                        return -EINVAL;
                flags = raw_flags;
        } else {
                int runtime, force;

                r = sd_bus_message_read(message, "bb", &runtime, &force);
                if (r < 0)
                        return r;
                flags = unit_file_bools_to_flags(runtime, force);
        }

        r = bus_verify_manage_unit_files_async(m, message, reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = call(m->runtime_scope, flags, NULL, l, &changes, &n_changes);
        manager_unit_files_changed(m, changes, n_changes);
        if (r < 0)
                return install_error(reterr_error, r, changes, n_changes);

        return reply_install_changes_and_free(m, message, carries_install_info ? r : -1, changes, n_changes, reterr_error);
}

static int method_enable_unit_files_with_flags(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_enable_unit_files_generic(message, userdata, unit_file_enable, /* carries_install_info= */ true, reterr_error);
}

static int method_enable_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_enable_unit_files_generic(message, userdata, unit_file_enable, /* carries_install_info= */ true, reterr_error);
}

static int method_reenable_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_enable_unit_files_generic(message, userdata, unit_file_reenable, /* carries_install_info= */ true, reterr_error);
}

static int method_link_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_enable_unit_files_generic(message, userdata, unit_file_link, /* carries_install_info= */ false, reterr_error);
}

static int unit_file_preset_without_mode(RuntimeScope scope, UnitFileFlags flags, const char *root_dir, char * const *files, InstallChange **changes, size_t *n_changes) {
        return unit_file_preset(scope, flags, root_dir, files, UNIT_FILE_PRESET_FULL, changes, n_changes);
}

static int method_preset_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_enable_unit_files_generic(message, userdata, unit_file_preset_without_mode, /* carries_install_info= */ true, reterr_error);
}

static int method_mask_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_enable_unit_files_generic(message, userdata, unit_file_mask, /* carries_install_info= */ false, reterr_error);
}

static int method_preset_unit_files_with_mode(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {

        _cleanup_strv_free_ char **l = NULL;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        Manager *m = ASSERT_PTR(userdata);
        UnitFilePresetMode preset_mode;
        int runtime, force, r;
        UnitFileFlags flags;
        const char *mode;

        assert(message);

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "sbb", &mode, &runtime, &force);
        if (r < 0)
                return r;

        flags = unit_file_bools_to_flags(runtime, force);

        if (isempty(mode))
                preset_mode = UNIT_FILE_PRESET_FULL;
        else {
                preset_mode = unit_file_preset_mode_from_string(mode);
                if (preset_mode < 0)
                        return -EINVAL;
        }

        r = bus_verify_manage_unit_files_async(m, message, reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_file_preset(m->runtime_scope, flags, NULL, l, preset_mode, &changes, &n_changes);
        manager_unit_files_changed(m, changes, n_changes);
        if (r < 0)
                return install_error(reterr_error, r, changes, n_changes);

        return reply_install_changes_and_free(m, message, r, changes, n_changes, reterr_error);
}

static int method_disable_unit_files_generic(
                sd_bus_message *message,
                Manager *m,
                int (*call)(RuntimeScope scope, UnitFileFlags flags, const char *root_dir, char * const *files, InstallChange **changes, size_t *n_changes),
                bool carries_install_info,
                sd_bus_error *reterr_error) {

        _cleanup_strv_free_ char **l = NULL;
        InstallChange *changes = NULL;
        UnitFileFlags flags;
        size_t n_changes = 0;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        if (sd_bus_message_is_method_call(message, NULL, "DisableUnitFilesWithFlags") ||
            sd_bus_message_is_method_call(message, NULL, "DisableUnitFilesWithFlagsAndInstallInfo")) {
                uint64_t raw_flags;

                r = sd_bus_message_read(message, "t", &raw_flags);
                if (r < 0)
                        return r;
                if ((raw_flags & ~_UNIT_FILE_FLAGS_MASK_PUBLIC) != 0 ||
                                FLAGS_SET(raw_flags, UNIT_FILE_FORCE))
                        return -EINVAL;
                flags = raw_flags;
        } else {
                int runtime;

                r = sd_bus_message_read(message, "b", &runtime);
                if (r < 0)
                        return r;
                flags = unit_file_bools_to_flags(runtime, false);
        }

        r = bus_verify_manage_unit_files_async(m, message, reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = call(m->runtime_scope, flags, NULL, l, &changes, &n_changes);
        manager_unit_files_changed(m, changes, n_changes);
        if (r < 0)
                return install_error(reterr_error, r, changes, n_changes);

        return reply_install_changes_and_free(m, message, carries_install_info ? r : -1, changes, n_changes, reterr_error);
}

static int method_disable_unit_files_with_flags(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_disable_unit_files_generic(message, userdata, unit_file_disable, /* carries_install_info= */ false, reterr_error);
}

static int method_disable_unit_files_with_flags_and_install_info(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_disable_unit_files_generic(message, userdata, unit_file_disable, /* carries_install_info= */ true, reterr_error);
}

static int method_disable_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_disable_unit_files_generic(message, userdata, unit_file_disable, /* carries_install_info= */ false, reterr_error);
}

static int method_unmask_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_disable_unit_files_generic(message, userdata, unit_file_unmask, /* carries_install_info= */ false, reterr_error);
}

static int method_revert_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_strv_free_ char **l = NULL;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        r = bus_verify_manage_unit_files_async(m, message, reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_file_revert(m->runtime_scope, NULL, l, &changes, &n_changes);
        manager_unit_files_changed(m, changes, n_changes);
        if (r < 0)
                return install_error(reterr_error, r, changes, n_changes);

        return reply_install_changes_and_free(m, message, -1, changes, n_changes, reterr_error);
}

static int method_set_default_target(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        Manager *m = ASSERT_PTR(userdata);
        const char *name;
        int force, r;

        assert(message);

        r = mac_selinux_access_check(message, "enable", reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "sb", &name, &force);
        if (r < 0)
                return r;

        r = bus_verify_manage_unit_files_async(m, message, reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_file_set_default(m->runtime_scope, force ? UNIT_FILE_FORCE : 0, NULL, name, &changes, &n_changes);
        manager_unit_files_changed(m, changes, n_changes);
        if (r < 0)
                return install_error(reterr_error, r, changes, n_changes);

        return reply_install_changes_and_free(m, message, -1, changes, n_changes, reterr_error);
}

static int method_preset_all_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        Manager *m = ASSERT_PTR(userdata);
        UnitFilePresetMode preset_mode;
        const char *mode;
        UnitFileFlags flags;
        int force, runtime, r;

        assert(message);

        r = mac_selinux_access_check(message, "enable", reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "sbb", &mode, &runtime, &force);
        if (r < 0)
                return r;

        flags = unit_file_bools_to_flags(runtime, force);

        if (isempty(mode))
                preset_mode = UNIT_FILE_PRESET_FULL;
        else {
                preset_mode = unit_file_preset_mode_from_string(mode);
                if (preset_mode < 0)
                        return -EINVAL;
        }

        r = bus_verify_manage_unit_files_async(m, message, reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_file_preset_all(m->runtime_scope, flags, NULL, preset_mode, &changes, &n_changes);
        manager_unit_files_changed(m, changes, n_changes);
        if (r < 0)
                return install_error(reterr_error, r, changes, n_changes);

        return reply_install_changes_and_free(m, message, -1, changes, n_changes, reterr_error);
}

static int method_add_dependency_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = ASSERT_PTR(userdata);
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        int runtime, force, r;
        char *target, *type;
        UnitDependency dep;
        UnitFileFlags flags;

        assert(message);

        r = bus_verify_manage_unit_files_async(m, message, reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "ssbb", &target, &type, &runtime, &force);
        if (r < 0)
                return r;

        flags = unit_file_bools_to_flags(runtime, force);

        dep = unit_dependency_from_string(type);
        if (dep < 0 || !IN_SET(dep, UNIT_WANTS, UNIT_REQUIRES))
                return -EINVAL;

        r = unit_file_add_dependency(m->runtime_scope, flags, NULL, l, target, dep, &changes, &n_changes);
        manager_unit_files_changed(m, changes, n_changes);
        if (r < 0)
                return install_error(reterr_error, r, changes, n_changes);

        return reply_install_changes_and_free(m, message, -1, changes, n_changes, reterr_error);
}

static int method_get_unit_file_links(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        InstallChange *changes = NULL;
        size_t n_changes = 0, i;
        const char *name;
        int runtime, r;

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

        r = sd_bus_message_read(message, "sb", &name, &runtime);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "s");
        if (r < 0)
                return r;

        r = unit_file_disable(m->runtime_scope,
                              UNIT_FILE_DRY_RUN | (runtime ? UNIT_FILE_RUNTIME : 0),
                              NULL, STRV_MAKE(name), &changes, &n_changes);
        if (r < 0)
                return log_error_errno(r, "Failed to get file links for %s: %m", name);

        for (i = 0; i < n_changes; i++)
                if (changes[i].type == INSTALL_CHANGE_UNLINK) {
                        r = sd_bus_message_append(reply, "s", changes[i].path);
                        if (r < 0)
                                return r;
                }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int method_get_job_waiting(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        uint32_t id;
        Job *j;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "u", &id);
        if (r < 0)
                return r;

        j = manager_get_job(m, id);
        if (!j)
                return sd_bus_error_setf(reterr_error, BUS_ERROR_NO_SUCH_JOB, "Job %u does not exist.", (unsigned) id);

        return bus_job_method_get_waiting_jobs(message, j, reterr_error);
}

static int method_abandon_scope(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        const char *name;
        Unit *u;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = bus_get_unit_by_name(m, message, name, &u, reterr_error);
        if (r < 0)
                return r;

        if (u->type != UNIT_SCOPE)
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Unit '%s' is not a scope unit, refusing.", name);

        return bus_scope_method_abandon(message, u, reterr_error);
}

static int method_set_show_status(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        ShowStatus mode = _SHOW_STATUS_INVALID;
        const char *t;
        int r;

        assert(message);

        r = mac_selinux_access_check(message, "reload", reterr_error);
        if (r < 0)
                return r;

        r = bus_verify_set_environment_async(m, message, reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = sd_bus_message_read(message, "s", &t);
        if (r < 0)
                return r;

        if (!isempty(t)) {
                mode = show_status_from_string(t);
                if (mode < 0)
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Invalid show status '%s'", t);
        }

        manager_override_show_status(m, mode, "bus");

        return sd_bus_reply_method_return(message, NULL);
}

static int method_dump_unit_descriptor_store(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return method_generic_unit_operation(message, userdata, reterr_error, UNIT_SERVICE, bus_service_method_dump_file_descriptor_store, GENERIC_UNIT_VALIDATE_LOADED);
}

static int method_start_aux_scope(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return sd_bus_error_set(reterr_error, SD_BUS_ERROR_NOT_SUPPORTED, "StartAuxiliaryScope() method has been removed.");
}

const sd_bus_vtable bus_manager_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("Version", "s", property_get_version, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Features", "s", property_get_features, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Virtualization", "s", property_get_virtualization, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ConfidentialVirtualization", "s", property_get_confidential_virtualization, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Architecture", "s", property_get_architecture, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Tainted", "s", property_get_tainted, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("FirmwareTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_FIRMWARE]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("LoaderTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_LOADER]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("KernelTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_KERNEL]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("InitRDTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_INITRD]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("UserspaceTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_USERSPACE]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("FinishTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_FINISH]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("ShutdownStartTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_SHUTDOWN_START]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("SecurityStartTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_SECURITY_START]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("SecurityFinishTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_SECURITY_FINISH]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("GeneratorsStartTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_GENERATORS_START]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("GeneratorsFinishTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_GENERATORS_FINISH]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("UnitsLoadStartTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_UNITS_LOAD_START]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("UnitsLoadFinishTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_UNITS_LOAD_FINISH]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("UnitsLoadTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_UNITS_LOAD]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("InitRDSecurityStartTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_INITRD_SECURITY_START]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("InitRDSecurityFinishTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_INITRD_SECURITY_FINISH]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("InitRDGeneratorsStartTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_INITRD_GENERATORS_START]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("InitRDGeneratorsFinishTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_INITRD_GENERATORS_FINISH]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("InitRDUnitsLoadStartTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_START]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("InitRDUnitsLoadFinishTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_FINISH]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_WRITABLE_PROPERTY("LogLevel", "s", bus_property_get_log_level, property_set_log_level, 0, 0),
        SD_BUS_WRITABLE_PROPERTY("LogTarget", "s", bus_property_get_log_target, property_set_log_target, 0, 0),
        SD_BUS_PROPERTY("NNames", "u", property_get_hashmap_size, offsetof(Manager, units), 0),
        SD_BUS_PROPERTY("NFailedUnits", "u", property_get_set_size, offsetof(Manager, failed_units), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("NJobs", "u", property_get_hashmap_size, offsetof(Manager, jobs), 0),
        SD_BUS_PROPERTY("NInstalledJobs", "u", bus_property_get_unsigned, offsetof(Manager, n_installed_jobs), 0),
        SD_BUS_PROPERTY("NFailedJobs", "u", bus_property_get_unsigned, offsetof(Manager, n_failed_jobs), 0),
        SD_BUS_PROPERTY("TransactionsWithOrderingCycle", "at", property_get_transactions_with_cycle, 0, 0),
        SD_BUS_PROPERTY("Progress", "d", property_get_progress, 0, 0),
        SD_BUS_PROPERTY("Environment", "as", property_get_environment, 0, 0),
        SD_BUS_PROPERTY("ConfirmSpawn", "b", bus_property_get_bool, offsetof(Manager, confirm_spawn), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ShowStatus", "b", property_get_show_status, 0, 0),
        SD_BUS_PROPERTY("UnitPath", "as", NULL, offsetof(Manager, lookup_paths.search_path), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultStandardOutput", "s", bus_property_get_exec_output, offsetof(Manager, defaults.std_output), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultStandardError", "s", bus_property_get_exec_output, offsetof(Manager, defaults.std_error), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WatchdogDevice", "s", property_get_watchdog_device, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WatchdogLastPingTimestamp", "t", property_get_watchdog_last_ping_realtime, 0, 0),
        SD_BUS_PROPERTY("WatchdogLastPingTimestampMonotonic", "t", property_get_watchdog_last_ping_monotonic, 0, 0),
        SD_BUS_WRITABLE_PROPERTY("RuntimeWatchdogUSec", "t", property_get_runtime_watchdog, property_set_runtime_watchdog, 0, 0),
        SD_BUS_WRITABLE_PROPERTY("RuntimeWatchdogPreUSec", "t", property_get_pretimeout_watchdog, property_set_pretimeout_watchdog, 0, 0),
        SD_BUS_WRITABLE_PROPERTY("RuntimeWatchdogPreGovernor", "s", property_get_pretimeout_watchdog_governor, property_set_pretimeout_watchdog_governor, 0, 0),
        SD_BUS_WRITABLE_PROPERTY("RebootWatchdogUSec", "t", property_get_reboot_watchdog, property_set_reboot_watchdog, 0, 0),
        /* The following item is an obsolete alias */
        SD_BUS_WRITABLE_PROPERTY("ShutdownWatchdogUSec", "t", property_get_reboot_watchdog, property_set_reboot_watchdog, 0, SD_BUS_VTABLE_HIDDEN),
        SD_BUS_WRITABLE_PROPERTY("KExecWatchdogUSec", "t", property_get_kexec_watchdog, property_set_kexec_watchdog, 0, 0),
        SD_BUS_WRITABLE_PROPERTY("ServiceWatchdogs", "b", bus_property_get_bool, bus_property_set_bool, offsetof(Manager, service_watchdogs), 0),
        SD_BUS_PROPERTY("ControlGroup", "s", NULL, offsetof(Manager, cgroup_root), 0),
        SD_BUS_PROPERTY("SystemState", "s", property_get_system_state, 0, 0),
        SD_BUS_PROPERTY("ExitCode", "y", NULL, offsetof(Manager, return_value), 0),
        SD_BUS_PROPERTY("DefaultTimerAccuracyUSec", "t", bus_property_get_usec, offsetof(Manager, defaults.timer_accuracy_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultTimeoutStartUSec", "t", bus_property_get_usec, offsetof(Manager, defaults.timeout_start_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultTimeoutStopUSec", "t", bus_property_get_usec, offsetof(Manager, defaults.timeout_stop_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultTimeoutAbortUSec", "t", property_get_default_timeout_abort_usec, 0, 0),
        SD_BUS_PROPERTY("DefaultDeviceTimeoutUSec", "t", bus_property_get_usec, offsetof(Manager, defaults.device_timeout_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultRestartUSec", "t", bus_property_get_usec, offsetof(Manager, defaults.restart_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultStartLimitIntervalUSec", "t", bus_property_get_usec, offsetof(Manager, defaults.start_limit.interval), SD_BUS_VTABLE_PROPERTY_CONST),
        /* The following two items are obsolete alias */
        SD_BUS_PROPERTY("DefaultStartLimitIntervalSec", "t", bus_property_get_usec, offsetof(Manager, defaults.start_limit.interval), SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("DefaultStartLimitInterval", "t", bus_property_get_usec, offsetof(Manager, defaults.start_limit.interval), SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("DefaultStartLimitBurst", "u", bus_property_get_unsigned, offsetof(Manager, defaults.start_limit.burst), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultIOAccounting", "b", bus_property_get_bool, offsetof(Manager, defaults.io_accounting), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultIPAccounting", "b", bus_property_get_bool, offsetof(Manager, defaults.ip_accounting), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultMemoryAccounting", "b", bus_property_get_bool, offsetof(Manager, defaults.memory_accounting), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultTasksAccounting", "b", bus_property_get_bool, offsetof(Manager, defaults.tasks_accounting), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitCPU", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_CPU]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitCPUSoft", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_CPU]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitFSIZE", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_FSIZE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitFSIZESoft", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_FSIZE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitDATA", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_DATA]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitDATASoft", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_DATA]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitSTACK", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_STACK]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitSTACKSoft", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_STACK]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitCORE", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_CORE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitCORESoft", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_CORE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitRSS", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_RSS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitRSSSoft", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_RSS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitNOFILE", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_NOFILE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitNOFILESoft", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_NOFILE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitAS", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_AS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitASSoft", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_AS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitNPROC", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_NPROC]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitNPROCSoft", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_NPROC]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitMEMLOCK", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_MEMLOCK]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitMEMLOCKSoft", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_MEMLOCK]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitLOCKS", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_LOCKS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitLOCKSSoft", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_LOCKS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitSIGPENDING", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_SIGPENDING]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitSIGPENDINGSoft", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_SIGPENDING]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitMSGQUEUE", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_MSGQUEUE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitMSGQUEUESoft", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_MSGQUEUE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitNICE", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_NICE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitNICESoft", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_NICE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitRTPRIO", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_RTPRIO]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitRTPRIOSoft", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_RTPRIO]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitRTTIME", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_RTTIME]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitRTTIMESoft", "t", bus_property_get_rlimit, offsetof(Manager, defaults.rlimit[RLIMIT_RTTIME]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultTasksMax", "t", bus_property_get_tasks_max, offsetof(Manager, defaults.tasks_max), 0),
        SD_BUS_PROPERTY("DefaultMemoryPressureThresholdUSec", "t", bus_property_get_usec, offsetof(Manager, defaults.memory_pressure_threshold_usec), 0),
        SD_BUS_PROPERTY("DefaultMemoryPressureWatch", "s", bus_property_get_cgroup_pressure_watch, offsetof(Manager, defaults.memory_pressure_watch), 0),
        SD_BUS_PROPERTY("TimerSlackNSec", "t", property_get_timer_slack_nsec, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultOOMPolicy", "s", bus_property_get_oom_policy, offsetof(Manager, defaults.oom_policy), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultOOMScoreAdjust", "i", property_get_oom_score_adjust, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultRestrictSUIDSGID", "b", bus_property_get_bool, offsetof(Manager, defaults.restrict_suid_sgid), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CtrlAltDelBurstAction", "s", bus_property_get_emergency_action, offsetof(Manager, cad_burst_action), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SoftRebootsCount", "u", bus_property_get_unsigned, offsetof(Manager, soft_reboots_count), SD_BUS_VTABLE_PROPERTY_CONST),

        /* deprecated cgroup v1 property */
        SD_BUS_PROPERTY("DefaultBlockIOAccounting", "b", bus_property_get_bool_false, 0, SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_DEPRECATED|SD_BUS_VTABLE_HIDDEN),
        /* see comment in bus_cgroup_vtable */
        SD_BUS_PROPERTY("DefaultCPUAccounting", "b", bus_property_get_bool_true, 0, SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_DEPRECATED|SD_BUS_VTABLE_HIDDEN),

        SD_BUS_METHOD_WITH_ARGS("GetUnit",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("o", unit),
                                method_get_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetUnitByPID",
                                SD_BUS_ARGS("u", pid),
                                SD_BUS_RESULT("o", unit),
                                method_get_unit_by_pid,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetUnitByInvocationID",
                                SD_BUS_ARGS("ay", invocation_id),
                                SD_BUS_RESULT("o", unit),
                                method_get_unit_by_invocation_id,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetUnitByControlGroup",
                                SD_BUS_ARGS("s", cgroup),
                                SD_BUS_RESULT("o", unit),
                                method_get_unit_by_control_group,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetUnitByPIDFD",
                                SD_BUS_ARGS("h", pidfd),
                                SD_BUS_RESULT("o", unit, "s", unit_id, "ay", invocation_id),
                                method_get_unit_by_pidfd,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("LoadUnit",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("o", unit),
                                method_load_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("StartUnit",
                                SD_BUS_ARGS("s", name, "s", mode),
                                SD_BUS_RESULT("o", job),
                                method_start_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("StartUnitWithFlags",
                                SD_BUS_ARGS("s", name, "s", mode, "t", flags),
                                SD_BUS_RESULT("o", job),
                                method_start_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("StartUnitReplace",
                                SD_BUS_ARGS("s", old_unit, "s", new_unit, "s", mode),
                                SD_BUS_RESULT("o", job),
                                method_start_unit_replace,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("StopUnit",
                                SD_BUS_ARGS("s", name, "s", mode),
                                SD_BUS_RESULT("o", job),
                                method_stop_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ReloadUnit",
                                SD_BUS_ARGS("s", name, "s", mode),
                                SD_BUS_RESULT("o", job),
                                method_reload_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("RestartUnit",
                                SD_BUS_ARGS("s", name, "s", mode),
                                SD_BUS_RESULT("o", job),
                                method_restart_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("TryRestartUnit",
                                SD_BUS_ARGS("s", name, "s", mode),
                                SD_BUS_RESULT("o", job),
                                method_try_restart_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ReloadOrRestartUnit",
                                SD_BUS_ARGS("s", name, "s", mode),
                                SD_BUS_RESULT("o", job),
                                method_reload_or_restart_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ReloadOrTryRestartUnit",
                                SD_BUS_ARGS("s", name, "s", mode),
                                SD_BUS_RESULT("o", job),
                                method_reload_or_try_restart_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("EnqueueUnitJob",
                                SD_BUS_ARGS("s", name, "s", job_type, "s", job_mode),
                                SD_BUS_RESULT("u", job_id, "o", job_path, "s", unit_id, "o", unit_path, "s", job_type, "a(uosos)", affected_jobs),
                                method_enqueue_unit_job,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("KillUnit",
                                SD_BUS_ARGS("s", name, "s", whom, "i", signal),
                                SD_BUS_NO_RESULT,
                                method_kill_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("KillUnitSubgroup",
                                SD_BUS_ARGS("s", name, "s", whom, "s", subgroup, "i", signal),
                                SD_BUS_NO_RESULT,
                                method_kill_unit_subgroup,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("QueueSignalUnit",
                                SD_BUS_ARGS("s", name, "s", whom, "i", signal, "i", value),
                                SD_BUS_NO_RESULT,
                                method_kill_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CleanUnit",
                                SD_BUS_ARGS("s", name, "as", mask),
                                SD_BUS_NO_RESULT,
                                method_clean_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("FreezeUnit",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_NO_RESULT,
                                method_freeze_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ThawUnit",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_NO_RESULT,
                                method_thaw_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ResetFailedUnit",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_NO_RESULT,
                                method_reset_failed_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetUnitProperties",
                                SD_BUS_ARGS("s", name, "b", runtime, "a(sv)", properties),
                                SD_BUS_NO_RESULT,
                                method_set_unit_properties,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("BindMountUnit",
                                SD_BUS_ARGS("s", name, "s", source, "s", destination, "b", read_only, "b", mkdir),
                                SD_BUS_NO_RESULT,
                                method_bind_mount_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("MountImageUnit",
                                SD_BUS_ARGS("s", name, "s", source, "s", destination, "b", read_only, "b", mkdir, "a(ss)", options),
                                SD_BUS_NO_RESULT,
                                method_mount_image_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("RefUnit",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_NO_RESULT,
                                method_ref_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("UnrefUnit",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_NO_RESULT,
                                method_unref_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("StartTransientUnit",
                                SD_BUS_ARGS("s", name, "s", mode, "a(sv)", properties, "a(sa(sv))", aux),
                                SD_BUS_RESULT("o", job),
                                method_start_transient_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetUnitProcesses",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("a(sus)", processes),
                                method_get_unit_processes,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("AttachProcessesToUnit",
                                SD_BUS_ARGS("s", unit_name, "s", subcgroup, "au", pids),
                                SD_BUS_NO_RESULT,
                                method_attach_processes_to_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("RemoveSubgroupFromUnit",
                                SD_BUS_ARGS("s", unit_name, "s", subcgroup, "t", flags),
                                SD_BUS_NO_RESULT,
                                method_remove_subgroup_from_unit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("AbandonScope",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_NO_RESULT,
                                method_abandon_scope,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetJob",
                                SD_BUS_ARGS("u", id),
                                SD_BUS_RESULT("o", job),
                                method_get_job,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetJobAfter",
                                SD_BUS_ARGS("u", id),
                                SD_BUS_RESULT("a(usssoo)", jobs),
                                method_get_job_waiting,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetJobBefore",
                                SD_BUS_ARGS("u", id),
                                SD_BUS_RESULT("a(usssoo)", jobs),
                                method_get_job_waiting,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CancelJob",
                                SD_BUS_ARGS("u", id),
                                SD_BUS_NO_RESULT,
                                method_cancel_job,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ClearJobs",
                      NULL,
                      NULL,
                      method_clear_jobs,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResetFailed",
                      NULL,
                      NULL,
                      method_reset_failed,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetShowStatus",
                                SD_BUS_ARGS("s", mode),
                                SD_BUS_NO_RESULT,
                                method_set_show_status,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ListUnits",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(ssssssouso)", units),
                                method_list_units,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ListUnitsFiltered",
                                SD_BUS_ARGS("as", states),
                                SD_BUS_RESULT("a(ssssssouso)", units),
                                method_list_units_filtered,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ListUnitsByPatterns",
                                SD_BUS_ARGS("as", states, "as", patterns),
                                SD_BUS_RESULT("a(ssssssouso)", units),
                                method_list_units_by_patterns,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ListUnitsByNames",
                                SD_BUS_ARGS("as", names),
                                SD_BUS_RESULT("a(ssssssouso)", units),
                                method_list_units_by_names,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ListJobs",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(usssoo)", jobs),
                                method_list_jobs,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Subscribe",
                      NULL,
                      NULL,
                      method_subscribe,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Unsubscribe",
                      NULL,
                      NULL,
                      method_unsubscribe,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Dump",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", output),
                                method_dump,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("DumpUnitsMatchingPatterns",
                                SD_BUS_ARGS("as", patterns),
                                SD_BUS_RESULT("s", output),
                                method_dump_units_matching_patterns,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("DumpByFileDescriptor",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("h", fd),
                                method_dump_by_fd,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("DumpUnitsMatchingPatternsByFileDescriptor",
                                SD_BUS_ARGS("as", patterns),
                                SD_BUS_RESULT("h", fd),
                                method_dump_units_matching_patterns_by_fd,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CreateSnapshot",
                                SD_BUS_ARGS("s", name, "b", cleanup),
                                SD_BUS_RESULT("o", unit),
                                method_refuse_snapshot,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_METHOD_WITH_ARGS("RemoveSnapshot",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_NO_RESULT,
                                method_refuse_snapshot,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_METHOD("Reload",
                      NULL,
                      NULL,
                      method_reload,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Reexecute",
                      NULL,
                      NULL,
                      method_reexecute,
                      SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_METHOD_NO_REPLY),
        SD_BUS_METHOD("Exit",
                      NULL,
                      NULL,
                      method_exit,
                      0),
        SD_BUS_METHOD("Reboot",
                      NULL,
                      NULL,
                      method_reboot,
                      SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
        SD_BUS_METHOD_WITH_ARGS("SoftReboot",
                                SD_BUS_ARGS("s", new_root),
                                SD_BUS_NO_RESULT,
                                method_soft_reboot,
                                SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
        SD_BUS_METHOD("PowerOff",
                      NULL,
                      NULL,
                      method_poweroff,
                      SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
        SD_BUS_METHOD("Halt",
                      NULL,
                      NULL,
                      method_halt,
                      SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
        SD_BUS_METHOD("KExec",
                      NULL,
                      NULL,
                      method_kexec,
                      SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
        SD_BUS_METHOD_WITH_ARGS("SwitchRoot",
                                SD_BUS_ARGS("s", new_root, "s", init),
                                SD_BUS_NO_RESULT,
                                method_switch_root,
                                SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
        SD_BUS_METHOD_WITH_ARGS("SetEnvironment",
                                SD_BUS_ARGS("as", assignments),
                                SD_BUS_NO_RESULT,
                                method_set_environment,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("UnsetEnvironment",
                                SD_BUS_ARGS("as", names),
                                SD_BUS_NO_RESULT,
                                method_unset_environment,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("UnsetAndSetEnvironment",
                                SD_BUS_ARGS("as", names, "as", assignments),
                                SD_BUS_NO_RESULT,
                                method_unset_and_set_environment,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("EnqueueMarkedJobs",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("ao", jobs),
                                method_enqueue_marked_jobs,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ListUnitFiles",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(ss)", unit_files),
                                method_list_unit_files,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ListUnitFilesByPatterns",
                                SD_BUS_ARGS("as", states, "as", patterns),
                                SD_BUS_RESULT("a(ss)", unit_files),
                                method_list_unit_files_by_patterns,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetUnitFileState",
                                SD_BUS_ARGS("s", file),
                                SD_BUS_RESULT("s", state),
                                method_get_unit_file_state,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("EnableUnitFiles",
                                SD_BUS_ARGS("as", files, "b", runtime, "b", force),
                                SD_BUS_RESULT("b", carries_install_info, "a(sss)", changes),
                                method_enable_unit_files,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("DisableUnitFiles",
                                SD_BUS_ARGS("as", files, "b", runtime),
                                SD_BUS_RESULT("a(sss)", changes),
                                method_disable_unit_files,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("EnableUnitFilesWithFlags",
                                SD_BUS_ARGS("as", files, "t", flags),
                                SD_BUS_RESULT("b", carries_install_info, "a(sss)", changes),
                                method_enable_unit_files_with_flags,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("DisableUnitFilesWithFlags",
                                SD_BUS_ARGS("as", files, "t", flags),
                                SD_BUS_RESULT("a(sss)", changes),
                                method_disable_unit_files_with_flags,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("DisableUnitFilesWithFlagsAndInstallInfo",
                                SD_BUS_ARGS("as", files, "t", flags),
                                SD_BUS_RESULT("b", carries_install_info, "a(sss)", changes),
                                method_disable_unit_files_with_flags_and_install_info,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ReenableUnitFiles",
                                SD_BUS_ARGS("as", files, "b", runtime, "b", force),
                                SD_BUS_RESULT("b", carries_install_info, "a(sss)", changes),
                                method_reenable_unit_files,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("LinkUnitFiles",
                                SD_BUS_ARGS("as", files, "b", runtime, "b", force),
                                SD_BUS_RESULT("a(sss)", changes),
                                method_link_unit_files,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("PresetUnitFiles",
                                SD_BUS_ARGS("as", files, "b", runtime, "b", force),
                                SD_BUS_RESULT("b", carries_install_info, "a(sss)", changes),
                                method_preset_unit_files,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("PresetUnitFilesWithMode",
                                SD_BUS_ARGS("as", files, "s", mode, "b", runtime, "b", force),
                                SD_BUS_RESULT("b", carries_install_info, "a(sss)", changes),
                                method_preset_unit_files_with_mode,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("MaskUnitFiles",
                                SD_BUS_ARGS("as", files, "b", runtime, "b", force),
                                SD_BUS_RESULT("a(sss)", changes),
                                method_mask_unit_files,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("UnmaskUnitFiles",
                                SD_BUS_ARGS("as", files, "b", runtime),
                                SD_BUS_RESULT("a(sss)", changes),
                                method_unmask_unit_files,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("RevertUnitFiles",
                                SD_BUS_ARGS("as", files),
                                SD_BUS_RESULT("a(sss)", changes),
                                method_revert_unit_files,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetDefaultTarget",
                                SD_BUS_ARGS("s", name, "b", force),
                                SD_BUS_RESULT("a(sss)", changes),
                                method_set_default_target,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetDefaultTarget",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", name),
                                method_get_default_target,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("PresetAllUnitFiles",
                                SD_BUS_ARGS("s", mode, "b", runtime, "b", force),
                                SD_BUS_RESULT("a(sss)", changes),
                                method_preset_all_unit_files,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("AddDependencyUnitFiles",
                                SD_BUS_ARGS("as", files, "s", target, "s", type, "b", runtime, "b", force),
                                SD_BUS_RESULT("a(sss)", changes),
                                method_add_dependency_unit_files,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetUnitFileLinks",
                                SD_BUS_ARGS("s", name, "b", runtime),
                                SD_BUS_RESULT("as", links),
                                method_get_unit_file_links,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetExitCode",
                                SD_BUS_ARGS("y", number),
                                SD_BUS_NO_RESULT,
                                method_set_exit_code,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("LookupDynamicUserByName",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("u", uid),
                                method_lookup_dynamic_user_by_name,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("LookupDynamicUserByUID",
                                SD_BUS_ARGS("u", uid),
                                SD_BUS_RESULT("s", name),
                                method_lookup_dynamic_user_by_uid,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetDynamicUsers",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(us)", users),
                                method_get_dynamic_users,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("DumpUnitFileDescriptorStore",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("a(suuutuusu)", entries),
                                method_dump_unit_descriptor_store,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("StartAuxiliaryScope",
                                SD_BUS_ARGS("s", name, "ah", pidfds, "t", flags, "a(sv)", properties),
                                SD_BUS_RESULT("o", job),
                                method_start_aux_scope,
                                SD_BUS_VTABLE_DEPRECATED|SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_HIDDEN),

        SD_BUS_SIGNAL_WITH_ARGS("UnitNew",
                                SD_BUS_ARGS("s", id, "o", unit),
                                0),
        SD_BUS_SIGNAL_WITH_ARGS("UnitRemoved",
                                SD_BUS_ARGS("s", id, "o", unit),
                                0),
        SD_BUS_SIGNAL_WITH_ARGS("JobNew",
                                SD_BUS_ARGS("u", id, "o", job, "s", unit),
                                0),
        SD_BUS_SIGNAL_WITH_ARGS("JobRemoved",
                                SD_BUS_ARGS("u", id, "o", job, "s", unit, "s", result),
                                0),
        SD_BUS_SIGNAL_WITH_ARGS("StartupFinished",
                                SD_BUS_ARGS("t", firmware, "t", loader, "t", kernel, "t", initrd, "t", userspace, "t", total),
                                0),
        SD_BUS_SIGNAL("UnitFilesChanged", NULL, 0),
        SD_BUS_SIGNAL_WITH_ARGS("Reloading",
                                SD_BUS_ARGS("b", active),
                                0),

        SD_BUS_VTABLE_END
};

const sd_bus_vtable bus_manager_log_control_vtable[] = {
        SD_BUS_VTABLE_START(0),

        /* We define a private version of this interface here, since we want slightly different
         * implementations for the setters. We'll still use the generic getters however, and we share the
         * setters with the implementations for the Manager interface above (which pre-dates the generic
         * service API interface). */

        SD_BUS_WRITABLE_PROPERTY("LogLevel", "s", bus_property_get_log_level, property_set_log_level, 0, 0),
        SD_BUS_WRITABLE_PROPERTY("LogTarget", "s", bus_property_get_log_target, property_set_log_target, 0, 0),
        SD_BUS_PROPERTY("SyslogIdentifier", "s", bus_property_get_syslog_identifier, 0, 0),

        SD_BUS_VTABLE_END,
};

static int send_finished(sd_bus *bus, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;
        usec_t *times = ASSERT_PTR(userdata);
        int r;

        assert(bus);

        r = sd_bus_message_new_signal(bus,
                                      &message,
                                      "/org/freedesktop/systemd1",
                                      "org.freedesktop.systemd1.Manager",
                                      "StartupFinished");
        if (r < 0)
                return r;

        r = sd_bus_message_append(message, "tttttt", times[0], times[1], times[2], times[3], times[4], times[5]);
        if (r < 0)
                return r;

        return sd_bus_send(bus, message, NULL);
}

void bus_manager_send_finished(
                Manager *m,
                usec_t firmware_usec,
                usec_t loader_usec,
                usec_t kernel_usec,
                usec_t initrd_usec,
                usec_t userspace_usec,
                usec_t total_usec) {

        int r;

        assert(m);

        r = bus_foreach_bus(
                        m,
                        NULL,
                        send_finished,
                        (usec_t[6]) {
                                firmware_usec,
                                loader_usec,
                                kernel_usec,
                                initrd_usec,
                                userspace_usec,
                                total_usec
                        });
        if (r < 0)
                log_debug_errno(r, "Failed to send finished signal: %m");
}

static int send_reloading(sd_bus *bus, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;
        int r;

        assert(bus);

        r = sd_bus_message_new_signal(bus, &message, "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "Reloading");
        if (r < 0)
                return r;

        r = sd_bus_message_append(message, "b", PTR_TO_INT(userdata));
        if (r < 0)
                return r;

        return sd_bus_send(bus, message, NULL);
}

void bus_manager_send_reloading(Manager *m, bool active) {
        int r;

        assert(m);

        r = bus_foreach_bus(m, NULL, send_reloading, INT_TO_PTR(active));
        if (r < 0)
                log_debug_errno(r, "Failed to send reloading signal: %m");
}

static int send_changed_signal(sd_bus *bus, void *userdata) {
        assert(bus);

        return sd_bus_emit_properties_changed_strv(bus,
                                                   "/org/freedesktop/systemd1",
                                                   "org.freedesktop.systemd1.Manager",
                                                   NULL);
}

void bus_manager_send_change_signal(Manager *m) {
        int r;

        assert(m);

        r = bus_foreach_bus(m, NULL, send_changed_signal, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to send manager change signal: %m");
}
