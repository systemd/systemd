/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <sys/prctl.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "alloc-util.h"
#include "architecture.h"
#include "build.h"
#include "bus-common-errors.h"
#include "dbus-execute.h"
#include "dbus-job.h"
#include "dbus-manager.h"
#include "dbus-scope.h"
#include "dbus-unit.h"
#include "dbus.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "install.h"
#include "log.h"
#include "os-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "selinux-access.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "syslog-util.h"
#include "user-util.h"
#include "virt.h"
#include "watchdog.h"

/* Require 16MiB free in /run/systemd for reloading/reexecing. After all we need to serialize our state there, and if
 * we can't we'll fail badly. */
#define RELOAD_DISK_SPACE_MIN (UINT64_C(16) * UINT64_C(1024) * UINT64_C(1024))

static UnitFileFlags unit_file_bools_to_flags(bool runtime, bool force) {
        return (runtime ? UNIT_FILE_RUNTIME : 0) |
               (force   ? UNIT_FILE_FORCE   : 0);
}

BUS_DEFINE_PROPERTY_GET_ENUM(bus_property_get_oom_policy, oom_policy, OOMPolicy);

static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_version, "s", GIT_VERSION);
static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_features, "s", SYSTEMD_FEATURES);
static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_architecture, "s", architecture_to_string(uname_architecture()));
static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_log_target, "s", log_target_to_string(log_get_target()));
static BUS_DEFINE_PROPERTY_GET2(property_get_system_state, "s", Manager, manager_state, manager_state_to_string);
static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_timer_slack_nsec, "t", (uint64_t) prctl(PR_GET_TIMERSLACK));
static BUS_DEFINE_PROPERTY_GET_REF(property_get_hashmap_size, "u", Hashmap *, hashmap_size);
static BUS_DEFINE_PROPERTY_GET_REF(property_get_set_size, "u", Set *, set_size);
static BUS_DEFINE_PROPERTY_GET(property_get_default_timeout_abort_usec, "t", Manager, manager_default_timeout_abort_usec);

static int property_get_virtualization(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        int v;

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

static int property_get_tainted(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *s = NULL;
        Manager *m = userdata;

        assert(bus);
        assert(reply);
        assert(m);

        s = manager_taint_string(m);
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
                sd_bus_error *error) {

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
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid log target '%s'", t);

                manager_override_log_target(m, target);
        }

        return 0;
}

static int property_get_log_level(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *t = NULL;
        int r;

        assert(bus);
        assert(reply);

        r = log_level_to_string_alloc(log_get_max_level(), &t);
        if (r < 0)
                return r;

        return sd_bus_message_append(reply, "s", t);
}

static int property_set_log_level(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *value,
                void *userdata,
                sd_bus_error *error) {

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
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid log level '%s'", t);

                manager_override_log_level(m, level);
        }

        return 0;
}

static int property_get_progress(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = userdata;
        double d;

        assert(bus);
        assert(reply);
        assert(m);

        if (MANAGER_IS_FINISHED(m))
                d = 1.0;
        else
                d = 1.0 - ((double) hashmap_size(m->jobs) / (double) m->n_installed_jobs);

        return sd_bus_message_append(reply, "d", d);
}

static int property_get_environment(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_strv_free_ char **l = NULL;
        Manager *m = userdata;
        int r;

        assert(bus);
        assert(reply);
        assert(m);

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
                sd_bus_error *error) {

        Manager *m = userdata;
        int b;

        assert(bus);
        assert(reply);
        assert(m);

        b = IN_SET(m->show_status, SHOW_STATUS_TEMPORARY, SHOW_STATUS_YES);
        return sd_bus_message_append_basic(reply, 'b', &b);
}

static int property_set_runtime_watchdog(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *value,
                void *userdata,
                sd_bus_error *error) {

        usec_t *t = userdata;
        int r;

        assert(bus);
        assert(value);

        assert_cc(sizeof(usec_t) == sizeof(uint64_t));

        r = sd_bus_message_read(value, "t", t);
        if (r < 0)
                return r;

        return watchdog_set_timeout(t);
}

static int bus_get_unit_by_name(Manager *m, sd_bus_message *message, const char *name, Unit **ret_unit, sd_bus_error *error) {
        Unit *u;
        int r;

        assert(m);
        assert(message);
        assert(ret_unit);

        /* More or less a wrapper around manager_get_unit() that generates nice errors and has one trick up its sleeve:
         * if the name is specified empty we use the client's unit. */

        if (isempty(name)) {
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
                pid_t pid;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_pid(creds, &pid);
                if (r < 0)
                        return r;

                u = manager_get_unit_by_pid(m, pid);
                if (!u)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "Client not member of any unit.");
        } else {
                u = manager_get_unit(m, name);
                if (!u)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s not loaded.", name);
        }

        *ret_unit = u;
        return 0;
}

static int bus_load_unit_by_name(Manager *m, sd_bus_message *message, const char *name, Unit **ret_unit, sd_bus_error *error) {
        assert(m);
        assert(message);
        assert(ret_unit);

        /* Pretty much the same as bus_get_unit_by_name(), but we also load the unit if necessary. */

        if (isempty(name))
                return bus_get_unit_by_name(m, message, name, ret_unit, error);

        return manager_load_unit(m, name, NULL, error, ret_unit);
}

static int reply_unit_path(Unit *u, sd_bus_message *message, sd_bus_error *error) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(u);
        assert(message);

        r = mac_selinux_unit_access_check(u, message, "status", error);
        if (r < 0)
                return r;

        path = unit_dbus_path(u);
        if (!path)
                return log_oom();

        return sd_bus_reply_method_return(message, "o", path);
}

static int method_get_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *name;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = bus_get_unit_by_name(m, message, name, &u, error);
        if (r < 0)
                return r;

        return reply_unit_path(u, message, error);
}

static int method_get_unit_by_pid(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        pid_t pid;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        assert_cc(sizeof(pid_t) == sizeof(uint32_t));

        /* Anyone can call this method */

        r = sd_bus_message_read(message, "u", &pid);
        if (r < 0)
                return r;
        if (pid < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid PID " PID_FMT, pid);

        if (pid == 0) {
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_pid(creds, &pid);
                if (r < 0)
                        return r;
        }

        u = manager_get_unit_by_pid(m, pid);
        if (!u)
                return sd_bus_error_setf(error, BUS_ERROR_NO_UNIT_FOR_PID, "PID "PID_FMT" does not belong to any loaded unit.", pid);

        return reply_unit_path(u, message, error);
}

static int method_get_unit_by_invocation_id(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *path = NULL;
        Manager *m = userdata;
        sd_id128_t id;
        const void *a;
        Unit *u;
        size_t sz;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = sd_bus_message_read_array(message, 'y', &a, &sz);
        if (r < 0)
                return r;
        if (sz == 0)
                id = SD_ID128_NULL;
        else if (sz == 16)
                memcpy(&id, a, sz);
        else
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid invocation ID");

        if (sd_id128_is_null(id)) {
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
                pid_t pid;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_pid(creds, &pid);
                if (r < 0)
                        return r;

                u = manager_get_unit_by_pid(m, pid);
                if (!u)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "Client " PID_FMT " not member of any unit.", pid);
        } else {
                u = hashmap_get(m->units_by_invocation_id, &id);
                if (!u)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_UNIT_FOR_INVOCATION_ID, "No unit with the specified invocation ID " SD_ID128_FORMAT_STR " known.", SD_ID128_FORMAT_VAL(id));
        }

        r = mac_selinux_unit_access_check(u, message, "status", error);
        if (r < 0)
                return r;

        /* So here's a special trick: the bus path we return actually references the unit by its invocation ID instead
         * of the unit name. This means it stays valid only as long as the invocation ID stays the same. */
        path = unit_dbus_path_invocation_id(u);
        if (!path)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", path);
}

static int method_get_unit_by_control_group(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *cgroup;
        Unit *u;
        int r;

        r = sd_bus_message_read(message, "s", &cgroup);
        if (r < 0)
                return r;

        u = manager_get_unit_by_cgroup(m, cgroup);
        if (!u)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "Control group '%s' is not valid or not managed by this instance", cgroup);

        return reply_unit_path(u, message, error);
}

static int method_load_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *name;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = bus_load_unit_by_name(m, message, name, &u, error);
        if (r < 0)
                return r;

        return reply_unit_path(u, message, error);
}

static int method_start_unit_generic(sd_bus_message *message, Manager *m, JobType job_type, bool reload_if_possible, sd_bus_error *error) {
        const char *name;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_load_unit(m, name, NULL, error, &u);
        if (r < 0)
                return r;

        return bus_unit_method_start_generic(message, u, job_type, reload_if_possible, error);
}

static int method_start_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_START, false, error);
}

static int method_stop_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_STOP, false, error);
}

static int method_reload_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_RELOAD, false, error);
}

static int method_restart_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_RESTART, false, error);
}

static int method_try_restart_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_TRY_RESTART, false, error);
}

static int method_reload_or_restart_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_RESTART, true, error);
}

static int method_reload_or_try_restart_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_TRY_RESTART, true, error);
}

typedef enum GenericUnitOperationFlags {
        GENERIC_UNIT_LOAD            = 1 << 0, /* Load if the unit is not loaded yet */
        GENERIC_UNIT_VALIDATE_LOADED = 1 << 1, /* Verify unit is properly loaded before forwarding call */
} GenericUnitOperationFlags;

static int method_generic_unit_operation(
                sd_bus_message *message,
                Manager *m,
                sd_bus_error *error,
                sd_bus_message_handler_t handler,
                GenericUnitOperationFlags flags) {

        const char *name;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        /* Read the first argument from the command and pass the operation to the specified per-unit
         * method. */

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        if (!isempty(name) && FLAGS_SET(flags, GENERIC_UNIT_LOAD))
                r = manager_load_unit(m, name, NULL, error, &u);
        else
                r = bus_get_unit_by_name(m, message, name, &u, error);
        if (r < 0)
                return r;

        if (FLAGS_SET(flags, GENERIC_UNIT_VALIDATE_LOADED)) {
                r = bus_unit_validate_load_state(u, error);
                if (r < 0)
                        return r;
        }

        return handler(message, u, error);
}

static int method_enqueue_unit_job(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        /* We don't bother with GENERIC_UNIT_VALIDATE_LOADED here, as the job logic validates that anyway */
        return method_generic_unit_operation(message, userdata, error, bus_unit_method_enqueue_job, GENERIC_UNIT_LOAD);
}

static int method_start_unit_replace(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *old_name;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &old_name);
        if (r < 0)
                return r;

        r = bus_get_unit_by_name(m, message, old_name, &u, error);
        if (r < 0)
                return r;
        if (!u->job || u->job->type != JOB_START)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_JOB, "No job queued for unit %s", old_name);

        return method_start_unit_generic(message, m, JOB_START, false, error);
}

static int method_kill_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        /* We don't bother with GENERIC_UNIT_LOAD nor GENERIC_UNIT_VALIDATE_LOADED here, as it shouldn't
         * matter whether a unit is loaded for killing any processes possibly in the unit's cgroup. */
        return method_generic_unit_operation(message, userdata, error, bus_unit_method_kill, 0);
}

static int method_clean_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        /* Load the unit if necessary, in order to load it, and insist on the unit being loaded to be
         * cleaned */
        return method_generic_unit_operation(message, userdata, error, bus_unit_method_clean, GENERIC_UNIT_LOAD|GENERIC_UNIT_VALIDATE_LOADED);
}

static int method_reset_failed_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        /* Don't load the unit (because unloaded units can't be in failed state), and don't insist on the
         * unit to be loaded properly (since a failed unit might have its unit file disappeared) */
        return method_generic_unit_operation(message, userdata, error, bus_unit_method_reset_failed, 0);
}

static int method_set_unit_properties(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        /* Only change properties on fully loaded units, and load them in order to set properties */
        return method_generic_unit_operation(message, userdata, error, bus_unit_method_set_properties, GENERIC_UNIT_LOAD|GENERIC_UNIT_VALIDATE_LOADED);
}

static int method_ref_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        /* Only allow reffing of fully loaded units, and make sure reffing a unit loads it. */
        return method_generic_unit_operation(message, userdata, error, bus_unit_method_ref, GENERIC_UNIT_LOAD|GENERIC_UNIT_VALIDATE_LOADED);
}

static int method_unref_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        /* Dropping a ref OTOH should not require the unit to still be loaded. And since a reffed unit is a
         * loaded unit there's no need to load the unit for unreffing it. */
        return method_generic_unit_operation(message, userdata, error, bus_unit_method_unref, 0);
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

static int method_list_units_by_names(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = userdata;
        int r;
        char **unit;
        _cleanup_strv_free_ char **units = NULL;

        assert(message);
        assert(m);

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

                r = bus_load_unit_by_name(m, message, *unit, &u, error);
                if (r < 0)
                        return r;

                r = reply_unit_info(reply, u);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int method_get_unit_processes(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        /* Don't load a unit (since it won't have any processes if it's not loaded), but don't insist on the
         * unit being loaded (because even improperly loaded units might still have processes around */
        return method_generic_unit_operation(message, userdata, error, bus_unit_method_get_processes, 0);
}

static int method_attach_processes_to_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        /* Don't allow attaching new processes to units that aren't loaded. Don't bother with loading a unit
         * for this purpose though, as an unloaded unit is a stopped unit, and we don't allow attaching
         * processes to stopped units anyway. */
        return method_generic_unit_operation(message, userdata, error, bus_unit_method_attach_processes, GENERIC_UNIT_VALIDATE_LOADED);
}

static int transient_unit_from_message(
                Manager *m,
                sd_bus_message *message,
                const char *name,
                Unit **unit,
                sd_bus_error *error) {

        UnitType t;
        Unit *u;
        int r;

        assert(m);
        assert(message);
        assert(name);

        t = unit_name_to_type(name);
        if (t < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid unit name or type.");

        if (!unit_vtable[t]->can_transient)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unit type %s does not support transient units.", unit_type_to_string(t));

        r = manager_load_unit(m, name, NULL, error, &u);
        if (r < 0)
                return r;

        if (!unit_is_pristine(u))
                return sd_bus_error_setf(error, BUS_ERROR_UNIT_EXISTS, "Unit %s already exists.", name);

        /* OK, the unit failed to load and is unreferenced, now let's
         * fill in the transient data instead */
        r = unit_make_transient(u);
        if (r < 0)
                return r;

        /* Set our properties */
        r = bus_unit_set_properties(u, message, UNIT_RUNTIME, false, error);
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

        *unit = u;

        return 0;
}

static int transient_aux_units_from_message(
                Manager *m,
                sd_bus_message *message,
                sd_bus_error *error) {

        int r;

        assert(m);
        assert(message);

        r = sd_bus_message_enter_container(message, 'a', "(sa(sv))");
        if (r < 0)
                return r;

        while ((r = sd_bus_message_enter_container(message, 'r', "sa(sv)")) > 0) {
                const char *name = NULL;
                Unit *u;

                r = sd_bus_message_read(message, "s", &name);
                if (r < 0)
                        return r;

                r = transient_unit_from_message(m, message, name, &u, error);
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

static int method_start_transient_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *name, *smode;
        Manager *m = userdata;
        JobMode mode;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "start", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "ss", &name, &smode);
        if (r < 0)
                return r;

        mode = job_mode_from_string(smode);
        if (mode < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Job mode %s is invalid.", smode);

        r = bus_verify_manage_units_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = transient_unit_from_message(m, message, name, &u, error);
        if (r < 0)
                return r;

        r = transient_aux_units_from_message(m, message, error);
        if (r < 0)
                return r;

        /* Finally, start it */
        return bus_unit_queue_job(message, u, JOB_START, mode, 0, error);
}

static int method_get_job(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *path = NULL;
        Manager *m = userdata;
        uint32_t id;
        Job *j;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = sd_bus_message_read(message, "u", &id);
        if (r < 0)
                return r;

        j = manager_get_job(m, id);
        if (!j)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_JOB, "Job %u does not exist.", (unsigned) id);

        r = mac_selinux_unit_access_check(j->unit, message, "status", error);
        if (r < 0)
                return r;

        path = job_dbus_path(j);
        if (!path)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", path);
}

static int method_cancel_job(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        uint32_t id;
        Job *j;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "u", &id);
        if (r < 0)
                return r;

        j = manager_get_job(m, id);
        if (!j)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_JOB, "Job %u does not exist.", (unsigned) id);

        return bus_job_method_cancel(message, j, error);
}

static int method_clear_jobs(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        manager_clear_jobs(m);

        return sd_bus_reply_method_return(message, NULL);
}

static int method_reset_failed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        manager_reset_failed(m);

        return sd_bus_reply_method_return(message, NULL);
}

static int list_units_filtered(sd_bus_message *message, void *userdata, sd_bus_error *error, char **states, char **patterns) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = userdata;
        const char *k;
        Iterator i;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(ssssssouso)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH_KEY(u, k, m->units, i) {
                if (k != u->id)
                        continue;

                if (!strv_isempty(states) &&
                    !strv_contains(states, unit_load_state_to_string(u->load_state)) &&
                    !strv_contains(states, unit_active_state_to_string(unit_active_state(u))) &&
                    !strv_contains(states, unit_sub_state_to_string(u)))
                        continue;

                if (!strv_isempty(patterns) &&
                    !strv_fnmatch_or_empty(patterns, u->id, FNM_NOESCAPE))
                        continue;

                r = reply_unit_info(reply, u);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int method_list_units(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return list_units_filtered(message, userdata, error, NULL, NULL);
}

static int method_list_units_filtered(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **states = NULL;
        int r;

        r = sd_bus_message_read_strv(message, &states);
        if (r < 0)
                return r;

        return list_units_filtered(message, userdata, error, states, NULL);
}

static int method_list_units_by_patterns(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **states = NULL;
        _cleanup_strv_free_ char **patterns = NULL;
        int r;

        r = sd_bus_message_read_strv(message, &states);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &patterns);
        if (r < 0)
                return r;

        return list_units_filtered(message, userdata, error, states, patterns);
}

static int method_list_jobs(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = userdata;
        Iterator i;
        Job *j;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(usssoo)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(j, m->jobs, i) {
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

        return sd_bus_send(NULL, reply, NULL);
}

static int method_subscribe(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
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
                        return sd_bus_error_setf(error, BUS_ERROR_ALREADY_SUBSCRIBED, "Client is already subscribed.");
        }

        return sd_bus_reply_method_return(message, NULL);
}

static int method_unsubscribe(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        if (sd_bus_message_get_bus(message) == m->api_bus) {
                r = sd_bus_track_remove_sender(m->subscribed, message);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_error_setf(error, BUS_ERROR_NOT_SUBSCRIBED, "Client is not subscribed.");
        }

        return sd_bus_reply_method_return(message, NULL);
}

static int dump_impl(sd_bus_message *message, void *userdata, sd_bus_error *error, int (*reply)(sd_bus_message *, char *)) {
        _cleanup_free_ char *dump = NULL;
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        r = manager_get_dump_string(m, &dump);
        if (r < 0)
                return r;

        return reply(message, dump);
}

static int reply_dump(sd_bus_message *message, char *dump) {
        return sd_bus_reply_method_return(message, "s", dump);
}

static int method_dump(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return dump_impl(message, userdata, error, reply_dump);
}

static int reply_dump_by_fd(sd_bus_message *message, char *dump) {
        _cleanup_close_ int fd = -1;

        fd = acquire_data_fd(dump, strlen(dump), 0);
        if (fd < 0)
                return fd;

        return sd_bus_reply_method_return(message, "h", fd);
}

static int method_dump_by_fd(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return dump_impl(message, userdata, error, reply_dump_by_fd);
}

static int method_refuse_snapshot(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Support for snapshots has been removed.");
}

static int verify_run_space(const char *message, sd_bus_error *error) {
        struct statvfs svfs;
        uint64_t available;

        if (statvfs("/run/systemd", &svfs) < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to statvfs(/run/systemd): %m");

        available = (uint64_t) svfs.f_bfree * (uint64_t) svfs.f_bsize;

        if (available < RELOAD_DISK_SPACE_MIN) {
                char fb_available[FORMAT_BYTES_MAX], fb_need[FORMAT_BYTES_MAX];
                return sd_bus_error_setf(error,
                                         BUS_ERROR_DISK_FULL,
                                         "%s, not enough space available on /run/systemd. "
                                         "Currently, %s are free, but a safety buffer of %s is enforced.",
                                         message,
                                         format_bytes(fb_available, sizeof(fb_available), available),
                                         format_bytes(fb_need, sizeof(fb_need), RELOAD_DISK_SPACE_MIN));
        }

        return 0;
}

int verify_run_space_and_log(const char *message) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = verify_run_space(message, &error);
        if (r < 0)
                return log_error_errno(r, "%s", bus_error_message(&error, r));

        return 0;
}

static int method_reload(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = verify_run_space("Refusing to reload", error);
        if (r < 0)
                return r;

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = bus_verify_reload_daemon_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        /* Instead of sending the reply back right away, we just
         * remember that we need to and then send it after the reload
         * is finished. That way the caller knows when the reload
         * finished. */

        assert(!m->pending_reload_message);
        r = sd_bus_message_new_method_return(message, &m->pending_reload_message);
        if (r < 0)
                return r;

        m->objective = MANAGER_RELOAD;

        return 1;
}

static int method_reexecute(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = verify_run_space("Refusing to reexecute", error);
        if (r < 0)
                return r;

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = bus_verify_reload_daemon_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        /* We don't send a reply back here, the client should
         * just wait for us disconnecting. */

        m->objective = MANAGER_REEXECUTE;
        return 1;
}

static int method_exit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "halt", error);
        if (r < 0)
                return r;

        /* Exit() (in contrast to SetExitCode()) is actually allowed even if
         * we are running on the host. It will fall back on reboot() in
         * systemd-shutdown if it cannot do the exit() because it isn't a
         * container. */

        m->objective = MANAGER_EXIT;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_reboot(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "reboot", error);
        if (r < 0)
                return r;

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Reboot is only supported for system managers.");

        m->objective = MANAGER_REBOOT;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_poweroff(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "halt", error);
        if (r < 0)
                return r;

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Powering off is only supported for system managers.");

        m->objective = MANAGER_POWEROFF;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_halt(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "halt", error);
        if (r < 0)
                return r;

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Halt is only supported for system managers.");

        m->objective = MANAGER_HALT;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_kexec(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "reboot", error);
        if (r < 0)
                return r;

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "KExec is only supported for system managers.");

        m->objective = MANAGER_KEXEC;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_switch_root(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *ri = NULL, *rt = NULL;
        const char *root, *init;
        Manager *m = userdata;
        struct statvfs svfs;
        uint64_t available;
        int r;

        assert(message);
        assert(m);

        if (statvfs("/run/systemd", &svfs) < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to statvfs(/run/systemd): %m");

        available = (uint64_t) svfs.f_bfree * (uint64_t) svfs.f_bsize;

        if (available < RELOAD_DISK_SPACE_MIN) {
                char fb_available[FORMAT_BYTES_MAX], fb_need[FORMAT_BYTES_MAX];
                log_warning("Dangerously low amount of free space on /run/systemd, root switching operation might not complete successfully. "
                            "Currently, %s are free, but %s are suggested. Proceeding anyway.",
                            format_bytes(fb_available, sizeof(fb_available), available),
                            format_bytes(fb_need, sizeof(fb_need), RELOAD_DISK_SPACE_MIN));
        }

        r = mac_selinux_access_check(message, "reboot", error);
        if (r < 0)
                return r;

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Root switching is only supported by system manager.");

        r = sd_bus_message_read(message, "ss", &root, &init);
        if (r < 0)
                return r;

        if (isempty(root))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "New root directory may not be the empty string.");
        if (!path_is_absolute(root))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "New root path '%s' is not absolute.", root);
        if (path_equal(root, "/"))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "New root directory cannot be the old root directory.");

        /* Safety check */
        if (isempty(init)) {
                r = path_is_os_tree(root);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Failed to determine whether root path '%s' contains an OS tree: %m", root);
                if (r == 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Specified switch root path '%s' does not seem to be an OS tree. os-release file is missing.", root);
        } else {
                _cleanup_free_ char *chased = NULL;

                if (!path_is_absolute(init))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Path to init binary '%s' not absolute.", init);

                r = chase_symlinks(init, root, CHASE_PREFIX_ROOT|CHASE_TRAIL_SLASH, &chased);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Could not resolve init executable %s: %m", init);

                if (laccess(chased, X_OK) < 0) {
                        if (errno == EACCES)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Init binary %s is not executable.", init);

                        return sd_bus_error_set_errnof(error, r, "Could not check whether init binary %s is executable: %m", init);
                }
        }

        rt = strdup(root);
        if (!rt)
                return -ENOMEM;

        if (!isempty(init)) {
                ri = strdup(init);
                if (!ri)
                        return -ENOMEM;
        }

        free_and_replace(m->switch_root, rt);
        free_and_replace(m->switch_root_init, ri);

        m->objective = MANAGER_SWITCH_ROOT;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_set_environment(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **plus = NULL;
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &plus);
        if (r < 0)
                return r;
        if (!strv_env_is_valid(plus))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid environment assignments");

        r = bus_verify_set_environment_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = manager_client_environment_modify(m, NULL, plus);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_unset_environment(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **minus = NULL;
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &minus);
        if (r < 0)
                return r;

        if (!strv_env_name_or_assignment_is_valid(minus))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid environment variable names or assignments");

        r = bus_verify_set_environment_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = manager_client_environment_modify(m, minus, NULL);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_unset_and_set_environment(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **minus = NULL, **plus = NULL;
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &minus);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &plus);
        if (r < 0)
                return r;

        if (!strv_env_name_or_assignment_is_valid(minus))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid environment variable names or assignments");
        if (!strv_env_is_valid(plus))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid environment assignments");

        r = bus_verify_set_environment_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = manager_client_environment_modify(m, minus, plus);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_set_exit_code(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        uint8_t code;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "exit", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read_basic(message, 'y', &code);
        if (r < 0)
                return r;

        if (MANAGER_IS_SYSTEM(m) && detect_container() <= 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "ExitCode can only be set for user service managers or in containers.");

        m->return_value = code;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_lookup_dynamic_user_by_name(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *name;
        uid_t uid;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read_basic(message, 's', &name);
        if (r < 0)
                return r;

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Dynamic users are only supported in the system instance.");
        if (!valid_user_group_name(name))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "User name invalid: %s", name);

        r = dynamic_user_lookup_name(m, name, &uid);
        if (r == -ESRCH)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_DYNAMIC_USER, "Dynamic user %s does not exist.", name);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "u", (uint32_t) uid);
}

static int method_lookup_dynamic_user_by_uid(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *name = NULL;
        Manager *m = userdata;
        uid_t uid;
        int r;

        assert(message);
        assert(m);

        assert_cc(sizeof(uid) == sizeof(uint32_t));
        r = sd_bus_message_read_basic(message, 'u', &uid);
        if (r < 0)
                return r;

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Dynamic users are only supported in the system instance.");
        if (!uid_is_valid(uid))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "User ID invalid: " UID_FMT, uid);

        r = dynamic_user_lookup_uid(m, uid, &name);
        if (r == -ESRCH)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_DYNAMIC_USER, "Dynamic user ID " UID_FMT " does not exist.", uid);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "s", name);
}

static int method_get_dynamic_users(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = userdata;
        DynamicUser *d;
        Iterator i;
        int r;

        assert(message);
        assert(m);

        assert_cc(sizeof(uid_t) == sizeof(uint32_t));

        if (!MANAGER_IS_SYSTEM(m))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Dynamic users are only supported in the system instance.");

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(us)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(d, m->dynamic_users, i) {
                uid_t uid;

                r = dynamic_user_current(d, &uid);
                if (r == -EAGAIN) /* not realized yet? */
                        continue;
                if (r < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_FAILED, "Failed to lookup a dynamic user.");

                r = sd_bus_message_append(reply, "(us)", uid, d->name);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int list_unit_files_by_patterns(sd_bus_message *message, void *userdata, sd_bus_error *error, char **states, char **patterns) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = userdata;
        UnitFileList *item;
        Hashmap *h;
        Iterator i;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        h = hashmap_new(&string_hash_ops);
        if (!h)
                return -ENOMEM;

        r = unit_file_get_list(m->unit_file_scope, NULL, h, states, patterns);
        if (r < 0)
                goto fail;

        r = sd_bus_message_open_container(reply, 'a', "(ss)");
        if (r < 0)
                goto fail;

        HASHMAP_FOREACH(item, h, i) {

                r = sd_bus_message_append(reply, "(ss)", item->path, unit_file_state_to_string(item->state));
                if (r < 0)
                        goto fail;
        }

        unit_file_list_free(h);

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);

fail:
        unit_file_list_free(h);
        return r;
}

static int method_list_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return list_unit_files_by_patterns(message, userdata, error, NULL, NULL);
}

static int method_list_unit_files_by_patterns(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **states = NULL;
        _cleanup_strv_free_ char **patterns = NULL;
        int r;

        r = sd_bus_message_read_strv(message, &states);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &patterns);
        if (r < 0)
                return r;

        return list_unit_files_by_patterns(message, userdata, error, states, patterns);
}

static int method_get_unit_file_state(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *name;
        UnitFileState state;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = unit_file_get_state(m->unit_file_scope, NULL, name, &state);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "s", unit_file_state_to_string(state));
}

static int method_get_default_target(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *default_target = NULL;
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        r = unit_file_get_default(m->unit_file_scope, NULL, &default_target);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "s", default_target);
}

static int send_unit_files_changed(sd_bus *bus, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;
        int r;

        assert(bus);

        r = sd_bus_message_new_signal(bus, &message, "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "UnitFilesChanged");
        if (r < 0)
                return r;

        return sd_bus_send(bus, message, NULL);
}

/* Create an error reply, using the error information from changes[]
 * if possible, and fall back to generating an error from error code c.
 * The error message only describes the first error.
 *
 * Coordinate with unit_file_dump_changes() in install.c.
 */
static int install_error(
                sd_bus_error *error,
                int c,
                UnitFileChange *changes,
                size_t n_changes) {

        size_t i;
        int r;

        for (i = 0; i < n_changes; i++)

                switch(changes[i].type) {

                case 0 ... INT_MAX:
                        continue;

                case -EEXIST:
                        if (changes[i].source)
                                r = sd_bus_error_setf(error, BUS_ERROR_UNIT_EXISTS,
                                                      "File %s already exists and is a symlink to %s.",
                                                      changes[i].path, changes[i].source);
                        else
                                r = sd_bus_error_setf(error, BUS_ERROR_UNIT_EXISTS,
                                                      "File %s already exists.",
                                                      changes[i].path);
                        goto found;

                case -ERFKILL:
                        r = sd_bus_error_setf(error, BUS_ERROR_UNIT_MASKED,
                                              "Unit file %s is masked.", changes[i].path);
                        goto found;

                case -EADDRNOTAVAIL:
                        r = sd_bus_error_setf(error, BUS_ERROR_UNIT_GENERATED,
                                              "Unit %s is transient or generated.", changes[i].path);
                        goto found;

                case -ELOOP:
                        r = sd_bus_error_setf(error, BUS_ERROR_UNIT_LINKED,
                                              "Refusing to operate on linked unit file %s", changes[i].path);
                        goto found;

                case -ENOENT:
                        r = sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "Unit file %s does not exist.", changes[i].path);
                        goto found;

                default:
                        r = sd_bus_error_set_errnof(error, changes[i].type, "File %s: %m", changes[i].path);
                        goto found;
                }

        r = c < 0 ? c : -EINVAL;

 found:
        unit_file_changes_free(changes, n_changes);
        return r;
}

static int reply_unit_file_changes_and_free(
                Manager *m,
                sd_bus_message *message,
                int carries_install_info,
                UnitFileChange *changes,
                size_t n_changes,
                sd_bus_error *error) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        bool bad = false, good = false;
        size_t i;
        int r;

        if (unit_file_changes_have_modification(changes, n_changes)) {
                r = bus_foreach_bus(m, NULL, send_unit_files_changed, NULL);
                if (r < 0)
                        log_debug_errno(r, "Failed to send UnitFilesChanged signal: %m");
        }

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                goto fail;

        if (carries_install_info >= 0) {
                r = sd_bus_message_append(reply, "b", carries_install_info);
                if (r < 0)
                        goto fail;
        }

        r = sd_bus_message_open_container(reply, 'a', "(sss)");
        if (r < 0)
                goto fail;

        for (i = 0; i < n_changes; i++) {

                if (changes[i].type < 0) {
                        bad = true;
                        continue;
                }

                r = sd_bus_message_append(
                                reply, "(sss)",
                                unit_file_change_type_to_string(changes[i].type),
                                changes[i].path,
                                changes[i].source);
                if (r < 0)
                        goto fail;

                good = true;
        }

        /* If there was a failed change, and no successful change, then return the first failure as proper method call
         * error. */
        if (bad && !good)
                return install_error(error, 0, changes, n_changes);

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                goto fail;

        unit_file_changes_free(changes, n_changes);
        return sd_bus_send(NULL, reply, NULL);

fail:
        unit_file_changes_free(changes, n_changes);
        return r;
}

static int method_enable_unit_files_generic(
                sd_bus_message *message,
                Manager *m,
                int (*call)(UnitFileScope scope, UnitFileFlags flags, const char *root_dir, char *files[], UnitFileChange **changes, size_t *n_changes),
                bool carries_install_info,
                sd_bus_error *error) {

        _cleanup_strv_free_ char **l = NULL;
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileFlags flags;
        int runtime, force, r;

        assert(message);
        assert(m);

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "bb", &runtime, &force);
        if (r < 0)
                return r;

        flags = unit_file_bools_to_flags(runtime, force);

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = call(m->unit_file_scope, flags, NULL, l, &changes, &n_changes);
        if (r < 0)
                return install_error(error, r, changes, n_changes);

        return reply_unit_file_changes_and_free(m, message, carries_install_info ? r : -1, changes, n_changes, error);
}

static int method_enable_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_enable_unit_files_generic(message, userdata, unit_file_enable, true, error);
}

static int method_reenable_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_enable_unit_files_generic(message, userdata, unit_file_reenable, true, error);
}

static int method_link_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_enable_unit_files_generic(message, userdata, unit_file_link, false, error);
}

static int unit_file_preset_without_mode(UnitFileScope scope, UnitFileFlags flags, const char *root_dir, char **files, UnitFileChange **changes, size_t *n_changes) {
        return unit_file_preset(scope, flags, root_dir, files, UNIT_FILE_PRESET_FULL, changes, n_changes);
}

static int method_preset_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_enable_unit_files_generic(message, userdata, unit_file_preset_without_mode, true, error);
}

static int method_mask_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_enable_unit_files_generic(message, userdata, unit_file_mask, false, error);
}

static int method_preset_unit_files_with_mode(sd_bus_message *message, void *userdata, sd_bus_error *error) {

        _cleanup_strv_free_ char **l = NULL;
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;
        Manager *m = userdata;
        UnitFilePresetMode mm;
        int runtime, force, r;
        UnitFileFlags flags;
        const char *mode;

        assert(message);
        assert(m);

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "sbb", &mode, &runtime, &force);
        if (r < 0)
                return r;

        flags = unit_file_bools_to_flags(runtime, force);

        if (isempty(mode))
                mm = UNIT_FILE_PRESET_FULL;
        else {
                mm = unit_file_preset_mode_from_string(mode);
                if (mm < 0)
                        return -EINVAL;
        }

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_file_preset(m->unit_file_scope, flags, NULL, l, mm, &changes, &n_changes);
        if (r < 0)
                return install_error(error, r, changes, n_changes);

        return reply_unit_file_changes_and_free(m, message, r, changes, n_changes, error);
}

static int method_disable_unit_files_generic(
                sd_bus_message *message,
                Manager *m,
                int (*call)(UnitFileScope scope, UnitFileFlags flags, const char *root_dir, char *files[], UnitFileChange **changes, size_t *n_changes),
                sd_bus_error *error) {

        _cleanup_strv_free_ char **l = NULL;
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;
        int r, runtime;

        assert(message);
        assert(m);

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "b", &runtime);
        if (r < 0)
                return r;

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = call(m->unit_file_scope, runtime ? UNIT_FILE_RUNTIME : 0, NULL, l, &changes, &n_changes);
        if (r < 0)
                return install_error(error, r, changes, n_changes);

        return reply_unit_file_changes_and_free(m, message, -1, changes, n_changes, error);
}

static int method_disable_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_disable_unit_files_generic(message, userdata, unit_file_disable, error);
}

static int method_unmask_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_disable_unit_files_generic(message, userdata, unit_file_unmask, error);
}

static int method_revert_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_file_revert(m->unit_file_scope, NULL, l, &changes, &n_changes);
        if (r < 0)
                return install_error(error, r, changes, n_changes);

        return reply_unit_file_changes_and_free(m, message, -1, changes, n_changes, error);
}

static int method_set_default_target(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;
        Manager *m = userdata;
        const char *name;
        int force, r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "enable", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "sb", &name, &force);
        if (r < 0)
                return r;

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_file_set_default(m->unit_file_scope, force ? UNIT_FILE_FORCE : 0, NULL, name, &changes, &n_changes);
        if (r < 0)
                return install_error(error, r, changes, n_changes);

        return reply_unit_file_changes_and_free(m, message, -1, changes, n_changes, error);
}

static int method_preset_all_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;
        Manager *m = userdata;
        UnitFilePresetMode mm;
        const char *mode;
        UnitFileFlags flags;
        int force, runtime, r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "enable", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "sbb", &mode, &runtime, &force);
        if (r < 0)
                return r;

        flags = unit_file_bools_to_flags(runtime, force);

        if (isempty(mode))
                mm = UNIT_FILE_PRESET_FULL;
        else {
                mm = unit_file_preset_mode_from_string(mode);
                if (mm < 0)
                        return -EINVAL;
        }

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_file_preset_all(m->unit_file_scope, flags, NULL, mm, &changes, &n_changes);
        if (r < 0)
                return install_error(error, r, changes, n_changes);

        return reply_unit_file_changes_and_free(m, message, -1, changes, n_changes, error);
}

static int method_add_dependency_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = userdata;
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;
        int runtime, force, r;
        char *target, *type;
        UnitDependency dep;
        UnitFileFlags flags;

        assert(message);
        assert(m);

        r = bus_verify_manage_unit_files_async(m, message, error);
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
        if (dep < 0)
                return -EINVAL;

        r = unit_file_add_dependency(m->unit_file_scope, flags, NULL, l, target, dep, &changes, &n_changes);
        if (r < 0)
                return install_error(error, r, changes, n_changes);

        return reply_unit_file_changes_and_free(m, message, -1, changes, n_changes, error);
}

static int method_get_unit_file_links(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        UnitFileChange *changes = NULL;
        size_t n_changes = 0, i;
        UnitFileFlags flags;
        const char *name;
        char **p;
        int runtime, r;

        r = sd_bus_message_read(message, "sb", &name, &runtime);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "s");
        if (r < 0)
                return r;

        p = STRV_MAKE(name);
        flags = UNIT_FILE_DRY_RUN |
                (runtime ? UNIT_FILE_RUNTIME : 0);

        r = unit_file_disable(UNIT_FILE_SYSTEM, flags, NULL, p, &changes, &n_changes);
        if (r < 0)
                return log_error_errno(r, "Failed to get file links for %s: %m", name);

        for (i = 0; i < n_changes; i++)
                if (changes[i].type == UNIT_FILE_UNLINK) {
                        r = sd_bus_message_append(reply, "s", changes[i].path);
                        if (r < 0)
                                return r;
                }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int method_get_job_waiting(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        uint32_t id;
        Job *j;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "u", &id);
        if (r < 0)
                return r;

        j = manager_get_job(m, id);
        if (!j)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_JOB, "Job %u does not exist.", (unsigned) id);

        return bus_job_method_get_waiting_jobs(message, j, error);
}

static int method_abandon_scope(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *name;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = bus_get_unit_by_name(m, message, name, &u, error);
        if (r < 0)
                return r;

        if (u->type != UNIT_SCOPE)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unit '%s' is not a scope unit, refusing.", name);

        return bus_scope_method_abandon(message, u, error);
}

const sd_bus_vtable bus_manager_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("Version", "s", property_get_version, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Features", "s", property_get_features, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Virtualization", "s", property_get_virtualization, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Architecture", "s", property_get_architecture, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Tainted", "s", property_get_tainted, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("FirmwareTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_FIRMWARE]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("LoaderTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_LOADER]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("KernelTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_KERNEL]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("InitRDTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_INITRD]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("UserspaceTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_USERSPACE]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("FinishTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_FINISH]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("SecurityStartTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_SECURITY_START]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("SecurityFinishTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_SECURITY_FINISH]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("GeneratorsStartTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_GENERATORS_START]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("GeneratorsFinishTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_GENERATORS_FINISH]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("UnitsLoadStartTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_UNITS_LOAD_START]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("UnitsLoadFinishTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_UNITS_LOAD_FINISH]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("InitRDSecurityStartTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_INITRD_SECURITY_START]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("InitRDSecurityFinishTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_INITRD_SECURITY_FINISH]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("InitRDGeneratorsStartTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_INITRD_GENERATORS_START]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("InitRDGeneratorsFinishTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_INITRD_GENERATORS_FINISH]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("InitRDUnitsLoadStartTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_START]), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("InitRDUnitsLoadFinishTimestamp", offsetof(Manager, timestamps[MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_FINISH]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_WRITABLE_PROPERTY("LogLevel", "s", property_get_log_level, property_set_log_level, 0, 0),
        SD_BUS_WRITABLE_PROPERTY("LogTarget", "s", property_get_log_target, property_set_log_target, 0, 0),
        SD_BUS_PROPERTY("NNames", "u", property_get_hashmap_size, offsetof(Manager, units), 0),
        SD_BUS_PROPERTY("NFailedUnits", "u", property_get_set_size, offsetof(Manager, failed_units), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("NJobs", "u", property_get_hashmap_size, offsetof(Manager, jobs), 0),
        SD_BUS_PROPERTY("NInstalledJobs", "u", bus_property_get_unsigned, offsetof(Manager, n_installed_jobs), 0),
        SD_BUS_PROPERTY("NFailedJobs", "u", bus_property_get_unsigned, offsetof(Manager, n_failed_jobs), 0),
        SD_BUS_PROPERTY("Progress", "d", property_get_progress, 0, 0),
        SD_BUS_PROPERTY("Environment", "as", property_get_environment, 0, 0),
        SD_BUS_PROPERTY("ConfirmSpawn", "b", bus_property_get_bool, offsetof(Manager, confirm_spawn), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ShowStatus", "b", property_get_show_status, 0, 0),
        SD_BUS_PROPERTY("UnitPath", "as", NULL, offsetof(Manager, lookup_paths.search_path), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultStandardOutput", "s", bus_property_get_exec_output, offsetof(Manager, default_std_output), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultStandardError", "s", bus_property_get_exec_output, offsetof(Manager, default_std_output), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_WRITABLE_PROPERTY("RuntimeWatchdogUSec", "t", bus_property_get_usec, property_set_runtime_watchdog, offsetof(Manager, runtime_watchdog), 0),
        SD_BUS_WRITABLE_PROPERTY("RebootWatchdogUSec", "t", bus_property_get_usec, bus_property_set_usec, offsetof(Manager, reboot_watchdog), 0),
        /* The following item is an obsolete alias */
        SD_BUS_WRITABLE_PROPERTY("ShutdownWatchdogUSec", "t", bus_property_get_usec, bus_property_set_usec, offsetof(Manager, reboot_watchdog), SD_BUS_VTABLE_HIDDEN),
        SD_BUS_WRITABLE_PROPERTY("KExecWatchdogUSec", "t", bus_property_get_usec, bus_property_set_usec, offsetof(Manager, kexec_watchdog), 0),
        SD_BUS_WRITABLE_PROPERTY("ServiceWatchdogs", "b", bus_property_get_bool, bus_property_set_bool, offsetof(Manager, service_watchdogs), 0),
        SD_BUS_PROPERTY("ControlGroup", "s", NULL, offsetof(Manager, cgroup_root), 0),
        SD_BUS_PROPERTY("SystemState", "s", property_get_system_state, 0, 0),
        SD_BUS_PROPERTY("ExitCode", "y", bus_property_get_unsigned, offsetof(Manager, return_value), 0),
        SD_BUS_PROPERTY("DefaultTimerAccuracyUSec", "t", bus_property_get_usec, offsetof(Manager, default_timer_accuracy_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultTimeoutStartUSec", "t", bus_property_get_usec, offsetof(Manager, default_timeout_start_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultTimeoutStopUSec", "t", bus_property_get_usec, offsetof(Manager, default_timeout_stop_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultTimeoutAbortUSec", "t", property_get_default_timeout_abort_usec, 0, 0),
        SD_BUS_PROPERTY("DefaultRestartUSec", "t", bus_property_get_usec, offsetof(Manager, default_restart_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultStartLimitIntervalUSec", "t", bus_property_get_usec, offsetof(Manager, default_start_limit_interval), SD_BUS_VTABLE_PROPERTY_CONST),
        /* The following two items are obsolete alias */
        SD_BUS_PROPERTY("DefaultStartLimitIntervalSec", "t", bus_property_get_usec, offsetof(Manager, default_start_limit_interval), SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("DefaultStartLimitInterval", "t", bus_property_get_usec, offsetof(Manager, default_start_limit_interval), SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("DefaultStartLimitBurst", "u", bus_property_get_unsigned, offsetof(Manager, default_start_limit_burst), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultCPUAccounting", "b", bus_property_get_bool, offsetof(Manager, default_cpu_accounting), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultBlockIOAccounting", "b", bus_property_get_bool, offsetof(Manager, default_blockio_accounting), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultMemoryAccounting", "b", bus_property_get_bool, offsetof(Manager, default_memory_accounting), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultTasksAccounting", "b", bus_property_get_bool, offsetof(Manager, default_tasks_accounting), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitCPU", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_CPU]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitCPUSoft", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_CPU]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitFSIZE", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_FSIZE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitFSIZESoft", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_FSIZE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitDATA", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_DATA]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitDATASoft", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_DATA]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitSTACK", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_STACK]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitSTACKSoft", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_STACK]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitCORE", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_CORE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitCORESoft", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_CORE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitRSS", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_RSS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitRSSSoft", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_RSS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitNOFILE", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_NOFILE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitNOFILESoft", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_NOFILE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitAS", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_AS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitASSoft", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_AS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitNPROC", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_NPROC]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitNPROCSoft", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_NPROC]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitMEMLOCK", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_MEMLOCK]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitMEMLOCKSoft", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_MEMLOCK]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitLOCKS", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_LOCKS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitLOCKSSoft", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_LOCKS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitSIGPENDING", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_SIGPENDING]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitSIGPENDINGSoft", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_SIGPENDING]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitMSGQUEUE", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_MSGQUEUE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitMSGQUEUESoft", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_MSGQUEUE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitNICE", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_NICE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitNICESoft", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_NICE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitRTPRIO", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_RTPRIO]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitRTPRIOSoft", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_RTPRIO]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitRTTIME", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_RTTIME]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultLimitRTTIMESoft", "t", bus_property_get_rlimit, offsetof(Manager, rlimit[RLIMIT_RTTIME]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultTasksMax", "t", NULL, offsetof(Manager, default_tasks_max), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TimerSlackNSec", "t", property_get_timer_slack_nsec, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultOOMPolicy", "s", bus_property_get_oom_policy, offsetof(Manager, default_oom_policy), SD_BUS_VTABLE_PROPERTY_CONST),

        SD_BUS_METHOD("GetUnit", "s", "o", method_get_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetUnitByPID", "u", "o", method_get_unit_by_pid, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetUnitByInvocationID", "ay", "o", method_get_unit_by_invocation_id, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetUnitByControlGroup", "s", "o", method_get_unit_by_control_group, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("LoadUnit", "s", "o", method_load_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("StartUnit", "ss", "o", method_start_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("StartUnitReplace", "sss", "o", method_start_unit_replace, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("StopUnit", "ss", "o", method_stop_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ReloadUnit", "ss", "o", method_reload_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("RestartUnit", "ss", "o", method_restart_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("TryRestartUnit", "ss", "o", method_try_restart_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ReloadOrRestartUnit", "ss", "o", method_reload_or_restart_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ReloadOrTryRestartUnit", "ss", "o", method_reload_or_try_restart_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("EnqueueUnitJob", "sss", "uososa(uosos)", method_enqueue_unit_job, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("KillUnit", "ssi", NULL, method_kill_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CleanUnit", "sas", NULL, method_clean_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResetFailedUnit", "s", NULL, method_reset_failed_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetUnitProperties", "sba(sv)", NULL, method_set_unit_properties, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("RefUnit", "s", NULL, method_ref_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("UnrefUnit", "s", NULL, method_unref_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("StartTransientUnit", "ssa(sv)a(sa(sv))", "o", method_start_transient_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetUnitProcesses", "s", "a(sus)", method_get_unit_processes, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("AttachProcessesToUnit", "ssau", NULL, method_attach_processes_to_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("AbandonScope", "s", NULL, method_abandon_scope, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetJob", "u", "o", method_get_job, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetJobAfter", "u", "a(usssoo)", method_get_job_waiting, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetJobBefore", "u", "a(usssoo)", method_get_job_waiting, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CancelJob", "u", NULL, method_cancel_job, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ClearJobs", NULL, NULL, method_clear_jobs, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResetFailed", NULL, NULL, method_reset_failed, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListUnits", NULL, "a(ssssssouso)", method_list_units, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListUnitsFiltered", "as", "a(ssssssouso)", method_list_units_filtered, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListUnitsByPatterns", "asas", "a(ssssssouso)", method_list_units_by_patterns, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListUnitsByNames", "as", "a(ssssssouso)", method_list_units_by_names, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListJobs", NULL, "a(usssoo)", method_list_jobs, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Subscribe", NULL, NULL, method_subscribe, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Unsubscribe", NULL, NULL, method_unsubscribe, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Dump", NULL, "s", method_dump, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("DumpByFileDescriptor", NULL, "h", method_dump_by_fd, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CreateSnapshot", "sb", "o", method_refuse_snapshot, SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_METHOD("RemoveSnapshot", "s", NULL, method_refuse_snapshot, SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_METHOD("Reload", NULL, NULL, method_reload, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Reexecute", NULL, NULL, method_reexecute, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Exit", NULL, NULL, method_exit, 0),
        SD_BUS_METHOD("Reboot", NULL, NULL, method_reboot, SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
        SD_BUS_METHOD("PowerOff", NULL, NULL, method_poweroff, SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
        SD_BUS_METHOD("Halt", NULL, NULL, method_halt, SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
        SD_BUS_METHOD("KExec", NULL, NULL, method_kexec, SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
        SD_BUS_METHOD("SwitchRoot", "ss", NULL, method_switch_root, SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
        SD_BUS_METHOD("SetEnvironment", "as", NULL, method_set_environment, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("UnsetEnvironment", "as", NULL, method_unset_environment, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("UnsetAndSetEnvironment", "asas", NULL, method_unset_and_set_environment, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListUnitFiles", NULL, "a(ss)", method_list_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListUnitFilesByPatterns", "asas", "a(ss)", method_list_unit_files_by_patterns, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetUnitFileState", "s", "s", method_get_unit_file_state, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("EnableUnitFiles", "asbb", "ba(sss)", method_enable_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("DisableUnitFiles", "asb", "a(sss)", method_disable_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ReenableUnitFiles", "asbb", "ba(sss)", method_reenable_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("LinkUnitFiles", "asbb", "a(sss)", method_link_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("PresetUnitFiles", "asbb", "ba(sss)", method_preset_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("PresetUnitFilesWithMode", "assbb", "ba(sss)", method_preset_unit_files_with_mode, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("MaskUnitFiles", "asbb", "a(sss)", method_mask_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("UnmaskUnitFiles", "asb", "a(sss)", method_unmask_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("RevertUnitFiles", "as", "a(sss)", method_revert_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetDefaultTarget", "sb", "a(sss)", method_set_default_target, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetDefaultTarget", NULL, "s", method_get_default_target, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("PresetAllUnitFiles", "sbb", "a(sss)", method_preset_all_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("AddDependencyUnitFiles", "asssbb", "a(sss)", method_add_dependency_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetUnitFileLinks", "sb", "as", method_get_unit_file_links, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetExitCode", "y", NULL, method_set_exit_code, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("LookupDynamicUserByName", "s", "u", method_lookup_dynamic_user_by_name, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("LookupDynamicUserByUID", "u", "s", method_lookup_dynamic_user_by_uid, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetDynamicUsers", NULL, "a(us)", method_get_dynamic_users, SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_SIGNAL("UnitNew", "so", 0),
        SD_BUS_SIGNAL("UnitRemoved", "so", 0),
        SD_BUS_SIGNAL("JobNew", "uos", 0),
        SD_BUS_SIGNAL("JobRemoved", "uoss", 0),
        SD_BUS_SIGNAL("StartupFinished", "tttttt", 0),
        SD_BUS_SIGNAL("UnitFilesChanged", NULL, 0),
        SD_BUS_SIGNAL("Reloading", "b", 0),

        SD_BUS_VTABLE_END
};

static int send_finished(sd_bus *bus, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;
        usec_t *times = userdata;
        int r;

        assert(bus);
        assert(times);

        r = sd_bus_message_new_signal(bus, &message, "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "StartupFinished");
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
