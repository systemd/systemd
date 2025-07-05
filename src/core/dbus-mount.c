/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-common-errors.h"
#include "bus-get-properties.h"
#include "dbus-cgroup.h"
#include "dbus-execute.h"
#include "dbus-kill.h"
#include "dbus-mount.h"
#include "dbus-util.h"
#include "fstab-util.h"
#include "locale-util.h"
#include "manager.h"
#include "mount.h"
#include "selinux-access.h"
#include "string-util.h"
#include "unit.h"

static int property_get_where(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Mount *m = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        _cleanup_free_ char *escaped = mount_get_where_escaped(m);
        if (!escaped)
                return -ENOMEM;

        return sd_bus_message_append_basic(reply, 's', escaped);
}

static BUS_DEFINE_PROPERTY_GET(property_get_type, "s", Mount, mount_get_fstype);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, mount_result, MountResult);

static int property_get_what(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *escaped = NULL;
        Mount *m = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        escaped = mount_get_what_escaped(m);
        if (!escaped)
                return -ENOMEM;

        return sd_bus_message_append_basic(reply, 's', escaped);
}

static int property_get_options(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *escaped = NULL;
        Mount *m = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        escaped = mount_get_options_escaped(m);
        if (!escaped)
                return -ENOMEM;

        return sd_bus_message_append_basic(reply, 's', escaped);
}

static int bus_mount_method_remount(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Mount *m = ASSERT_PTR(userdata);
        Unit *u = UNIT(m);
        int r;

        assert(message);

        if (u->load_state != UNIT_LOADED)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "Unit '%s' not loaded", u->id);

        if (u->job || m->remount_context)
                return sd_bus_error_setf(error, BUS_ERROR_UNIT_BUSY,
                                         "Mount '%s' has a job pending or is already being remounted, refusing remount request",
                                         m->where);

        if (m->state != MOUNT_MOUNTED)
                return sd_bus_error_setf(error, BUS_ERROR_UNIT_INACTIVE,
                                         "Cannot remount inactive mount '%s'", m->where);

        r = mac_selinux_unit_access_check(u, message, "start", error);
        if (r < 0)
                return r;

        const char *opts;
        uint64_t flags;

        r = sd_bus_message_read(message, "st", &opts, &flags);
        if (r < 0)
                return r;

        if ((flags & ~REMOUNT_OPTIONS_APPEND) != 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid flags parameter");

        r = bus_verify_manage_units_async_full(u, "remount",
                                               N_("Authentication is required to remount '$(unit)'."),
                                               message,
                                               error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        _cleanup_(remount_context_freep) RemountContext *ctx = new(RemountContext, 1);
        if (!ctx)
                return -ENOMEM;

        *ctx = (RemountContext) {
                .request = sd_bus_message_ref(message),
                .options = strdup(opts),
                .flags = flags,
        };
        if (!ctx->options)
                return -ENOMEM;

        /* The update of parameters_fragment is deferred to mount_reload_finish(), i.e. after the reload job
         * finishes, in an atomic fashion. */
        m->remount_context = TAKE_PTR(ctx);

        r = manager_add_job(u->manager, JOB_RELOAD, u, JOB_REPLACE, error, /* ret = */ NULL);
        if (r < 0) {
                m->remount_context = remount_context_free(m->remount_context);
                return r;
        }

        return 1;
}

const sd_bus_vtable bus_mount_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Where", "s", property_get_where, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("What", "s", property_get_what, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Options", "s", property_get_options, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Type", "s", property_get_type, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("TimeoutUSec", "t", bus_property_get_usec, offsetof(Mount, timeout_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ControlPID", "u", bus_property_get_pid, offsetof(Mount, control_pid.pid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("DirectoryMode", "u", bus_property_get_mode, offsetof(Mount, directory_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SloppyOptions", "b", bus_property_get_bool, offsetof(Mount, sloppy_options), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LazyUnmount", "b", bus_property_get_bool, offsetof(Mount, lazy_unmount), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ForceUnmount", "b", bus_property_get_bool, offsetof(Mount, force_unmount), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ReadWriteOnly", "b", bus_property_get_bool, offsetof(Mount, read_write_only), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Mount, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("ReloadResult", "s", property_get_result, offsetof(Mount, reload_result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("CleanResult", "s", property_get_result, offsetof(Mount, clean_result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("UID", "u", bus_property_get_uid, offsetof(Unit, ref_uid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("GID", "u", bus_property_get_gid, offsetof(Unit, ref_gid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),

        BUS_EXEC_COMMAND_VTABLE("ExecMount", offsetof(Mount, exec_command[MOUNT_EXEC_MOUNT]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_VTABLE("ExecUnmount", offsetof(Mount, exec_command[MOUNT_EXEC_UNMOUNT]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_VTABLE("ExecRemount", offsetof(Mount, exec_command[MOUNT_EXEC_REMOUNT]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),

        SD_BUS_METHOD_WITH_ARGS("Remount",
                                SD_BUS_ARGS("s", options, "t", flags),
                                SD_BUS_NO_RESULT,
                                bus_mount_method_remount,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END
};

static int bus_mount_set_transient_property(
                Mount *m,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        Unit *u = UNIT(m);
        int r;

        assert(m);
        assert(name);
        assert(message);

        flags |= UNIT_PRIVATE;

        if (streq(name, "Where"))
                return bus_set_transient_path(u, name, &m->where, message, flags, error);

        if (streq(name, "What")) {
                _cleanup_free_ char *path = NULL;
                const char *v;

                r = sd_bus_message_read(message, "s", &v);
                if (r < 0)
                        return r;

                if (!isempty(v)) {
                        path = fstab_node_to_udev_node(v);
                        if (!path)
                                return -ENOMEM;

                        /* path_is_valid is not used - see the comment for config_parse_mount_node */
                        if (strlen(path) >= PATH_MAX)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Resolved What=%s too long", path);
                }

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        free_and_replace(m->parameters_fragment.what, path);
                        unit_write_settingf(u, flags|UNIT_ESCAPE_SPECIFIERS, name, "What=%s", strempty(m->parameters_fragment.what));
                }

                return 1;
        }

        if (streq(name, "Options"))
                return bus_set_transient_string(u, name, &m->parameters_fragment.options, message, flags, error);

        if (streq(name, "Type"))
                return bus_set_transient_string(u, name, &m->parameters_fragment.fstype, message, flags, error);

        if (streq(name, "TimeoutUSec"))
                return bus_set_transient_usec_fix_0(u, name, &m->timeout_usec, message, flags, error);

        if (streq(name, "DirectoryMode"))
                return bus_set_transient_mode_t(u, name, &m->directory_mode, message, flags, error);

        if (streq(name, "SloppyOptions"))
                return bus_set_transient_bool(u, name, &m->sloppy_options, message, flags, error);

        if (streq(name, "LazyUnmount"))
                return bus_set_transient_bool(u, name, &m->lazy_unmount, message, flags, error);

        if (streq(name, "ForceUnmount"))
                return bus_set_transient_bool(u, name, &m->force_unmount, message, flags, error);

        if (streq(name, "ReadWriteOnly"))
                return bus_set_transient_bool(u, name, &m->read_write_only, message, flags, error);

        return 0;
}

int bus_mount_set_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        Mount *m = MOUNT(u);
        int r;

        assert(m);
        assert(name);
        assert(message);

        r = bus_cgroup_set_property(u, &m->cgroup_context, name, message, flags, error);
        if (r != 0)
                return r;

        if (u->transient && u->load_state == UNIT_STUB) {
                /* This is a transient unit, let's load a little more */

                r = bus_mount_set_transient_property(m, name, message, flags, error);
                if (r != 0)
                        return r;

                r = bus_exec_context_set_transient_property(u, &m->exec_context, name, message, flags, error);
                if (r != 0)
                        return r;

                r = bus_kill_context_set_transient_property(u, &m->kill_context, name, message, flags, error);
                if (r != 0)
                        return r;
        }

        return 0;
}

int bus_mount_commit_properties(Unit *u) {
        assert(u);

        (void) unit_realize_cgroup(u);

        return 0;
}
