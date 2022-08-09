/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-get-properties.h"
#include "dbus-path.h"
#include "dbus-util.h"
#include "list.h"
#include "path.h"
#include "path-util.h"
#include "string-util.h"
#include "unit.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, path_result, PathResult);

static int property_get_paths(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Path *p = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "(ss)");
        if (r < 0)
                return r;

        LIST_FOREACH(spec, k, p->specs) {
                r = sd_bus_message_append(reply, "(ss)", path_type_to_string(k->type), k->path);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

const sd_bus_vtable bus_path_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Unit", "s", bus_property_get_triggered_unit, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Paths", "a(ss)", property_get_paths, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MakeDirectory", "b", bus_property_get_bool, offsetof(Path, make_directory), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DirectoryMode", "u", bus_property_get_mode, offsetof(Path, directory_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Path, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("TriggerLimitIntervalUSec", "t", bus_property_get_usec, offsetof(Path, trigger_limit.interval), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TriggerLimitBurst", "u", bus_property_get_unsigned, offsetof(Path, trigger_limit.burst), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_VTABLE_END
};

static int bus_path_set_transient_property(
                Path *p,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        Unit *u = UNIT(p);
        int r;

        assert(p);
        assert(name);
        assert(message);

        flags |= UNIT_PRIVATE;

        if (streq(name, "MakeDirectory"))
                return bus_set_transient_bool(u, name, &p->make_directory, message, flags, error);

        if (streq(name, "DirectoryMode"))
                return bus_set_transient_mode_t(u, name, &p->directory_mode, message, flags, error);

        if (streq(name, "Paths")) {
                const char *type_name, *path;
                bool empty = true;

                r = sd_bus_message_enter_container(message, 'a', "(ss)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "(ss)", &type_name, &path)) > 0) {
                        PathType t;

                        t = path_type_from_string(type_name);
                        if (t < 0)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown path type: %s", type_name);

                        if (isempty(path))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Path in %s is empty", type_name);

                        if (!path_is_absolute(path))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Path in %s is not absolute: %s", type_name, path);

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                _cleanup_free_ char *k = NULL;
                                PathSpec *s;

                                k = strdup(path);
                                if (!k)
                                        return -ENOMEM;

                                path_simplify(k);

                                s = new0(PathSpec, 1);
                                if (!s)
                                        return -ENOMEM;

                                s->unit = u;
                                s->path = TAKE_PTR(k);
                                s->type = t;
                                s->inotify_fd = -1;

                                LIST_PREPEND(spec, p->specs, s);

                                unit_write_settingf(u, flags|UNIT_ESCAPE_SPECIFIERS, name, "%s=%s", type_name, path);
                        }

                        empty = false;
                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags) && empty) {
                        path_free_specs(p);
                        unit_write_settingf(u, flags, name, "PathExists=");
                }

                return 1;
        }

        if (streq(name, "TriggerLimitBurst"))
                return bus_set_transient_unsigned(u, name, &p->trigger_limit.burst, message, flags, error);

        if (streq(name, "TriggerLimitIntervalUSec"))
                return bus_set_transient_usec(u, name, &p->trigger_limit.interval, message, flags, error);

        return 0;
}

int bus_path_set_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags mode,
                sd_bus_error *error) {

        Path *p = PATH(u);

        assert(p);
        assert(name);
        assert(message);

        if (u->transient && u->load_state == UNIT_STUB)
                return bus_path_set_transient_property(p, name, message, mode, error);

        return 0;
}
