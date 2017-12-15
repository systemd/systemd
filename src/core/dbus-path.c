/* SPDX-License-Identifier: LGPL-2.1+ */
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

#include "alloc-util.h"
#include "bus-util.h"
#include "dbus-path.h"
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

        Path *p = userdata;
        PathSpec *k;
        int r;

        assert(bus);
        assert(reply);
        assert(p);

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

static int property_get_unit(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *p = userdata, *trigger;

        assert(bus);
        assert(reply);
        assert(p);

        trigger = UNIT_TRIGGER(p);

        return sd_bus_message_append(reply, "s", trigger ? trigger->id : "");
}

const sd_bus_vtable bus_path_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Unit", "s", property_get_unit, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Paths", "a(ss)", property_get_paths, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MakeDirectory", "b", bus_property_get_bool, offsetof(Path, make_directory), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DirectoryMode", "u", bus_property_get_mode, offsetof(Path, directory_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Path, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
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

        if (STR_IN_SET(name, "PathExists", "PathExistsGlob", "PathChanged", "PathModified", "DirectoryNotEmpty")) {
                const char *str;
                PathType b;

                b = path_type_from_string(name);
                if (b < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown path type");

                r = sd_bus_message_read(message, "s", &str);
                if (r < 0)
                        return r;

                if (!isempty(str) && !path_is_absolute(str))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Path is not absolute");

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        if (isempty(str)) {
                                path_free_specs(p);
                                unit_write_settingf(u, flags, name, "%s=", name);
                        } else {
                                _cleanup_free_ char *k;
                                PathSpec *s;

                                k = strdup(str);
                                if (!k)
                                        return -ENOMEM;

                                s = new0(PathSpec, 1);
                                if (!s)
                                        return -ENOMEM;

                                s->unit = u;
                                s->path = path_kill_slashes(k);
                                k = NULL;
                                s->type = b;
                                s->inotify_fd = -1;

                                LIST_PREPEND(spec, p->specs, s);

                                unit_write_settingf(u, flags|UNIT_ESCAPE_SPECIFIERS, name, "%s=%s", name, str);
                        }
                }

                return 1;

        } else if (streq(name, "MakeDirectory")) {
                int b;

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        p->make_directory = b;
                        unit_write_settingf(u, flags, name, "%s=%s", name, yes_no(b));
                }

                return 1;

        } else if (streq(name, "DirectoryMode")) {
                mode_t m;

                r = sd_bus_message_read(message, "u", &m);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        p->directory_mode = m;
                        unit_write_settingf(u, flags, name, "%s=%040o", name, m);
                }

                return 1;

        } else if (streq(name, "Unit")) {
                /* not implemented yet */
                return 0;
        }

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
