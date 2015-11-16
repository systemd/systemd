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

#include "bus-util.h"
#include "dbus-path.h"
#include "path.h"
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
