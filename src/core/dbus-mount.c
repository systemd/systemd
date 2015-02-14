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

#include "unit.h"
#include "mount.h"
#include "dbus-execute.h"
#include "dbus-kill.h"
#include "dbus-cgroup.h"
#include "dbus-mount.h"
#include "bus-util.h"

static int property_get_what(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Mount *m = userdata;
        const char *d;

        assert(bus);
        assert(reply);
        assert(m);

        if (m->from_proc_self_mountinfo && m->parameters_proc_self_mountinfo.what)
                d = m->parameters_proc_self_mountinfo.what;
        else if (m->from_fragment && m->parameters_fragment.what)
                d = m->parameters_fragment.what;
        else
                d = "";

        return sd_bus_message_append(reply, "s", d);
}

static int property_get_options(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Mount *m = userdata;
        const char *d;

        assert(bus);
        assert(reply);
        assert(m);

        if (m->from_proc_self_mountinfo && m->parameters_proc_self_mountinfo.options)
                d = m->parameters_proc_self_mountinfo.options;
        else if (m->from_fragment && m->parameters_fragment.options)
                d = m->parameters_fragment.options;
        else
                d = "";

        return sd_bus_message_append(reply, "s", d);
}

static int property_get_type(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Mount *m = userdata;
        const char *d;

        assert(bus);
        assert(reply);
        assert(m);

        if (m->from_proc_self_mountinfo && m->parameters_proc_self_mountinfo.fstype)
                d = m->parameters_proc_self_mountinfo.fstype;
        else if (m->from_fragment && m->parameters_fragment.fstype)
                d = m->parameters_fragment.fstype;
        else
                d = "";

        return sd_bus_message_append(reply, "s", d);
}

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, mount_result, MountResult);

const sd_bus_vtable bus_mount_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Where", "s", NULL, offsetof(Mount, where), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("What", "s", property_get_what, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Options","s", property_get_options, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Type", "s", property_get_type, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("TimeoutUSec", "t", bus_property_get_usec, offsetof(Mount, timeout_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ControlPID", "u", bus_property_get_pid, offsetof(Mount, control_pid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("DirectoryMode", "u", bus_property_get_mode, offsetof(Mount, directory_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SloppyOptions", "b", bus_property_get_bool, offsetof(Mount, sloppy_options), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Mount, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_EXEC_COMMAND_VTABLE("ExecMount", offsetof(Mount, exec_command[MOUNT_EXEC_MOUNT]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_VTABLE("ExecUnmount", offsetof(Mount, exec_command[MOUNT_EXEC_UNMOUNT]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_VTABLE("ExecRemount", offsetof(Mount, exec_command[MOUNT_EXEC_REMOUNT]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_VTABLE_END
};

static int bus_mount_set_transient_property(
                Mount *m,
                const char *name,
                sd_bus_message *message,
                UnitSetPropertiesMode mode,
                sd_bus_error *error) {

        const char *new_property;
        char **property;
        char *p;
        int r;

        assert(m);
        assert(name);
        assert(message);

        if (streq(name, "What"))
                property = &m->parameters_fragment.what;
        else if (streq(name, "Options"))
                property = &m->parameters_fragment.options;
        else if (streq(name, "Type"))
                property = &m->parameters_fragment.fstype;
        else
                return 0;

        r = sd_bus_message_read(message, "s", &new_property);
        if (r < 0)
                return r;

        if (mode != UNIT_CHECK) {
                p = strdup(new_property);
                if (!p)
                        return -ENOMEM;

                free(*property);
                *property = p;
        }

        return 1;
}

int bus_mount_set_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitSetPropertiesMode mode,
                sd_bus_error *error) {

        Mount *m = MOUNT(u);
        int r;

        assert(m);
        assert(name);
        assert(message);

        r = bus_cgroup_set_property(u, &m->cgroup_context, name, message, mode, error);
        if (r != 0)
                return r;

        if (u->transient && u->load_state == UNIT_STUB) {
                /* This is a transient unit, let's load a little more */

                r = bus_mount_set_transient_property(m, name, message, mode, error);
                if (r != 0)
                        return r;

                r = bus_exec_context_set_transient_property(u, &m->exec_context, name, message, mode, error);
                if (r != 0)
                        return r;

                r = bus_kill_context_set_transient_property(u, &m->kill_context, name, message, mode, error);
                if (r != 0)
                        return r;
        }

        return 0;
}

int bus_mount_commit_properties(Unit *u) {
        assert(u);

        unit_update_cgroup_members_masks(u);
        unit_realize_cgroup(u);

        return 0;
}
