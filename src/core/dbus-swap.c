/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2010 Maarten Lankhorst

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
#include "swap.h"
#include "dbus-unit.h"
#include "dbus-execute.h"
#include "dbus-kill.h"
#include "dbus-cgroup.h"
#include "dbus-swap.h"
#include "bus-util.h"

static int property_get_priority(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Swap *s = SWAP(userdata);
        int p;

        assert(bus);
        assert(reply);
        assert(s);

        if (s->from_proc_swaps)
                p = s->parameters_proc_swaps.priority;
        else if (s->from_fragment)
                p = s->parameters_fragment.priority;
        else
                p = -1;

        return sd_bus_message_append(reply, "i", p);
}

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, swap_result, SwapResult);

const sd_bus_vtable bus_swap_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("What", "s", NULL, offsetof(Swap, what), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Priority", "i", property_get_priority, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("TimeoutUSec", "t", bus_property_get_usec, offsetof(Swap, timeout_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ControlPID", "u", bus_property_get_pid, offsetof(Swap, control_pid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Swap, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_EXEC_COMMAND_VTABLE("ExecActivate", offsetof(Swap, exec_command[SWAP_EXEC_ACTIVATE]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_VTABLE("ExecDeactivate", offsetof(Swap, exec_command[SWAP_EXEC_DEACTIVATE]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_VTABLE_END
};

int bus_swap_set_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitSetPropertiesMode mode,
                sd_bus_error *error) {

        Swap *s = SWAP(u);

        assert(s);
        assert(name);
        assert(message);

        return bus_cgroup_set_property(u, &s->cgroup_context, name, message, mode, error);
}

int bus_swap_commit_properties(Unit *u) {
        assert(u);

        unit_update_cgroup_members_masks(u);
        unit_realize_cgroup(u);

        return 0;
}
