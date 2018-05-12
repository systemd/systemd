/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2010 Maarten Lankhorst
***/

#include "bus-util.h"
#include "dbus-cgroup.h"
#include "dbus-execute.h"
#include "dbus-swap.h"
#include "string-util.h"
#include "swap.h"
#include "unit.h"

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

static int property_get_options(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Swap *s = SWAP(userdata);
        const char *options = NULL;

        assert(bus);
        assert(reply);
        assert(s);

        if (s->from_fragment)
                options = s->parameters_fragment.options;

        return sd_bus_message_append(reply, "s", options);
}

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, swap_result, SwapResult);

const sd_bus_vtable bus_swap_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("What", "s", NULL, offsetof(Swap, what), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Priority", "i", property_get_priority, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Options", "s", property_get_options, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("TimeoutUSec", "t", bus_property_get_usec, offsetof(Swap, timeout_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ControlPID", "u", bus_property_get_pid, offsetof(Swap, control_pid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Swap, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("UID", "u", bus_property_get_uid, offsetof(Unit, ref_uid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("GID", "u", bus_property_get_gid, offsetof(Unit, ref_gid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_EXEC_COMMAND_VTABLE("ExecActivate", offsetof(Swap, exec_command[SWAP_EXEC_ACTIVATE]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        BUS_EXEC_COMMAND_VTABLE("ExecDeactivate", offsetof(Swap, exec_command[SWAP_EXEC_DEACTIVATE]), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_VTABLE_END
};

int bus_swap_set_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        Swap *s = SWAP(u);

        assert(s);
        assert(name);
        assert(message);

        return bus_cgroup_set_property(u, &s->cgroup_context, name, message, flags, error);
}

int bus_swap_commit_properties(Unit *u) {
        assert(u);

        unit_update_cgroup_members_masks(u);
        unit_realize_cgroup(u);

        return 0;
}
