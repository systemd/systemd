/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2010 Maarten Lankhorst
***/

#include "bus-get-properties.h"
#include "dbus-cgroup.h"
#include "dbus-execute.h"
#include "dbus-swap.h"
#include "string-util.h"
#include "swap.h"
#include "unit.h"

static BUS_DEFINE_PROPERTY_GET(property_get_priority, "i", Swap, swap_get_priority);
static BUS_DEFINE_PROPERTY_GET(property_get_options, "s", Swap, swap_get_options);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, swap_result, SwapResult);

const sd_bus_vtable bus_swap_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("What", "s", NULL, offsetof(Swap, what), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Priority", "i", property_get_priority, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Options", "s", property_get_options, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("TimeoutUSec", "t", bus_property_get_usec, offsetof(Swap, timeout_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ControlPID", "u", bus_property_get_pid, offsetof(Swap, control_pid.pid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
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

        (void) unit_realize_cgroup(u);

        return 0;
}
