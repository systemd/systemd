/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dbus-cgroup.h"
#include "dbus-slice.h"
#include "slice.h"
#include "unit.h"

const sd_bus_vtable bus_slice_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_VTABLE_END
};

int bus_slice_set_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        Slice *s = SLICE(u);

        assert(name);
        assert(u);

        return bus_cgroup_set_property(u, &s->cgroup_context, name, message, flags, error);
}

int bus_slice_commit_properties(Unit *u) {
        assert(u);

        unit_realize_cgroup(u);

        return 0;
}
