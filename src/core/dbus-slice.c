/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-get-properties.h"
#include "dbus-cgroup.h"
#include "dbus-slice.h"
#include "dbus-util.h"
#include "slice.h"
#include "string-util.h"
#include "unit.h"

static int property_get_currently_active(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Slice *s = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(
                        reply,
                        "u",
                        (uint32_t) slice_get_currently_active(s, /* ignore= */ NULL, /* with_pending= */ false));
}

const sd_bus_vtable bus_slice_vtable[] = {
        SD_BUS_VTABLE_START(0),
        /* The following are currently constant, but we should change that eventually (i.e. open them up via
         * systemctl set-property), hence they aren't marked as constant */
        SD_BUS_PROPERTY("ConcurrencyHardMax", "u", bus_property_get_unsigned, offsetof(Slice, concurrency_hard_max), 0),
        SD_BUS_PROPERTY("ConcurrencySoftMax", "u", bus_property_get_unsigned, offsetof(Slice, concurrency_soft_max), 0),
        SD_BUS_PROPERTY("NCurrentlyActive", "u", property_get_currently_active, 0, 0),
        SD_BUS_VTABLE_END
};

static int bus_slice_set_transient_property(
                Slice *s,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        Unit *u = UNIT(s);

        assert(s);
        assert(name);
        assert(message);

        flags |= UNIT_PRIVATE;

        if (streq(name, "ConcurrencyHardMax"))
                return bus_set_transient_unsigned(u, name, &s->concurrency_hard_max, message, flags, error);

        if (streq(name, "ConcurrencySoftMax"))
                return bus_set_transient_unsigned(u, name, &s->concurrency_soft_max, message, flags, error);

        return 0;
}

int bus_slice_set_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        Slice *s = SLICE(u);
        int r;

        assert(name);
        assert(u);

        r = bus_cgroup_set_property(u, &s->cgroup_context, name, message, flags, error);
        if (r != 0)
                return r;

        if (u->transient && u->load_state == UNIT_STUB) {
                /* This is a transient unit, let's allow a little more */

                r = bus_slice_set_transient_property(s, name, message, flags, error);
                if (r != 0)
                        return r;
        }

        return 0;
}

int bus_slice_commit_properties(Unit *u) {
        assert(u);

        (void) unit_realize_cgroup(u);

        return 0;
}
