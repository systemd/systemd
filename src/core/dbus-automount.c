/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "automount.h"
#include "bus-get-properties.h"
#include "dbus-automount.h"
#include "dbus-util.h"
#include "string-util.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, automount_result, AutomountResult);

const sd_bus_vtable bus_automount_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Where", "s", NULL, offsetof(Automount, where), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ExtraOptions", "s", NULL, offsetof(Automount, extra_options), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DirectoryMode", "u", bus_property_get_mode, offsetof(Automount, directory_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Automount, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("TimeoutIdleUSec", "t", bus_property_get_usec, offsetof(Automount, timeout_idle_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_VTABLE_END
};

static int bus_automount_set_transient_property(
                Automount *a,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        Unit *u = UNIT(a);

        assert(a);
        assert(name);
        assert(message);

        flags |= UNIT_PRIVATE;

        if (streq(name, "Where"))
                return bus_set_transient_path(u, name, &a->where, message, flags, error);

        if (streq(name, "ExtraOptions"))
                return bus_set_transient_string(u, name, &a->extra_options, message, flags, error);

        if (streq(name, "TimeoutIdleUSec"))
                return bus_set_transient_usec_fix_0(u, name, &a->timeout_idle_usec, message, flags, error);

        if (streq(name, "DirectoryMode"))
                return bus_set_transient_mode_t(u, name, &a->directory_mode, message, flags, error);

        return 0;
}

int bus_automount_set_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        Automount *a = AUTOMOUNT(u);

        assert(a);
        assert(name);
        assert(message);

        if (u->transient && u->load_state == UNIT_STUB) /* This is a transient unit? let's load a little more */
                return bus_automount_set_transient_property(a, name, message, flags, error);

        return 0;
}
