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

#include "automount.h"
#include "bus-util.h"
#include "dbus-automount.h"
#include "string-util.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, automount_result, AutomountResult);

const sd_bus_vtable bus_automount_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Where", "s", NULL, offsetof(Automount, where), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DirectoryMode", "u", bus_property_get_mode, offsetof(Automount, directory_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Automount, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("TimeoutIdleUSec", "t", bus_property_get_usec, offsetof(Automount, timeout_idle_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_VTABLE_END
};

static int bus_automount_set_transient_property(
                Automount *a,
                const char *name,
                sd_bus_message *message,
                UnitSetPropertiesMode mode,
                sd_bus_error *error) {

        int r;

        assert(a);
        assert(name);
        assert(message);

        if (streq(name, "TimeoutIdleUSec")) {
                usec_t timeout_idle_usec;
                r = sd_bus_message_read(message, "t", &timeout_idle_usec);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        char time[FORMAT_TIMESPAN_MAX];

                        a->timeout_idle_usec = timeout_idle_usec;
                        unit_write_drop_in_format(UNIT(a), mode, name, "[Automount]\nTimeoutIdleSec=%s\n",
                                format_timespan(time, sizeof(time), timeout_idle_usec, USEC_PER_MSEC));
                }
        } else
                return 0;

        return 1;
}

int bus_automount_set_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitSetPropertiesMode mode,
                sd_bus_error *error) {

        Automount *a = AUTOMOUNT(u);
        int r = 0;

        assert(a);
        assert(name);
        assert(message);

        if (u->transient && u->load_state == UNIT_STUB)
                /* This is a transient unit, let's load a little more */

                r = bus_automount_set_transient_property(a, name, message, mode, error);

        return r;
}
