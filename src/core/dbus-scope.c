/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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
#include "scope.h"
#include "dbus-unit.h"
#include "dbus-cgroup.h"
#include "dbus-kill.h"
#include "dbus-scope.h"
#include "bus-util.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, scope_result, ScopeResult);

const sd_bus_vtable bus_scope_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("TimeoutStopUSec", "t", bus_property_get_usec, offsetof(Scope, timeout_stop_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Scope, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_VTABLE_END
};

static int bus_scope_set_transient_property(
                Scope *s,
                const char *name,
                sd_bus_message *message,
                UnitSetPropertiesMode mode,
                sd_bus_error *error) {

        int r;

        assert(s);
        assert(name);
        assert(message);

        if (streq(name, "PIDs")) {
                unsigned n = 0;
                uint32_t pid;

                r = set_ensure_allocated(&s->pids, trivial_hash_func, trivial_compare_func);
                if (r < 0)
                        return r;

                r = sd_bus_message_enter_container(message, 'a', "u");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "u", &pid)) > 0) {

                        if (pid <= 1)
                                return -EINVAL;

                        if (mode != UNIT_CHECK) {
                                r = set_put(s->pids, LONG_TO_PTR(pid));
                                if (r < 0 && r != -EEXIST)
                                        return r;
                        }

                        n++;
                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (n <= 0)
                        return -EINVAL;

                return 1;

        } else if (streq(name, "TimeoutStopUSec")) {

                if (mode != UNIT_CHECK) {
                        r = sd_bus_message_read(message, "t", &s->timeout_stop_usec);
                        if (r < 0)
                                return r;

                        unit_write_drop_in_format(UNIT(s), mode, name, "[Scope]\nTimeoutStopSec=%lluus\n", (unsigned long long) s->timeout_stop_usec);
                } else {
                        r = sd_bus_message_skip(message, "t");
                        if (r < 0)
                                return r;
                }

                return 1;
        }

        return 0;
}

int bus_scope_set_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitSetPropertiesMode mode,
                sd_bus_error *error) {

        Scope *s = SCOPE(u);
        int r;

        assert(s);
        assert(name);
        assert(message);

        r = bus_cgroup_set_property(u, &s->cgroup_context, name, message, mode, error);
        if (r != 0)
                return r;

        if (u->load_state == UNIT_STUB) {
                /* While we are created we still accept PIDs */

                r = bus_scope_set_transient_property(s, name, message, mode, error);
                if (r != 0)
                        return r;

                r = bus_kill_context_set_transient_property(u, &s->kill_context, name, message, mode, error);
                if (r != 0)
                        return r;
        }

        return 0;
}

int bus_scope_commit_properties(Unit *u) {
        assert(u);

        unit_realize_cgroup(u);
        return 0;
}
