/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <errno.h>
#include <dbus/dbus.h>

#include "dbus-kill.h"
#include "dbus-common.h"

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_kill_append_mode, kill_mode, KillMode);

const BusProperty bus_kill_context_properties[] = {
        { "KillMode",    bus_kill_append_mode,     "s", offsetof(KillContext, kill_mode)    },
        { "KillSignal",  bus_property_append_int,  "i", offsetof(KillContext, kill_signal)  },
        { "SendSIGKILL", bus_property_append_bool, "b", offsetof(KillContext, send_sigkill) },
        { "SendSIGHUP",  bus_property_append_bool, "b", offsetof(KillContext, send_sighup)  },
        {}
};

int bus_kill_context_set_transient_property(
                Unit *u,
                KillContext *c,
                const char *name,
                DBusMessageIter *i,
                UnitSetPropertiesMode mode,
                DBusError *error) {

        assert(u);
        assert(c);
        assert(name);
        assert(i);

        if (streq(name, "KillMode")) {
                const char *m;
                KillMode k;

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_STRING)
                        return -EINVAL;

                dbus_message_iter_get_basic(i, &m);

                k = kill_mode_from_string(m);
                if (k < 0)
                        return -EINVAL;

                if (mode != UNIT_CHECK) {
                        c->kill_mode = k;

                        unit_write_drop_in_private_format(u, mode, name, "KillMode=%s\n", kill_mode_to_string(k));
                }

                return 1;

        } else if (streq(name, "SendSIGHUP")) {

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_BOOLEAN)
                        return -EINVAL;

                if (mode != UNIT_CHECK) {
                        dbus_bool_t b;

                        dbus_message_iter_get_basic(i, &b);
                        c->send_sighup = b;

                        unit_write_drop_in_private_format(u, mode, name, "SendSIGHUP=%s\n", yes_no(b));
                }

                return 1;

        } else if (streq(name, "SendSIGKILL")) {

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_BOOLEAN)
                        return -EINVAL;

                if (mode != UNIT_CHECK) {
                        dbus_bool_t b;

                        dbus_message_iter_get_basic(i, &b);
                        c->send_sigkill = b;

                        unit_write_drop_in_private_format(u, mode, name, "SendSIGKILL=%s\n", yes_no(b));
                }

                return 1;

        }

        return 0;
}
