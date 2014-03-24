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
#include "timer.h"
#include "dbus-unit.h"
#include "dbus-timer.h"
#include "bus-util.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, timer_result, TimerResult);

static int property_get_monotonic_timers(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Timer *t = userdata;
        TimerValue *v;
        int r;

        assert(bus);
        assert(reply);
        assert(t);

        r = sd_bus_message_open_container(reply, 'a', "(stt)");
        if (r < 0)
                return r;

        LIST_FOREACH(value, v, t->values) {
                _cleanup_free_ char *buf = NULL;
                const char *s;
                size_t l;

                if (v->base == TIMER_CALENDAR)
                        continue;

                s = timer_base_to_string(v->base);
                assert(endswith(s, "Sec"));

                /* s/Sec/USec/ */
                l = strlen(s);
                buf = new(char, l+2);
                if (!buf)
                        return -ENOMEM;

                memcpy(buf, s, l-3);
                memcpy(buf+l-3, "USec", 5);

                r = sd_bus_message_append(reply, "(stt)", buf, v->value, v->next_elapse);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_calendar_timers(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Timer *t = userdata;
        TimerValue *v;
        int r;

        assert(bus);
        assert(reply);
        assert(t);

        r = sd_bus_message_open_container(reply, 'a', "(sst)");
        if (r < 0)
                return r;

        LIST_FOREACH(value, v, t->values) {
                _cleanup_free_ char *buf = NULL;

                if (v->base != TIMER_CALENDAR)
                        continue;

                r = calendar_spec_to_string(v->calendar_spec, &buf);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(reply, "(sst)", timer_base_to_string(v->base), buf, v->next_elapse);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_unit(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *u = userdata, *trigger;

        assert(bus);
        assert(reply);
        assert(u);

        trigger = UNIT_TRIGGER(u);

        return sd_bus_message_append(reply, "s", trigger ? trigger->id : "");
}

static int property_get_next_elapse_monotonic(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Timer *t = userdata;
        usec_t x;

        assert(bus);
        assert(reply);
        assert(t);

        if (t->next_elapse_monotonic_or_boottime <= 0)
                x = 0;
        else if (t->wake_system) {
                usec_t a, b;

                a = now(CLOCK_MONOTONIC);
                b = now(CLOCK_BOOTTIME);

                if (t->next_elapse_monotonic_or_boottime + a > b)
                        x = t->next_elapse_monotonic_or_boottime + a - b;
                else
                        x = 0;
        } else
                x = t->next_elapse_monotonic_or_boottime;

        return sd_bus_message_append(reply, "t", x);
}

const sd_bus_vtable bus_timer_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Unit", "s", property_get_unit, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TimersMonotonic", "a(stt)", property_get_monotonic_timers, 0, SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_PROPERTY("TimersCalendar", "a(sst)", property_get_calendar_timers, 0, SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_PROPERTY("NextElapseUSecRealtime", "t", bus_property_get_usec, offsetof(Timer, next_elapse_realtime), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("NextElapseUSecMonotonic", "t", property_get_next_elapse_monotonic, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_PROPERTY_DUAL_TIMESTAMP("LastTriggerUSec", offsetof(Timer, last_trigger), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Timer, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("AccuracyUSec", "t", bus_property_get_usec, offsetof(Timer, accuracy_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Persistent", "b", bus_property_get_bool, offsetof(Timer, persistent), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WakeSystem", "b", bus_property_get_bool, offsetof(Timer, wake_system), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_VTABLE_END
};
