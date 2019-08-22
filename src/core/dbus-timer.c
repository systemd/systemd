/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "bus-util.h"
#include "dbus-timer.h"
#include "dbus-util.h"
#include "strv.h"
#include "timer.h"
#include "unit.h"

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

static int property_get_next_elapse_monotonic(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Timer *t = userdata;

        assert(bus);
        assert(reply);
        assert(t);

        return sd_bus_message_append(reply, "t",
                                     (uint64_t) usec_shift_clock(t->next_elapse_monotonic_or_boottime,
                                                                 TIMER_MONOTONIC_CLOCK(t), CLOCK_MONOTONIC));
}

const sd_bus_vtable bus_timer_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Unit", "s", bus_property_get_triggered_unit, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TimersMonotonic", "a(stt)", property_get_monotonic_timers, 0, SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_PROPERTY("TimersCalendar", "a(sst)", property_get_calendar_timers, 0, SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_PROPERTY("OnClockChange", "b", bus_property_get_bool, offsetof(Timer, on_clock_change), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("OnTimezoneChange", "b", bus_property_get_bool, offsetof(Timer, on_timezone_change), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("NextElapseUSecRealtime", "t", bus_property_get_usec, offsetof(Timer, next_elapse_realtime), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("NextElapseUSecMonotonic", "t", property_get_next_elapse_monotonic, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_PROPERTY_DUAL_TIMESTAMP("LastTriggerUSec", offsetof(Timer, last_trigger), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Timer, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("AccuracyUSec", "t", bus_property_get_usec, offsetof(Timer, accuracy_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RandomizedDelayUSec", "t", bus_property_get_usec, offsetof(Timer, random_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Persistent", "b", bus_property_get_bool, offsetof(Timer, persistent), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WakeSystem", "b", bus_property_get_bool, offsetof(Timer, wake_system), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RemainAfterElapse", "b", bus_property_get_bool, offsetof(Timer, remain_after_elapse), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_VTABLE_END
};

static int timer_add_one_monotonic_spec(
                Timer *t,
                const char *name,
                TimerBase base,
                UnitWriteFlags flags,
                usec_t usec,
                sd_bus_error *error) {

        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                char ts[FORMAT_TIMESPAN_MAX];
                TimerValue *v;

                unit_write_settingf(UNIT(t), flags|UNIT_ESCAPE_SPECIFIERS, name,
                                    "%s=%s",
                                    timer_base_to_string(base),
                                    format_timespan(ts, sizeof ts, usec, USEC_PER_MSEC));

                v = new(TimerValue, 1);
                if (!v)
                        return -ENOMEM;

                *v = (TimerValue) {
                        .base = base,
                        .value = usec,
                };

                LIST_PREPEND(value, t->values, v);
        }

        return 1;
}

static int timer_add_one_calendar_spec(
                Timer *t,
                const char *name,
                TimerBase base,
                UnitWriteFlags flags,
                const char *str,
                sd_bus_error *error) {

        _cleanup_(calendar_spec_freep) CalendarSpec *c = NULL;
        int r;

        r = calendar_spec_from_string(str, &c);
        if (r == -EINVAL)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid calendar spec");
        if (r < 0)
                return r;

        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                unit_write_settingf(UNIT(t), flags|UNIT_ESCAPE_SPECIFIERS, name,
                                    "%s=%s", timer_base_to_string(base), str);

                TimerValue *v = new(TimerValue, 1);
                if (!v)
                        return -ENOMEM;

                *v = (TimerValue) {
                        .base = base,
                        .calendar_spec = TAKE_PTR(c),
                };

                LIST_PREPEND(value, t->values, v);
        }

        return 1;
};

static int bus_timer_set_transient_property(
                Timer *t,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        Unit *u = UNIT(t);
        int r;

        assert(t);
        assert(name);
        assert(message);

        flags |= UNIT_PRIVATE;

        if (streq(name, "AccuracyUSec"))
                return bus_set_transient_usec(u, name, &t->accuracy_usec, message, flags, error);

        if (streq(name, "AccuracySec")) {
                log_notice("Client is using obsolete AccuracySec= transient property, please use AccuracyUSec= instead.");
                return bus_set_transient_usec(u, "AccuracyUSec", &t->accuracy_usec, message, flags, error);
        }

        if (streq(name, "RandomizedDelayUSec"))
                return bus_set_transient_usec(u, name, &t->random_usec, message, flags, error);

        if (streq(name, "WakeSystem"))
                return bus_set_transient_bool(u, name, &t->wake_system, message, flags, error);

        if (streq(name, "Persistent"))
                return bus_set_transient_bool(u, name, &t->persistent, message, flags, error);

        if (streq(name, "RemainAfterElapse"))
                return bus_set_transient_bool(u, name, &t->remain_after_elapse, message, flags, error);

        if (streq(name, "OnTimezoneChange"))
                return bus_set_transient_bool(u, name, &t->on_timezone_change, message, flags, error);

        if (streq(name, "OnClockChange"))
                return bus_set_transient_bool(u, name, &t->on_clock_change, message, flags, error);

        if (streq(name, "TimersMonotonic")) {
                const char *base_name;
                usec_t usec;
                bool empty = true;

                r = sd_bus_message_enter_container(message, 'a', "(st)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "(st)", &base_name, &usec)) > 0) {
                        TimerBase b;

                        b = timer_base_from_string(base_name);
                        if (b < 0 || b == TIMER_CALENDAR)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                         "Invalid timer base: %s", base_name);

                        r = timer_add_one_monotonic_spec(t, name, b, flags, usec, error);
                        if (r < 0)
                                return r;

                        empty = false;
                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags) && empty) {
                        timer_free_values(t);
                        unit_write_setting(u, flags, name, "OnActiveSec=");
                }

                return 1;

        } else if (streq(name, "TimersCalendar")) {
                const char *base_name, *str;
                bool empty = true;

                r = sd_bus_message_enter_container(message, 'a', "(ss)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "(ss)", &base_name, &str)) > 0) {
                        TimerBase b;

                        b = timer_base_from_string(base_name);
                        if (b != TIMER_CALENDAR)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                         "Invalid timer base: %s", base_name);

                        r = timer_add_one_calendar_spec(t, name, b, flags, str, error);
                        if (r < 0)
                                return r;

                        empty = false;
                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags) && empty) {
                        timer_free_values(t);
                        unit_write_setting(u, flags, name, "OnCalendar=");
                }

                return 1;

        } else if (STR_IN_SET(name,
                       "OnActiveSec",
                       "OnBootSec",
                       "OnStartupSec",
                       "OnUnitActiveSec",
                       "OnUnitInactiveSec")) {

                TimerBase b;
                usec_t usec;

                log_notice("Client is using obsolete %s= transient property, please use TimersMonotonic= instead.", name);

                b = timer_base_from_string(name);
                if (b < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown timer base");

                r = sd_bus_message_read(message, "t", &usec);
                if (r < 0)
                        return r;

                return timer_add_one_monotonic_spec(t, name, b, flags, usec, error);

        } else if (streq(name, "OnCalendar")) {

                const char *str;

                log_notice("Client is using obsolete %s= transient property, please use TimersCalendar= instead.", name);

                r = sd_bus_message_read(message, "s", &str);
                if (r < 0)
                        return r;

                return timer_add_one_calendar_spec(t, name, TIMER_CALENDAR, flags, str, error);
        }

        return 0;
}

int bus_timer_set_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags mode,
                sd_bus_error *error) {

        Timer *t = TIMER(u);

        assert(t);
        assert(name);
        assert(message);

        if (u->transient && u->load_state == UNIT_STUB)
                return bus_timer_set_transient_property(t, name, message, mode, error);

        return 0;
}
