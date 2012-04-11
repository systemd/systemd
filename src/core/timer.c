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

#include <errno.h>

#include "unit.h"
#include "unit-name.h"
#include "timer.h"
#include "dbus-timer.h"
#include "special.h"
#include "bus-errors.h"

static const UnitActiveState state_translation_table[_TIMER_STATE_MAX] = {
        [TIMER_DEAD] = UNIT_INACTIVE,
        [TIMER_WAITING] = UNIT_ACTIVE,
        [TIMER_RUNNING] = UNIT_ACTIVE,
        [TIMER_ELAPSED] = UNIT_ACTIVE,
        [TIMER_FAILED] = UNIT_FAILED
};

static void timer_init(Unit *u) {
        Timer *t = TIMER(u);

        assert(u);
        assert(u->load_state == UNIT_STUB);

        t->next_elapse = (usec_t) -1;
}

static void timer_done(Unit *u) {
        Timer *t = TIMER(u);
        TimerValue *v;

        assert(t);

        while ((v = t->values)) {
                LIST_REMOVE(TimerValue, value, t->values, v);
                free(v);
        }

        unit_unwatch_timer(u, &t->timer_watch);

        unit_ref_unset(&t->unit);
}

static int timer_verify(Timer *t) {
        assert(t);

        if (UNIT(t)->load_state != UNIT_LOADED)
                return 0;

        if (!t->values) {
                log_error("%s lacks value setting. Refusing.", UNIT(t)->id);
                return -EINVAL;
        }

        return 0;
}

static int timer_add_default_dependencies(Timer *t) {
        int r;

        assert(t);

        if (UNIT(t)->manager->running_as == MANAGER_SYSTEM) {
                if ((r = unit_add_dependency_by_name(UNIT(t), UNIT_BEFORE, SPECIAL_BASIC_TARGET, NULL, true)) < 0)
                        return r;

                if ((r = unit_add_two_dependencies_by_name(UNIT(t), UNIT_AFTER, UNIT_REQUIRES, SPECIAL_SYSINIT_TARGET, NULL, true)) < 0)
                        return r;
        }

        return unit_add_two_dependencies_by_name(UNIT(t), UNIT_BEFORE, UNIT_CONFLICTS, SPECIAL_SHUTDOWN_TARGET, NULL, true);
}

static int timer_load(Unit *u) {
        Timer *t = TIMER(u);
        int r;

        assert(u);
        assert(u->load_state == UNIT_STUB);

        if ((r = unit_load_fragment_and_dropin(u)) < 0)
                return r;

        if (u->load_state == UNIT_LOADED) {

                if (!UNIT_DEREF(t->unit)) {
                        Unit *x;

                        r = unit_load_related_unit(u, ".service", &x);
                        if (r < 0)
                                return r;

                        unit_ref_set(&t->unit, x);
                }

                r = unit_add_two_dependencies(u, UNIT_BEFORE, UNIT_TRIGGERS, UNIT_DEREF(t->unit), true);
                if (r < 0)
                        return r;

                if (UNIT(t)->default_dependencies)
                        if ((r = timer_add_default_dependencies(t)) < 0)
                                return r;
        }

        return timer_verify(t);
}

static void timer_dump(Unit *u, FILE *f, const char *prefix) {
        Timer *t = TIMER(u);
        TimerValue *v;
        char
                timespan1[FORMAT_TIMESPAN_MAX];

        fprintf(f,
                "%sTimer State: %s\n"
                "%sResult: %s\n"
                "%sUnit: %s\n",
                prefix, timer_state_to_string(t->state),
                prefix, timer_result_to_string(t->result),
                prefix, UNIT_DEREF(t->unit)->id);

        LIST_FOREACH(value, v, t->values)
                fprintf(f,
                        "%s%s: %s\n",
                        prefix,
                        timer_base_to_string(v->base),
                        strna(format_timespan(timespan1, sizeof(timespan1), v->value)));
}

static void timer_set_state(Timer *t, TimerState state) {
        TimerState old_state;
        assert(t);

        old_state = t->state;
        t->state = state;

        if (state != TIMER_WAITING)
                unit_unwatch_timer(UNIT(t), &t->timer_watch);

        if (state != old_state)
                log_debug("%s changed %s -> %s",
                          UNIT(t)->id,
                          timer_state_to_string(old_state),
                          timer_state_to_string(state));

        unit_notify(UNIT(t), state_translation_table[old_state], state_translation_table[state], true);
}

static void timer_enter_waiting(Timer *t, bool initial);

static int timer_coldplug(Unit *u) {
        Timer *t = TIMER(u);

        assert(t);
        assert(t->state == TIMER_DEAD);

        if (t->deserialized_state != t->state) {

                if (t->deserialized_state == TIMER_WAITING)
                        timer_enter_waiting(t, false);
                else
                        timer_set_state(t, t->deserialized_state);
        }

        return 0;
}

static void timer_enter_dead(Timer *t, TimerResult f) {
        assert(t);

        if (f != TIMER_SUCCESS)
                t->result = f;

        timer_set_state(t, t->result != TIMER_SUCCESS ? TIMER_FAILED : TIMER_DEAD);
}

static void timer_enter_waiting(Timer *t, bool initial) {
        TimerValue *v;
        usec_t base = 0, delay, n;
        bool found = false;
        int r;

        n = now(CLOCK_MONOTONIC);

        LIST_FOREACH(value, v, t->values) {

                if (v->disabled)
                        continue;

                switch (v->base) {

                case TIMER_ACTIVE:
                        if (state_translation_table[t->state] == UNIT_ACTIVE)
                                base = UNIT(t)->inactive_exit_timestamp.monotonic;
                        else
                                base = n;
                        break;

                case TIMER_BOOT:
                        /* CLOCK_MONOTONIC equals the uptime on Linux */
                        base = 0;
                        break;

                case TIMER_STARTUP:
                        base = UNIT(t)->manager->startup_timestamp.monotonic;
                        break;

                case TIMER_UNIT_ACTIVE:

                        if (UNIT_DEREF(t->unit)->inactive_exit_timestamp.monotonic <= 0)
                                continue;

                        base = UNIT_DEREF(t->unit)->inactive_exit_timestamp.monotonic;
                        break;

                case TIMER_UNIT_INACTIVE:

                        if (UNIT_DEREF(t->unit)->inactive_enter_timestamp.monotonic <= 0)
                                continue;

                        base = UNIT_DEREF(t->unit)->inactive_enter_timestamp.monotonic;
                        break;

                default:
                        assert_not_reached("Unknown timer base");
                }

                v->next_elapse = base + v->value;

                if (!initial && v->next_elapse < n) {
                        v->disabled = true;
                        continue;
                }

                if (!found)
                        t->next_elapse = v->next_elapse;
                else
                        t->next_elapse = MIN(t->next_elapse, v->next_elapse);

                found = true;
        }

        if (!found) {
                timer_set_state(t, TIMER_ELAPSED);
                return;
        }

        delay = n < t->next_elapse ? t->next_elapse - n : 0;

        if ((r = unit_watch_timer(UNIT(t), delay, &t->timer_watch)) < 0)
                goto fail;

        timer_set_state(t, TIMER_WAITING);
        return;

fail:
        log_warning("%s failed to enter waiting state: %s", UNIT(t)->id, strerror(-r));
        timer_enter_dead(t, TIMER_FAILURE_RESOURCES);
}

static void timer_enter_running(Timer *t) {
        DBusError error;
        int r;

        assert(t);
        dbus_error_init(&error);

        /* Don't start job if we are supposed to go down */
        if (UNIT(t)->job && UNIT(t)->job->type == JOB_STOP)
                return;

        if ((r = manager_add_job(UNIT(t)->manager, JOB_START, UNIT_DEREF(t->unit), JOB_REPLACE, true, &error, NULL)) < 0)
                goto fail;

        timer_set_state(t, TIMER_RUNNING);
        return;

fail:
        log_warning("%s failed to queue unit startup job: %s", UNIT(t)->id, bus_error(&error, r));
        timer_enter_dead(t, TIMER_FAILURE_RESOURCES);

        dbus_error_free(&error);
}

static int timer_start(Unit *u) {
        Timer *t = TIMER(u);

        assert(t);
        assert(t->state == TIMER_DEAD || t->state == TIMER_FAILED);

        if (UNIT_DEREF(t->unit)->load_state != UNIT_LOADED)
                return -ENOENT;

        t->result = TIMER_SUCCESS;
        timer_enter_waiting(t, true);
        return 0;
}

static int timer_stop(Unit *u) {
        Timer *t = TIMER(u);

        assert(t);
        assert(t->state == TIMER_WAITING || t->state == TIMER_RUNNING || t->state == TIMER_ELAPSED);

        timer_enter_dead(t, TIMER_SUCCESS);
        return 0;
}

static int timer_serialize(Unit *u, FILE *f, FDSet *fds) {
        Timer *t = TIMER(u);

        assert(u);
        assert(f);
        assert(fds);

        unit_serialize_item(u, f, "state", timer_state_to_string(t->state));
        unit_serialize_item(u, f, "result", timer_result_to_string(t->result));

        return 0;
}

static int timer_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Timer *t = TIMER(u);

        assert(u);
        assert(key);
        assert(value);
        assert(fds);

        if (streq(key, "state")) {
                TimerState state;

                if ((state = timer_state_from_string(value)) < 0)
                        log_debug("Failed to parse state value %s", value);
                else
                        t->deserialized_state = state;
        } else if (streq(key, "result")) {
                TimerResult f;

                f = timer_result_from_string(value);
                if (f < 0)
                        log_debug("Failed to parse result value %s", value);
                else if (f != TIMER_SUCCESS)
                        t->result = f;

        } else
                log_debug("Unknown serialization key '%s'", key);

        return 0;
}

static UnitActiveState timer_active_state(Unit *u) {
        assert(u);

        return state_translation_table[TIMER(u)->state];
}

static const char *timer_sub_state_to_string(Unit *u) {
        assert(u);

        return timer_state_to_string(TIMER(u)->state);
}

static void timer_timer_event(Unit *u, uint64_t elapsed, Watch *w) {
        Timer *t = TIMER(u);

        assert(t);
        assert(elapsed == 1);

        if (t->state != TIMER_WAITING)
                return;

        log_debug("Timer elapsed on %s", u->id);
        timer_enter_running(t);
}

void timer_unit_notify(Unit *u, UnitActiveState new_state) {
        Iterator i;
        Unit *k;

        if (u->type == UNIT_TIMER)
                return;

        SET_FOREACH(k, u->dependencies[UNIT_TRIGGERED_BY], i) {
                Timer *t;
                TimerValue *v;

                if (k->type != UNIT_TIMER)
                        continue;

                if (k->load_state != UNIT_LOADED)
                        continue;

                t = TIMER(k);

                /* Reenable all timers that depend on unit state */
                LIST_FOREACH(value, v, t->values)
                        if (v->base == TIMER_UNIT_ACTIVE ||
                            v->base == TIMER_UNIT_INACTIVE)
                                v->disabled = false;

                switch (t->state) {

                case TIMER_WAITING:
                case TIMER_ELAPSED:

                        /* Recalculate sleep time */
                        timer_enter_waiting(t, false);
                        break;

                case TIMER_RUNNING:

                        if (UNIT_IS_INACTIVE_OR_FAILED(new_state)) {
                                log_debug("%s got notified about unit deactivation.", UNIT(t)->id);
                                timer_enter_waiting(t, false);
                        }

                        break;

                case TIMER_DEAD:
                case TIMER_FAILED:
                        break;

                default:
                        assert_not_reached("Unknown timer state");
                }
        }
}

static void timer_reset_failed(Unit *u) {
        Timer *t = TIMER(u);

        assert(t);

        if (t->state == TIMER_FAILED)
                timer_set_state(t, TIMER_DEAD);

        t->result = TIMER_SUCCESS;
}

static const char* const timer_state_table[_TIMER_STATE_MAX] = {
        [TIMER_DEAD] = "dead",
        [TIMER_WAITING] = "waiting",
        [TIMER_RUNNING] = "running",
        [TIMER_ELAPSED] = "elapsed",
        [TIMER_FAILED] = "failed"
};

DEFINE_STRING_TABLE_LOOKUP(timer_state, TimerState);

static const char* const timer_base_table[_TIMER_BASE_MAX] = {
        [TIMER_ACTIVE] = "OnActiveSec",
        [TIMER_BOOT] = "OnBootSec",
        [TIMER_STARTUP] = "OnStartupSec",
        [TIMER_UNIT_ACTIVE] = "OnUnitActiveSec",
        [TIMER_UNIT_INACTIVE] = "OnUnitInactiveSec"
};

DEFINE_STRING_TABLE_LOOKUP(timer_base, TimerBase);

static const char* const timer_result_table[_TIMER_RESULT_MAX] = {
        [TIMER_SUCCESS] = "success",
        [TIMER_FAILURE_RESOURCES] = "resources"
};

DEFINE_STRING_TABLE_LOOKUP(timer_result, TimerResult);

const UnitVTable timer_vtable = {
        .suffix = ".timer",
        .object_size = sizeof(Timer),
        .sections =
                "Unit\0"
                "Timer\0"
                "Install\0",

        .init = timer_init,
        .done = timer_done,
        .load = timer_load,

        .coldplug = timer_coldplug,

        .dump = timer_dump,

        .start = timer_start,
        .stop = timer_stop,

        .serialize = timer_serialize,
        .deserialize_item = timer_deserialize_item,

        .active_state = timer_active_state,
        .sub_state_to_string = timer_sub_state_to_string,

        .timer_event = timer_timer_event,

        .reset_failed = timer_reset_failed,

        .bus_interface = "org.freedesktop.systemd1.Timer",
        .bus_message_handler = bus_timer_message_handler,
        .bus_invalidating_properties =  bus_timer_invalidating_properties
};
