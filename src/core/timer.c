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
#include "bus-util.h"
#include "bus-error.h"

static const UnitActiveState state_translation_table[_TIMER_STATE_MAX] = {
        [TIMER_DEAD] = UNIT_INACTIVE,
        [TIMER_WAITING] = UNIT_ACTIVE,
        [TIMER_RUNNING] = UNIT_ACTIVE,
        [TIMER_ELAPSED] = UNIT_ACTIVE,
        [TIMER_FAILED] = UNIT_FAILED
};

static int timer_dispatch(sd_event_source *s, uint64_t usec, void *userdata);

static void timer_init(Unit *u) {
        Timer *t = TIMER(u);

        assert(u);
        assert(u->load_state == UNIT_STUB);

        t->next_elapse_monotonic_or_boottime = USEC_INFINITY;
        t->next_elapse_realtime = USEC_INFINITY;
        t->accuracy_usec = u->manager->default_timer_accuracy_usec;
}

void timer_free_values(Timer *t) {
        TimerValue *v;

        assert(t);

        while ((v = t->values)) {
                LIST_REMOVE(value, t->values, v);
                calendar_spec_free(v->calendar_spec);
                free(v);
        }
}

static void timer_done(Unit *u) {
        Timer *t = TIMER(u);

        assert(t);

        timer_free_values(t);

        t->monotonic_event_source = sd_event_source_unref(t->monotonic_event_source);
        t->realtime_event_source = sd_event_source_unref(t->realtime_event_source);

        free(t->stamp_path);
}

static int timer_verify(Timer *t) {
        assert(t);

        if (UNIT(t)->load_state != UNIT_LOADED)
                return 0;

        if (!t->values) {
                log_unit_error(UNIT(t), "Timer unit lacks value setting. Refusing.");
                return -EINVAL;
        }

        return 0;
}

static int timer_add_default_dependencies(Timer *t) {
        int r;
        TimerValue *v;

        assert(t);

        r = unit_add_dependency_by_name(UNIT(t), UNIT_BEFORE, SPECIAL_TIMERS_TARGET, NULL, true);
        if (r < 0)
                return r;

        if (UNIT(t)->manager->running_as == MANAGER_SYSTEM) {
                r = unit_add_two_dependencies_by_name(UNIT(t), UNIT_AFTER, UNIT_REQUIRES, SPECIAL_SYSINIT_TARGET, NULL, true);
                if (r < 0)
                        return r;

                LIST_FOREACH(value, v, t->values) {
                        if (v->base == TIMER_CALENDAR) {
                                r = unit_add_dependency_by_name(UNIT(t), UNIT_AFTER, SPECIAL_TIME_SYNC_TARGET, NULL, true);
                                if (r < 0)
                                        return r;
                                break;
                        }
                }
        }

        return unit_add_two_dependencies_by_name(UNIT(t), UNIT_BEFORE, UNIT_CONFLICTS, SPECIAL_SHUTDOWN_TARGET, NULL, true);
}

static int timer_setup_persistent(Timer *t) {
        int r;

        assert(t);

        if (!t->persistent)
                return 0;

        if (UNIT(t)->manager->running_as == MANAGER_SYSTEM) {

                r = unit_require_mounts_for(UNIT(t), "/var/lib/systemd/timers");
                if (r < 0)
                        return r;

                t->stamp_path = strappend("/var/lib/systemd/timers/stamp-", UNIT(t)->id);
        } else {
                const char *e;

                e = getenv("XDG_DATA_HOME");
                if (e)
                        t->stamp_path = strjoin(e, "/systemd/timers/stamp-", UNIT(t)->id, NULL);
                else {

                        _cleanup_free_ char *h = NULL;

                        r = get_home_dir(&h);
                        if (r < 0)
                                return log_unit_error_errno(UNIT(t), r, "Failed to determine home directory: %m");

                        t->stamp_path = strjoin(h, "/.local/share/systemd/timers/stamp-", UNIT(t)->id, NULL);
                }
        }

        if (!t->stamp_path)
                return log_oom();

        return 0;
}

static int timer_load(Unit *u) {
        Timer *t = TIMER(u);
        int r;

        assert(u);
        assert(u->load_state == UNIT_STUB);

        r = unit_load_fragment_and_dropin(u);
        if (r < 0)
                return r;

        if (u->load_state == UNIT_LOADED) {

                if (set_isempty(u->dependencies[UNIT_TRIGGERS])) {
                        Unit *x;

                        r = unit_load_related_unit(u, ".service", &x);
                        if (r < 0)
                                return r;

                        r = unit_add_two_dependencies(u, UNIT_BEFORE, UNIT_TRIGGERS, x, true);
                        if (r < 0)
                                return r;
                }

                r = timer_setup_persistent(t);
                if (r < 0)
                        return r;

                if (u->default_dependencies) {
                        r = timer_add_default_dependencies(t);
                        if (r < 0)
                                return r;
                }
        }

        return timer_verify(t);
}

static void timer_dump(Unit *u, FILE *f, const char *prefix) {
        char buf[FORMAT_TIMESPAN_MAX];
        Timer *t = TIMER(u);
        Unit *trigger;
        TimerValue *v;

        trigger = UNIT_TRIGGER(u);

        fprintf(f,
                "%sTimer State: %s\n"
                "%sResult: %s\n"
                "%sUnit: %s\n"
                "%sPersistent: %s\n"
                "%sWakeSystem: %s\n"
                "%sAccuracy: %s\n",
                prefix, timer_state_to_string(t->state),
                prefix, timer_result_to_string(t->result),
                prefix, trigger ? trigger->id : "n/a",
                prefix, yes_no(t->persistent),
                prefix, yes_no(t->wake_system),
                prefix, format_timespan(buf, sizeof(buf), t->accuracy_usec, 1));

        LIST_FOREACH(value, v, t->values) {

                if (v->base == TIMER_CALENDAR) {
                        _cleanup_free_ char *p = NULL;

                        calendar_spec_to_string(v->calendar_spec, &p);

                        fprintf(f,
                                "%s%s: %s\n",
                                prefix,
                                timer_base_to_string(v->base),
                                strna(p));
                } else  {
                        char timespan1[FORMAT_TIMESPAN_MAX];

                        fprintf(f,
                                "%s%s: %s\n",
                                prefix,
                                timer_base_to_string(v->base),
                                format_timespan(timespan1, sizeof(timespan1), v->value, 0));
                }
        }
}

static void timer_set_state(Timer *t, TimerState state) {
        TimerState old_state;
        assert(t);

        old_state = t->state;
        t->state = state;

        if (state != TIMER_WAITING) {
                t->monotonic_event_source = sd_event_source_unref(t->monotonic_event_source);
                t->realtime_event_source = sd_event_source_unref(t->realtime_event_source);
        }

        if (state != old_state)
                log_unit_debug(UNIT(t), "Changed %s -> %s", timer_state_to_string(old_state), timer_state_to_string(state));

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

static usec_t monotonic_to_boottime(usec_t t) {
        usec_t a, b;

        if (t <= 0)
                return 0;

        a = now(CLOCK_BOOTTIME);
        b = now(CLOCK_MONOTONIC);

        if (t + a > b)
                return t + a - b;
        else
                return 0;
}

static void timer_enter_waiting(Timer *t, bool initial) {
        bool found_monotonic = false, found_realtime = false;
        usec_t ts_realtime, ts_monotonic;
        usec_t base = 0;
        TimerValue *v;
        int r;

        /* If we shall wake the system we use the boottime clock
         * rather than the monotonic clock. */

        ts_realtime = now(CLOCK_REALTIME);
        ts_monotonic = now(t->wake_system ? CLOCK_BOOTTIME : CLOCK_MONOTONIC);
        t->next_elapse_monotonic_or_boottime = t->next_elapse_realtime = 0;

        LIST_FOREACH(value, v, t->values) {

                if (v->disabled)
                        continue;

                if (v->base == TIMER_CALENDAR) {
                        usec_t b;

                        /* If we know the last time this was
                         * triggered, schedule the job based relative
                         * to that. If we don't just start from
                         * now. */

                        b = t->last_trigger.realtime > 0 ? t->last_trigger.realtime : ts_realtime;

                        r = calendar_spec_next_usec(v->calendar_spec, b, &v->next_elapse);
                        if (r < 0)
                                continue;

                        if (!found_realtime)
                                t->next_elapse_realtime = v->next_elapse;
                        else
                                t->next_elapse_realtime = MIN(t->next_elapse_realtime, v->next_elapse);

                        found_realtime = true;

                } else  {
                        switch (v->base) {

                        case TIMER_ACTIVE:
                                if (state_translation_table[t->state] == UNIT_ACTIVE)
                                        base = UNIT(t)->inactive_exit_timestamp.monotonic;
                                else
                                        base = ts_monotonic;
                                break;

                        case TIMER_BOOT:
                                /* CLOCK_MONOTONIC equals the uptime on Linux */
                                base = 0;
                                break;

                        case TIMER_STARTUP:
                                base = UNIT(t)->manager->userspace_timestamp.monotonic;
                                break;

                        case TIMER_UNIT_ACTIVE:

                                base = UNIT_TRIGGER(UNIT(t))->inactive_exit_timestamp.monotonic;

                                if (base <= 0)
                                        base = t->last_trigger.monotonic;

                                if (base <= 0)
                                        continue;

                                break;

                        case TIMER_UNIT_INACTIVE:

                                base = UNIT_TRIGGER(UNIT(t))->inactive_enter_timestamp.monotonic;

                                if (base <= 0)
                                        base = t->last_trigger.monotonic;

                                if (base <= 0)
                                        continue;

                                break;

                        default:
                                assert_not_reached("Unknown timer base");
                        }

                        if (t->wake_system)
                                base = monotonic_to_boottime(base);

                        v->next_elapse = base + v->value;

                        if (!initial && v->next_elapse < ts_monotonic && IN_SET(v->base, TIMER_ACTIVE, TIMER_BOOT, TIMER_STARTUP)) {
                                /* This is a one time trigger, disable it now */
                                v->disabled = true;
                                continue;
                        }

                        if (!found_monotonic)
                                t->next_elapse_monotonic_or_boottime = v->next_elapse;
                        else
                                t->next_elapse_monotonic_or_boottime = MIN(t->next_elapse_monotonic_or_boottime, v->next_elapse);

                        found_monotonic = true;
                }
        }

        if (!found_monotonic && !found_realtime) {
                log_unit_debug(UNIT(t), "Timer is elapsed.");
                timer_set_state(t, TIMER_ELAPSED);
                return;
        }

        if (found_monotonic) {
                char buf[FORMAT_TIMESPAN_MAX];

                log_unit_debug(UNIT(t), "Monotonic timer elapses in %s.", format_timespan(buf, sizeof(buf), t->next_elapse_monotonic_or_boottime > ts_monotonic ? t->next_elapse_monotonic_or_boottime - ts_monotonic : 0, 0));

                if (t->monotonic_event_source) {
                        r = sd_event_source_set_time(t->monotonic_event_source, t->next_elapse_monotonic_or_boottime);
                        if (r < 0)
                                goto fail;

                        r = sd_event_source_set_enabled(t->monotonic_event_source, SD_EVENT_ONESHOT);
                        if (r < 0)
                                goto fail;
                } else {

                        r = sd_event_add_time(
                                        UNIT(t)->manager->event,
                                        &t->monotonic_event_source,
                                        t->wake_system ? CLOCK_BOOTTIME_ALARM : CLOCK_MONOTONIC,
                                        t->next_elapse_monotonic_or_boottime, t->accuracy_usec,
                                        timer_dispatch, t);
                        if (r < 0)
                                goto fail;

                        (void) sd_event_source_set_description(t->monotonic_event_source, "timer-monotonic");
                }

        } else if (t->monotonic_event_source) {

                r = sd_event_source_set_enabled(t->monotonic_event_source, SD_EVENT_OFF);
                if (r < 0)
                        goto fail;
        }

        if (found_realtime) {
                char buf[FORMAT_TIMESTAMP_MAX];
                log_unit_debug(UNIT(t), "Realtime timer elapses at %s.", format_timestamp(buf, sizeof(buf), t->next_elapse_realtime));

                if (t->realtime_event_source) {
                        r = sd_event_source_set_time(t->realtime_event_source, t->next_elapse_realtime);
                        if (r < 0)
                                goto fail;

                        r = sd_event_source_set_enabled(t->realtime_event_source, SD_EVENT_ONESHOT);
                        if (r < 0)
                                goto fail;
                } else {
                        r = sd_event_add_time(
                                        UNIT(t)->manager->event,
                                        &t->realtime_event_source,
                                        t->wake_system ? CLOCK_REALTIME_ALARM : CLOCK_REALTIME,
                                        t->next_elapse_realtime, t->accuracy_usec,
                                        timer_dispatch, t);
                        if (r < 0)
                                goto fail;

                        (void) sd_event_source_set_description(t->realtime_event_source, "timer-realtime");
                }

        } else if (t->realtime_event_source) {

                r = sd_event_source_set_enabled(t->realtime_event_source, SD_EVENT_OFF);
                if (r < 0)
                        goto fail;
        }

        timer_set_state(t, TIMER_WAITING);
        return;

fail:
        log_unit_warning_errno(UNIT(t), r, "Failed to enter waiting state: %m");
        timer_enter_dead(t, TIMER_FAILURE_RESOURCES);
}

static void timer_enter_running(Timer *t) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(t);

        /* Don't start job if we are supposed to go down */
        if (unit_stop_pending(UNIT(t)))
                return;

        r = manager_add_job(UNIT(t)->manager, JOB_START, UNIT_TRIGGER(UNIT(t)),
                            JOB_REPLACE, true, &error, NULL);
        if (r < 0)
                goto fail;

        dual_timestamp_get(&t->last_trigger);

        if (t->stamp_path)
                touch_file(t->stamp_path, true, t->last_trigger.realtime, UID_INVALID, GID_INVALID, 0);

        timer_set_state(t, TIMER_RUNNING);
        return;

fail:
        log_unit_warning(UNIT(t), "Failed to queue unit startup job: %s", bus_error_message(&error, r));
        timer_enter_dead(t, TIMER_FAILURE_RESOURCES);
}

static int timer_start(Unit *u) {
        Timer *t = TIMER(u);
        TimerValue *v;

        assert(t);
        assert(t->state == TIMER_DEAD || t->state == TIMER_FAILED);

        if (UNIT_TRIGGER(u)->load_state != UNIT_LOADED)
                return -ENOENT;

        t->last_trigger = DUAL_TIMESTAMP_NULL;

        /* Reenable all timers that depend on unit activation time */
        LIST_FOREACH(value, v, t->values)
                if (v->base == TIMER_ACTIVE)
                        v->disabled = false;

        if (t->stamp_path) {
                struct stat st;

                if (stat(t->stamp_path, &st) >= 0)
                        t->last_trigger.realtime = timespec_load(&st.st_atim);
                else if (errno == ENOENT)
                        /* The timer has never run before,
                         * make sure a stamp file exists.
                         */
                        touch_file(t->stamp_path, true, USEC_INFINITY, UID_INVALID, GID_INVALID, 0);
        }

        t->result = TIMER_SUCCESS;
        timer_enter_waiting(t, true);
        return 1;
}

static int timer_stop(Unit *u) {
        Timer *t = TIMER(u);

        assert(t);
        assert(t->state == TIMER_WAITING || t->state == TIMER_RUNNING || t->state == TIMER_ELAPSED);

        timer_enter_dead(t, TIMER_SUCCESS);
        return 1;
}

static int timer_serialize(Unit *u, FILE *f, FDSet *fds) {
        Timer *t = TIMER(u);

        assert(u);
        assert(f);
        assert(fds);

        unit_serialize_item(u, f, "state", timer_state_to_string(t->state));
        unit_serialize_item(u, f, "result", timer_result_to_string(t->result));

        if (t->last_trigger.realtime > 0)
                unit_serialize_item_format(u, f, "last-trigger-realtime", "%" PRIu64, t->last_trigger.realtime);

        if (t->last_trigger.monotonic > 0)
                unit_serialize_item_format(u, f, "last-trigger-monotonic", "%" PRIu64, t->last_trigger.monotonic);

        return 0;
}

static int timer_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Timer *t = TIMER(u);
        int r;

        assert(u);
        assert(key);
        assert(value);
        assert(fds);

        if (streq(key, "state")) {
                TimerState state;

                state = timer_state_from_string(value);
                if (state < 0)
                        log_unit_debug(u, "Failed to parse state value: %s", value);
                else
                        t->deserialized_state = state;
        } else if (streq(key, "result")) {
                TimerResult f;

                f = timer_result_from_string(value);
                if (f < 0)
                        log_unit_debug(u, "Failed to parse result value: %s", value);
                else if (f != TIMER_SUCCESS)
                        t->result = f;
        } else if (streq(key, "last-trigger-realtime")) {

                r = safe_atou64(value, &t->last_trigger.realtime);
                if (r < 0)
                        log_unit_debug(u, "Failed to parse last-trigger-realtime value: %s", value);

        } else if (streq(key, "last-trigger-monotonic")) {

                r = safe_atou64(value, &t->last_trigger.monotonic);
                if (r < 0)
                        log_unit_debug(u, "Failed to parse last-trigger-monotonic value: %s", value);

        } else
                log_unit_debug(u, "Unknown serialization key: %s", key);

        return 0;
}

_pure_ static UnitActiveState timer_active_state(Unit *u) {
        assert(u);

        return state_translation_table[TIMER(u)->state];
}

_pure_ static const char *timer_sub_state_to_string(Unit *u) {
        assert(u);

        return timer_state_to_string(TIMER(u)->state);
}

static int timer_dispatch(sd_event_source *s, uint64_t usec, void *userdata) {
        Timer *t = TIMER(userdata);

        assert(t);

        if (t->state != TIMER_WAITING)
                return 0;

        log_unit_debug(UNIT(t), "Timer elapsed.");
        timer_enter_running(t);
        return 0;
}

static void timer_trigger_notify(Unit *u, Unit *other) {
        Timer *t = TIMER(u);
        TimerValue *v;

        assert(u);
        assert(other);

        if (other->load_state != UNIT_LOADED)
                return;

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

                if (UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(other))) {
                        log_unit_debug(UNIT(t), "Got notified about unit deactivation.");
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

static void timer_reset_failed(Unit *u) {
        Timer *t = TIMER(u);

        assert(t);

        if (t->state == TIMER_FAILED)
                timer_set_state(t, TIMER_DEAD);

        t->result = TIMER_SUCCESS;
}

static void timer_time_change(Unit *u) {
        Timer *t = TIMER(u);

        assert(u);

        if (t->state != TIMER_WAITING)
                return;

        log_unit_debug(u, "Time change, recalculating next elapse.");
        timer_enter_waiting(t, false);
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
        [TIMER_UNIT_INACTIVE] = "OnUnitInactiveSec",
        [TIMER_CALENDAR] = "OnCalendar"
};

DEFINE_STRING_TABLE_LOOKUP(timer_base, TimerBase);

static const char* const timer_result_table[_TIMER_RESULT_MAX] = {
        [TIMER_SUCCESS] = "success",
        [TIMER_FAILURE_RESOURCES] = "resources"
};

DEFINE_STRING_TABLE_LOOKUP(timer_result, TimerResult);

const UnitVTable timer_vtable = {
        .object_size = sizeof(Timer),

        .sections =
                "Unit\0"
                "Timer\0"
                "Install\0",
        .private_section = "Timer",

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

        .trigger_notify = timer_trigger_notify,

        .reset_failed = timer_reset_failed,
        .time_change = timer_time_change,

        .bus_interface = "org.freedesktop.systemd1.Timer",
        .bus_vtable = bus_timer_vtable,
        .bus_set_property = bus_timer_set_property,

        .can_transient = true,
};
