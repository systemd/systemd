/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "dbus-timer.h"
#include "dbus-unit.h"
#include "fs-util.h"
#include "parse-util.h"
#include "random-util.h"
#include "serialize.h"
#include "special.h"
#include "string-table.h"
#include "string-util.h"
#include "timer.h"
#include "unit-name.h"
#include "unit.h"
#include "user-util.h"
#include "virt.h"

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
        t->accuracy_usec = u->manager->defaults.timer_accuracy_usec;
        t->remain_after_elapse = true;
}

void timer_free_values(Timer *t) {
        TimerValue *v;

        assert(t);

        while ((v = LIST_POP(value, t->values))) {
                calendar_spec_free(v->calendar_spec);
                free(v);
        }
}

static void timer_done(Unit *u) {
        Timer *t = TIMER(u);

        assert(t);

        timer_free_values(t);

        t->monotonic_event_source = sd_event_source_disable_unref(t->monotonic_event_source);
        t->realtime_event_source = sd_event_source_disable_unref(t->realtime_event_source);

        t->stamp_path = mfree(t->stamp_path);
}

static int timer_verify(Timer *t) {
        assert(t);
        assert(UNIT(t)->load_state == UNIT_LOADED);

        if (!t->values && !t->on_clock_change && !t->on_timezone_change)
                return log_unit_error_errno(UNIT(t), SYNTHETIC_ERRNO(ENOEXEC), "Timer unit lacks value setting. Refusing.");

        return 0;
}

static int timer_add_default_dependencies(Timer *t) {
        int r;

        assert(t);

        if (!UNIT(t)->default_dependencies)
                return 0;

        r = unit_add_dependency_by_name(UNIT(t), UNIT_BEFORE, SPECIAL_TIMERS_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
        if (r < 0)
                return r;

        if (MANAGER_IS_SYSTEM(UNIT(t)->manager)) {
                r = unit_add_two_dependencies_by_name(UNIT(t), UNIT_AFTER, UNIT_REQUIRES, SPECIAL_SYSINIT_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
                if (r < 0)
                        return r;

                LIST_FOREACH(value, v, t->values) {
                        if (v->base != TIMER_CALENDAR)
                                continue;

                        FOREACH_STRING(target, SPECIAL_TIME_SYNC_TARGET, SPECIAL_TIME_SET_TARGET) {
                                r = unit_add_dependency_by_name(UNIT(t), UNIT_AFTER, target, true, UNIT_DEPENDENCY_DEFAULT);
                                if (r < 0)
                                        return r;
                        }

                        break;
                }
        }

        return unit_add_two_dependencies_by_name(UNIT(t), UNIT_BEFORE, UNIT_CONFLICTS, SPECIAL_SHUTDOWN_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
}

static int timer_add_trigger_dependencies(Timer *t) {
        Unit *x;
        int r;

        assert(t);

        if (UNIT_TRIGGER(UNIT(t)))
                return 0;

        r = unit_load_related_unit(UNIT(t), ".service", &x);
        if (r < 0)
                return r;

        return unit_add_two_dependencies(UNIT(t), UNIT_BEFORE, UNIT_TRIGGERS, x, true, UNIT_DEPENDENCY_IMPLICIT);
}

static int timer_setup_persistent(Timer *t) {
        _cleanup_free_ char *stamp_path = NULL;
        int r;

        assert(t);

        if (!t->persistent)
                return 0;

        if (MANAGER_IS_SYSTEM(UNIT(t)->manager)) {

                r = unit_add_mounts_for(UNIT(t), "/var/lib/systemd/timers", UNIT_DEPENDENCY_FILE, UNIT_MOUNT_REQUIRES);
                if (r < 0)
                        return r;

                stamp_path = strjoin("/var/lib/systemd/timers/stamp-", UNIT(t)->id);
        } else {
                const char *e;

                e = getenv("XDG_DATA_HOME");
                if (e)
                        stamp_path = strjoin(e, "/systemd/timers/stamp-", UNIT(t)->id);
                else {

                        _cleanup_free_ char *h = NULL;

                        r = get_home_dir(&h);
                        if (r < 0)
                                return log_unit_error_errno(UNIT(t), r, "Failed to determine home directory: %m");

                        stamp_path = strjoin(h, "/.local/share/systemd/timers/stamp-", UNIT(t)->id);
                }
        }

        if (!stamp_path)
                return log_oom();

        return free_and_replace(t->stamp_path, stamp_path);
}

static uint64_t timer_get_fixed_delay_hash(Timer *t) {
        static const uint8_t hash_key[] = {
                0x51, 0x0a, 0xdb, 0x76, 0x29, 0x51, 0x42, 0xc2,
                0x80, 0x35, 0xea, 0xe6, 0x8e, 0x3a, 0x37, 0xbd
        };

        struct siphash state;
        sd_id128_t machine_id;
        uid_t uid;
        int r;

        assert(t);

        uid = getuid();
        r = sd_id128_get_machine(&machine_id);
        if (r < 0) {
                log_unit_debug_errno(UNIT(t), r,
                                     "Failed to get machine ID for the fixed delay calculation, proceeding with 0: %m");
                machine_id = SD_ID128_NULL;
        }

        siphash24_init(&state, hash_key);
        siphash24_compress(&machine_id, sizeof(sd_id128_t), &state);
        siphash24_compress_boolean(MANAGER_IS_SYSTEM(UNIT(t)->manager), &state);
        siphash24_compress(&uid, sizeof(uid_t), &state);
        siphash24_compress_string(UNIT(t)->id, &state);

        return siphash24_finalize(&state);
}

static int timer_load(Unit *u) {
        Timer *t = TIMER(u);
        int r;

        assert(u);
        assert(u->load_state == UNIT_STUB);

        r = unit_load_fragment_and_dropin(u, true);
        if (r < 0)
                return r;

        if (u->load_state != UNIT_LOADED)
                return 0;

        /* This is a new unit? Then let's add in some extras */
        r = timer_add_trigger_dependencies(t);
        if (r < 0)
                return r;

        r = timer_setup_persistent(t);
        if (r < 0)
                return r;

        r = timer_add_default_dependencies(t);
        if (r < 0)
                return r;

        return timer_verify(t);
}

static void timer_dump(Unit *u, FILE *f, const char *prefix) {
        Timer *t = TIMER(u);
        Unit *trigger;

        trigger = UNIT_TRIGGER(u);

        fprintf(f,
                "%sTimer State: %s\n"
                "%sResult: %s\n"
                "%sUnit: %s\n"
                "%sPersistent: %s\n"
                "%sWakeSystem: %s\n"
                "%sAccuracy: %s\n"
                "%sRemainAfterElapse: %s\n"
                "%sFixedRandomDelay: %s\n"
                "%sOnClockChange: %s\n"
                "%sOnTimeZoneChange: %s\n",
                prefix, timer_state_to_string(t->state),
                prefix, timer_result_to_string(t->result),
                prefix, trigger ? trigger->id : "n/a",
                prefix, yes_no(t->persistent),
                prefix, yes_no(t->wake_system),
                prefix, FORMAT_TIMESPAN(t->accuracy_usec, 1),
                prefix, yes_no(t->remain_after_elapse),
                prefix, yes_no(t->fixed_random_delay),
                prefix, yes_no(t->on_clock_change),
                prefix, yes_no(t->on_timezone_change));

        LIST_FOREACH(value, v, t->values)
                if (v->base == TIMER_CALENDAR) {
                        _cleanup_free_ char *p = NULL;

                        (void) calendar_spec_to_string(v->calendar_spec, &p);

                        fprintf(f,
                                "%s%s: %s\n",
                                prefix,
                                timer_base_to_string(v->base),
                                strna(p));
                } else
                        fprintf(f,
                                "%s%s: %s\n",
                                prefix,
                                timer_base_to_string(v->base),
                                FORMAT_TIMESPAN(v->value, 0));
}

static void timer_set_state(Timer *t, TimerState state) {
        TimerState old_state;
        assert(t);

        if (t->state != state)
                bus_unit_send_pending_change_signal(UNIT(t), false);

        old_state = t->state;
        t->state = state;

        if (state != TIMER_WAITING) {
                t->monotonic_event_source = sd_event_source_disable_unref(t->monotonic_event_source);
                t->realtime_event_source = sd_event_source_disable_unref(t->realtime_event_source);
                t->next_elapse_monotonic_or_boottime = USEC_INFINITY;
                t->next_elapse_realtime = USEC_INFINITY;
        }

        if (state != old_state)
                log_unit_debug(UNIT(t), "Changed %s -> %s", timer_state_to_string(old_state), timer_state_to_string(state));

        unit_notify(UNIT(t), state_translation_table[old_state], state_translation_table[state], /* reload_success = */ true);
}

static void timer_enter_waiting(Timer *t, bool time_change);

static int timer_coldplug(Unit *u) {
        Timer *t = TIMER(u);

        assert(t);
        assert(t->state == TIMER_DEAD);

        if (t->deserialized_state == t->state)
                return 0;

        if (t->deserialized_state == TIMER_WAITING)
                timer_enter_waiting(t, false);
        else
                timer_set_state(t, t->deserialized_state);

        return 0;
}

static void timer_enter_dead(Timer *t, TimerResult f) {
        assert(t);

        if (t->result == TIMER_SUCCESS)
                t->result = f;

        unit_log_result(UNIT(t), t->result == TIMER_SUCCESS, timer_result_to_string(t->result));
        timer_set_state(t, t->result != TIMER_SUCCESS ? TIMER_FAILED : TIMER_DEAD);
}

static void timer_enter_elapsed(Timer *t, bool leave_around) {
        assert(t);

        /* If a unit is marked with RemainAfterElapse=yes we leave it
         * around even after it elapsed once, so that starting it
         * later again does not necessarily mean immediate
         * retriggering. We unconditionally leave units with
         * TIMER_UNIT_ACTIVE or TIMER_UNIT_INACTIVE triggers around,
         * since they might be restarted automatically at any time
         * later on. */

        if (t->remain_after_elapse || leave_around)
                timer_set_state(t, TIMER_ELAPSED);
        else
                timer_enter_dead(t, TIMER_SUCCESS);
}

static void add_random(Timer *t, usec_t *v) {
        usec_t add;

        assert(t);
        assert(v);

        if (t->random_usec == 0)
                return;
        if (*v == USEC_INFINITY)
                return;

        add = (t->fixed_random_delay ? timer_get_fixed_delay_hash(t) : random_u64()) % t->random_usec;

        if (*v + add < *v) /* overflow */
                *v = (usec_t) -2; /* Highest possible value, that is not USEC_INFINITY */
        else
                *v += add;

        log_unit_debug(UNIT(t), "Adding %s random time.", FORMAT_TIMESPAN(add, 0));
}

static void timer_enter_waiting(Timer *t, bool time_change) {
        bool found_monotonic = false, found_realtime = false;
        bool leave_around = false;
        triple_timestamp ts;
        Unit *trigger;
        int r;

        assert(t);

        trigger = UNIT_TRIGGER(UNIT(t));
        if (!trigger) {
                log_unit_error(UNIT(t), "Unit to trigger vanished.");
                goto fail;
        }

        triple_timestamp_now(&ts);
        t->next_elapse_monotonic_or_boottime = t->next_elapse_realtime = 0;

        LIST_FOREACH(value, v, t->values) {
                if (v->disabled)
                        continue;

                if (v->base == TIMER_CALENDAR) {
                        usec_t b, rebased;

                        /* If we know the last time this was
                         * triggered, schedule the job based relative
                         * to that. If we don't, just start from
                         * the activation time. */

                        if (dual_timestamp_is_set(&t->last_trigger))
                                b = t->last_trigger.realtime;
                        else if (dual_timestamp_is_set(&UNIT(t)->inactive_exit_timestamp))
                                b = UNIT(t)->inactive_exit_timestamp.realtime;
                        else
                                b = ts.realtime;

                        r = calendar_spec_next_usec(v->calendar_spec, b, &v->next_elapse);
                        if (r < 0)
                                continue;

                        /* To make the delay due to RandomizedDelaySec= work even at boot, if the scheduled
                         * time has already passed, set the time when systemd first started as the scheduled
                         * time. Note that we base this on the monotonic timestamp of the boot, not the
                         * realtime one, since the wallclock might have been off during boot. */
                        rebased = map_clock_usec(UNIT(t)->manager->timestamps[MANAGER_TIMESTAMP_USERSPACE].monotonic,
                                                 CLOCK_MONOTONIC, CLOCK_REALTIME);
                        if (v->next_elapse < rebased)
                                v->next_elapse = rebased;

                        if (!found_realtime)
                                t->next_elapse_realtime = v->next_elapse;
                        else
                                t->next_elapse_realtime = MIN(t->next_elapse_realtime, v->next_elapse);

                        found_realtime = true;

                } else {
                        usec_t base;

                        switch (v->base) {

                        case TIMER_ACTIVE:
                                if (state_translation_table[t->state] == UNIT_ACTIVE)
                                        base = UNIT(t)->inactive_exit_timestamp.monotonic;
                                else
                                        base = ts.monotonic;
                                break;

                        case TIMER_BOOT:
                                if (detect_container() <= 0) {
                                        /* CLOCK_MONOTONIC equals the uptime on Linux */
                                        base = 0;
                                        break;
                                }
                                /* In a container we don't want to include the time the host
                                 * was already up when the container started, so count from
                                 * our own startup. */
                                _fallthrough_;
                        case TIMER_STARTUP:
                                base = UNIT(t)->manager->timestamps[MANAGER_TIMESTAMP_USERSPACE].monotonic;
                                break;

                        case TIMER_UNIT_ACTIVE:
                                leave_around = true;
                                base = MAX(trigger->inactive_exit_timestamp.monotonic, t->last_trigger.monotonic);
                                if (base <= 0)
                                        continue;
                                break;

                        case TIMER_UNIT_INACTIVE:
                                leave_around = true;
                                base = MAX(trigger->inactive_enter_timestamp.monotonic, t->last_trigger.monotonic);
                                if (base <= 0)
                                        continue;
                                break;

                        default:
                                assert_not_reached();
                        }

                        v->next_elapse = usec_add(usec_shift_clock(base, CLOCK_MONOTONIC, TIMER_MONOTONIC_CLOCK(t)), v->value);

                        if (dual_timestamp_is_set(&t->last_trigger) &&
                            !time_change &&
                            v->next_elapse < triple_timestamp_by_clock(&ts, TIMER_MONOTONIC_CLOCK(t)) &&
                            IN_SET(v->base, TIMER_ACTIVE, TIMER_BOOT, TIMER_STARTUP)) {
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

        if (!found_monotonic && !found_realtime && !t->on_timezone_change && !t->on_clock_change) {
                log_unit_debug(UNIT(t), "Timer is elapsed.");
                timer_enter_elapsed(t, leave_around);
                return;
        }

        if (found_monotonic) {
                usec_t left;

                add_random(t, &t->next_elapse_monotonic_or_boottime);

                left = usec_sub_unsigned(t->next_elapse_monotonic_or_boottime, triple_timestamp_by_clock(&ts, TIMER_MONOTONIC_CLOCK(t)));
                log_unit_debug(UNIT(t), "Monotonic timer elapses in %s.", FORMAT_TIMESPAN(left, 0));

                if (t->monotonic_event_source) {
                        r = sd_event_source_set_time(t->monotonic_event_source, t->next_elapse_monotonic_or_boottime);
                        if (r < 0) {
                                log_unit_warning_errno(UNIT(t), r, "Failed to reschedule monotonic event source: %m");
                                goto fail;
                        }

                        r = sd_event_source_set_enabled(t->monotonic_event_source, SD_EVENT_ONESHOT);
                        if (r < 0) {
                                log_unit_warning_errno(UNIT(t), r, "Failed to enable monotonic event source: %m");
                                goto fail;
                        }
                } else {

                        r = sd_event_add_time(
                                        UNIT(t)->manager->event,
                                        &t->monotonic_event_source,
                                        t->wake_system ? CLOCK_BOOTTIME_ALARM : CLOCK_MONOTONIC,
                                        t->next_elapse_monotonic_or_boottime, t->accuracy_usec,
                                        timer_dispatch, t);
                        if (r < 0) {
                                log_unit_warning_errno(UNIT(t), r, "Failed to add monotonic event source: %m");
                                goto fail;
                        }

                        (void) sd_event_source_set_description(t->monotonic_event_source, "timer-monotonic");
                }

        } else if (t->monotonic_event_source) {

                r = sd_event_source_set_enabled(t->monotonic_event_source, SD_EVENT_OFF);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(t), r, "Failed to disable monotonic event source: %m");
                        goto fail;
                }
        }

        if (found_realtime) {
                add_random(t, &t->next_elapse_realtime);

                log_unit_debug(UNIT(t), "Realtime timer elapses at %s.", FORMAT_TIMESTAMP(t->next_elapse_realtime));

                if (t->realtime_event_source) {
                        r = sd_event_source_set_time(t->realtime_event_source, t->next_elapse_realtime);
                        if (r < 0) {
                                log_unit_warning_errno(UNIT(t), r, "Failed to reschedule realtime event source: %m");
                                goto fail;
                        }

                        r = sd_event_source_set_enabled(t->realtime_event_source, SD_EVENT_ONESHOT);
                        if (r < 0) {
                                log_unit_warning_errno(UNIT(t), r, "Failed to enable realtime event source: %m");
                                goto fail;
                        }
                } else {
                        r = sd_event_add_time(
                                        UNIT(t)->manager->event,
                                        &t->realtime_event_source,
                                        t->wake_system ? CLOCK_REALTIME_ALARM : CLOCK_REALTIME,
                                        t->next_elapse_realtime, t->accuracy_usec,
                                        timer_dispatch, t);
                        if (r < 0) {
                                log_unit_warning_errno(UNIT(t), r, "Failed to add realtime event source: %m");
                                goto fail;
                        }

                        (void) sd_event_source_set_description(t->realtime_event_source, "timer-realtime");
                }

        } else if (t->realtime_event_source) {

                r = sd_event_source_set_enabled(t->realtime_event_source, SD_EVENT_OFF);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(t), r, "Failed to disable realtime event source: %m");
                        goto fail;
                }
        }

        timer_set_state(t, TIMER_WAITING);
        return;

fail:
        timer_enter_dead(t, TIMER_FAILURE_RESOURCES);
}

static void timer_enter_running(Timer *t) {
        _cleanup_(activation_details_unrefp) ActivationDetails *details = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        Unit *trigger;
        Job *job;
        int r;

        assert(t);

        /* Don't start job if we are supposed to go down */
        if (unit_stop_pending(UNIT(t)))
                return;

        trigger = UNIT_TRIGGER(UNIT(t));
        if (!trigger) {
                log_unit_error(UNIT(t), "Unit to trigger vanished.");
                goto fail;
        }

        details = activation_details_new(UNIT(t));
        if (!details) {
                log_oom();
                goto fail;
        }

        r = manager_add_job(UNIT(t)->manager, JOB_START, trigger, JOB_REPLACE, NULL, &error, &job);
        if (r < 0) {
                log_unit_warning(UNIT(t), "Failed to queue unit startup job: %s", bus_error_message(&error, r));
                goto fail;
        }

        dual_timestamp_now(&t->last_trigger);
        ACTIVATION_DETAILS_TIMER(details)->last_trigger = t->last_trigger;

        job_set_activation_details(job, details);

        if (t->stamp_path)
                touch_file(t->stamp_path, true, t->last_trigger.realtime, UID_INVALID, GID_INVALID, MODE_INVALID);

        timer_set_state(t, TIMER_RUNNING);
        return;

fail:
        timer_enter_dead(t, TIMER_FAILURE_RESOURCES);
}

static int timer_start(Unit *u) {
        Timer *t = TIMER(u);
        int r;

        assert(t);
        assert(IN_SET(t->state, TIMER_DEAD, TIMER_FAILED));

        r = unit_test_trigger_loaded(u);
        if (r < 0)
                return r;

        r = unit_acquire_invocation_id(u);
        if (r < 0)
                return r;

        t->last_trigger = DUAL_TIMESTAMP_NULL;

        /* Reenable all timers that depend on unit activation time */
        LIST_FOREACH(value, v, t->values)
                if (v->base == TIMER_ACTIVE)
                        v->disabled = false;

        if (t->stamp_path) {
                struct stat st;

                if (stat(t->stamp_path, &st) >= 0) {
                        usec_t ft;

                        /* Load the file timestamp, but only if it is actually in the past. If it is in the future,
                         * something is wrong with the system clock. */

                        ft = timespec_load(&st.st_mtim);
                        if (ft < now(CLOCK_REALTIME))
                                t->last_trigger.realtime = ft;
                        else
                                log_unit_warning(u, "Not using persistent file timestamp %s as it is in the future.",
                                                 FORMAT_TIMESTAMP(ft));

                } else if (errno == ENOENT)
                        /* The timer has never run before, make sure a stamp file exists. */
                        (void) touch_file(t->stamp_path, true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID);
        }

        t->result = TIMER_SUCCESS;
        timer_enter_waiting(t, false);
        return 1;
}

static int timer_stop(Unit *u) {
        Timer *t = TIMER(u);

        assert(t);
        assert(IN_SET(t->state, TIMER_WAITING, TIMER_RUNNING, TIMER_ELAPSED));

        timer_enter_dead(t, TIMER_SUCCESS);
        return 1;
}

static int timer_serialize(Unit *u, FILE *f, FDSet *fds) {
        Timer *t = TIMER(u);

        assert(u);
        assert(f);
        assert(fds);

        (void) serialize_item(f, "state", timer_state_to_string(t->state));
        (void) serialize_item(f, "result", timer_result_to_string(t->result));

        if (dual_timestamp_is_set(&t->last_trigger))
                (void) serialize_usec(f, "last-trigger-realtime", t->last_trigger.realtime);

        if (t->last_trigger.monotonic > 0)
                (void) serialize_usec(f, "last-trigger-monotonic", t->last_trigger.monotonic);

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

        } else if (streq(key, "last-trigger-realtime"))
                (void) deserialize_usec(value, &t->last_trigger.realtime);
        else if (streq(key, "last-trigger-monotonic"))
                (void) deserialize_usec(value, &t->last_trigger.monotonic);
        else
                log_unit_debug(u, "Unknown serialization key: %s", key);

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

        assert(u);
        assert(other);

        /* Filter out invocations with bogus state */
        assert(UNIT_IS_LOAD_COMPLETE(other->load_state));

        /* Reenable all timers that depend on unit state */
        LIST_FOREACH(value, v, t->values)
                if (IN_SET(v->base, TIMER_UNIT_ACTIVE, TIMER_UNIT_INACTIVE))
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
                assert_not_reached();
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
        usec_t ts;

        assert(u);

        if (t->state != TIMER_WAITING)
                return;

        /* If we appear to have triggered in the future, the system clock must
         * have been set backwards.  So let's rewind our own clock and allow
         * the future triggers to happen again :).  Exactly the same as when
         * you start a timer unit with Persistent=yes. */
        ts = now(CLOCK_REALTIME);
        if (t->last_trigger.realtime > ts)
                t->last_trigger.realtime = ts;

        if (t->on_clock_change) {
                log_unit_debug(u, "Time change, triggering activation.");
                timer_enter_running(t);
        } else {
                log_unit_debug(u, "Time change, recalculating next elapse.");
                timer_enter_waiting(t, true);
        }
}

static void timer_timezone_change(Unit *u) {
        Timer *t = TIMER(u);

        assert(u);

        if (t->state != TIMER_WAITING)
                return;

        if (t->on_timezone_change) {
                log_unit_debug(u, "Timezone change, triggering activation.");
                timer_enter_running(t);
        } else {
                log_unit_debug(u, "Timezone change, recalculating next elapse.");
                timer_enter_waiting(t, false);
        }
}

static int timer_clean(Unit *u, ExecCleanMask mask) {
        Timer *t = TIMER(u);
        int r;

        assert(t);
        assert(mask != 0);

        if (t->state != TIMER_DEAD)
                return -EBUSY;

        if (mask != EXEC_CLEAN_STATE)
                return -EUNATCH;

        r = timer_setup_persistent(t);
        if (r < 0)
                return r;

        if (!t->stamp_path)
                return -EUNATCH;

        if (unlink(t->stamp_path) && errno != ENOENT)
                return log_unit_error_errno(u, errno, "Failed to clean stamp file of timer: %m");

        return 0;
}

static int timer_can_clean(Unit *u, ExecCleanMask *ret) {
        Timer *t = TIMER(u);

        assert(t);
        assert(ret);

        *ret = t->persistent ? EXEC_CLEAN_STATE : 0;
        return 0;
}

static int timer_can_start(Unit *u) {
        Timer *t = TIMER(u);
        int r;

        assert(t);

        r = unit_test_start_limit(u);
        if (r < 0) {
                timer_enter_dead(t, TIMER_FAILURE_START_LIMIT_HIT);
                return r;
        }

        return 1;
}

static void activation_details_timer_serialize(ActivationDetails *details, FILE *f) {
        ActivationDetailsTimer *t = ACTIVATION_DETAILS_TIMER(details);

        assert(details);
        assert(f);
        assert(t);

        (void) serialize_dual_timestamp(f, "activation-details-timer-last-trigger", &t->last_trigger);
}

static int activation_details_timer_deserialize(const char *key, const char *value, ActivationDetails **details) {
        int r;

        assert(key);
        assert(value);

        if (!details || !*details)
                return -EINVAL;

        ActivationDetailsTimer *t = ACTIVATION_DETAILS_TIMER(*details);
        if (!t)
                return -EINVAL;

        if (!streq(key, "activation-details-timer-last-trigger"))
                return -EINVAL;

        r = deserialize_dual_timestamp(value, &t->last_trigger);
        if (r < 0)
                return r;

        return 0;
}

static int activation_details_timer_append_env(ActivationDetails *details, char ***strv) {
        ActivationDetailsTimer *t = ACTIVATION_DETAILS_TIMER(details);
        int r;

        assert(details);
        assert(strv);
        assert(t);

        if (!dual_timestamp_is_set(&t->last_trigger))
                return 0;

        r = strv_extendf(strv, "TRIGGER_TIMER_REALTIME_USEC=" USEC_FMT, t->last_trigger.realtime);
        if (r < 0)
                return r;

        r = strv_extendf(strv, "TRIGGER_TIMER_MONOTONIC_USEC=" USEC_FMT, t->last_trigger.monotonic);
        if (r < 0)
                return r;

        return 2; /* Return the number of variables added to the env block */
}

static int activation_details_timer_append_pair(ActivationDetails *details, char ***strv) {
        ActivationDetailsTimer *t = ACTIVATION_DETAILS_TIMER(details);
        int r;

        assert(details);
        assert(strv);
        assert(t);

        if (!dual_timestamp_is_set(&t->last_trigger))
                return 0;

        r = strv_extend(strv, "trigger_timer_realtime_usec");
        if (r < 0)
                return r;

        r = strv_extendf(strv, USEC_FMT, t->last_trigger.realtime);
        if (r < 0)
                return r;

        r = strv_extend(strv, "trigger_timer_monotonic_usec");
        if (r < 0)
                return r;

        r = strv_extendf(strv, USEC_FMT, t->last_trigger.monotonic);
        if (r < 0)
                return r;

        return 2; /* Return the number of pairs added to the env block */
}

uint64_t timer_next_elapse_monotonic(const Timer *t) {
        assert(t);

        return (uint64_t) usec_shift_clock(t->next_elapse_monotonic_or_boottime,
                                           TIMER_MONOTONIC_CLOCK(t), CLOCK_MONOTONIC);
}

static const char* const timer_base_table[_TIMER_BASE_MAX] = {
        [TIMER_ACTIVE]        = "OnActiveSec",
        [TIMER_BOOT]          = "OnBootSec",
        [TIMER_STARTUP]       = "OnStartupSec",
        [TIMER_UNIT_ACTIVE]   = "OnUnitActiveSec",
        [TIMER_UNIT_INACTIVE] = "OnUnitInactiveSec",
        [TIMER_CALENDAR]      = "OnCalendar"
};

DEFINE_STRING_TABLE_LOOKUP(timer_base, TimerBase);

char* timer_base_to_usec_string(TimerBase i) {
        _cleanup_free_ char *buf = NULL;
        const char *s;
        size_t l;

        s = timer_base_to_string(i);

        if (endswith(s, "Sec")) {
                /* s/Sec/USec/ */
                l = strlen(s);
                buf = new(char, l+2);
                if (!buf)
                        return NULL;

                memcpy(buf, s, l-3);
                memcpy(buf+l-3, "USec", 5);
        } else {
                buf = strdup(s);
                if (!buf)
                        return NULL;
        }

        return TAKE_PTR(buf);
}

static const char* const timer_result_table[_TIMER_RESULT_MAX] = {
        [TIMER_SUCCESS]                 = "success",
        [TIMER_FAILURE_RESOURCES]       = "resources",
        [TIMER_FAILURE_START_LIMIT_HIT] = "start-limit-hit",
};

DEFINE_STRING_TABLE_LOOKUP(timer_result, TimerResult);

const UnitVTable timer_vtable = {
        .object_size = sizeof(Timer),

        .sections =
                "Unit\0"
                "Timer\0"
                "Install\0",
        .private_section = "Timer",

        .can_transient = true,
        .can_fail = true,
        .can_trigger = true,

        .init = timer_init,
        .done = timer_done,
        .load = timer_load,

        .coldplug = timer_coldplug,

        .dump = timer_dump,

        .start = timer_start,
        .stop = timer_stop,

        .clean = timer_clean,
        .can_clean = timer_can_clean,

        .serialize = timer_serialize,
        .deserialize_item = timer_deserialize_item,

        .active_state = timer_active_state,
        .sub_state_to_string = timer_sub_state_to_string,

        .trigger_notify = timer_trigger_notify,

        .reset_failed = timer_reset_failed,
        .time_change = timer_time_change,
        .timezone_change = timer_timezone_change,

        .bus_set_property = bus_timer_set_property,

        .can_start = timer_can_start,
};

const ActivationDetailsVTable activation_details_timer_vtable = {
        .object_size = sizeof(ActivationDetailsTimer),

        .serialize = activation_details_timer_serialize,
        .deserialize = activation_details_timer_deserialize,
        .append_env = activation_details_timer_append_env,
        .append_pair = activation_details_timer_append_pair,
};
