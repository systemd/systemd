/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "calendarspec.h"
#include "json-util.h"
#include "timer.h"
#include "varlink-timer.h"

static int timers_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        TimerValue *values = userdata;
        int r;

        assert(ret);

        LIST_FOREACH(value, value, values) {
                _cleanup_free_ char *base_name = NULL;

                base_name = timer_base_to_usec_string(value->base);
                if (!base_name)
                        return -ENOMEM;

                if (value->base == TIMER_CALENDAR) {
                        _cleanup_free_ char *calendar = NULL;

                        r = calendar_spec_to_string(value->calendar_spec, &calendar);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to convert calendar spec into string: %m");

                        r = sd_json_variant_append_arraybo(
                                        &v,
                                        JSON_BUILD_PAIR_ENUM("base", base_name),
                                        SD_JSON_BUILD_PAIR_STRING("calendar", calendar));
                } else
                        r = sd_json_variant_append_arraybo(
                                        &v,
                                        JSON_BUILD_PAIR_ENUM("base", base_name),
                                        SD_JSON_BUILD_PAIR_UNSIGNED("usec", value->value));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

int timer_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Timer *t = ASSERT_PTR(TIMER(userdata));
        Unit *trigger = UNIT_TRIGGER(UNIT(t));

        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Timers", timers_build_json, t->values),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Unit", trigger ? trigger->id : NULL),
                        SD_JSON_BUILD_PAIR_BOOLEAN("OnClockChange", t->on_clock_change),
                        SD_JSON_BUILD_PAIR_BOOLEAN("OnTimezoneChange", t->on_timezone_change),
                        JSON_BUILD_PAIR_FINITE_USEC("AccuracyUSec", t->accuracy_usec),
                        JSON_BUILD_PAIR_FINITE_USEC_NON_ZERO("RandomizedDelayUSec", t->random_delay_usec),
                        JSON_BUILD_PAIR_FINITE_USEC_NON_ZERO("RandomizedOffsetUSec", t->random_offset_usec),
                        SD_JSON_BUILD_PAIR_BOOLEAN("FixedRandomDelay", t->fixed_random_delay),
                        SD_JSON_BUILD_PAIR_BOOLEAN("Persistent", t->persistent),
                        SD_JSON_BUILD_PAIR_BOOLEAN("WakeSystem", t->wake_system),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RemainAfterElapse", t->remain_after_elapse),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DeferReactivation", t->defer_reactivation));
}

int timer_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Timer *t = ASSERT_PTR(TIMER(userdata));

        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_ENUM("Result", timer_result_to_string(t->result)),
                        JSON_BUILD_PAIR_FINITE_USEC("NextElapseUSecRealtime", t->next_elapse_realtime),
                        JSON_BUILD_PAIR_FINITE_USEC("NextElapseUSecMonotonic", timer_next_elapse_monotonic(t)),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("LastTriggerUSec", &t->last_trigger));
}
